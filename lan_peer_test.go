package dnssd

import (
	"context"
	"os"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// Opt-in dual-host harness. It uses this checkout's real responder/transport,
// with a receive-only fault injection to reproduce missing multicast replies.
type lanTraceConn struct {
	MDNSConn
	drop      bool
	normal    atomic.Int32
	responses atomic.Int32
	t         *testing.T
}

func (c *lanTraceConn) SendQuery(q *Query) error {
	c.normal.Add(1)
	c.t.Logf("QM iface=%s questions=%v known=%d", q.iface.Name, q.msg.Question, len(q.msg.Answer))
	return c.MDNSConn.SendQuery(q)
}
func (c *lanTraceConn) Read(ctx context.Context) <-chan *Request {
	out := make(chan *Request)
	go func() {
		defer close(out)
		in := c.MDNSConn.Read(ctx)
		for {
			select {
			case r, ok := <-in:
				if !ok {
					return
				}
				c.responses.Add(1)
				if c.drop {
					continue
				}
				select {
				case out <- r:
				case <-ctx.Done():
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	return out
}

type lanLegacyConn struct {
	*lookupConn
	sent int
	t    *testing.T
}

func (c *lanLegacyConn) SendLegacyQuery(q *Query) error {
	c.sent++
	c.t.Logf("LEGACY iface=%s questions=%v", q.iface.Name, q.msg.Question)
	return c.lookupConn.SendLegacyQuery(q)
}
func TestLANPeer(t *testing.T) {
	mode := os.Getenv("DNSSD_LAN_MODE")
	if mode == "" {
		t.Skip("explicit dual-host validation only")
	}
	seconds := 25
	if v := os.Getenv("DNSSD_LAN_SECONDS"); v != "" {
		seconds, _ = strconv.Atoi(v)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(seconds)*time.Second)
	defer cancel()
	EnableIPv6LinkLocalMulticast = false
	ifaceName := os.Getenv("DNSSD_LAN_IFACE")
	service := "_codex-lan._tcp.local."
	if mode == "serve" {
		TTLDefault = 12
		TTLHostname = 12
		name := os.Getenv("DNSSD_LAN_NAME")
		if name == "" {
			name = "LAN-Peer"
		}
		srv, err := NewService(Config{Name: name, Host: name, Type: "_codex-lan._tcp", Port: 12345, Ifaces: []string{ifaceName}, Text: map[string]string{"build": "ttl-scheduler"}})
		if err != nil {
			t.Fatal(err)
		}
		responder, err := NewResponder()
		if err != nil {
			t.Fatal(err)
		}
		if _, err = responder.Add(srv); err != nil {
			t.Fatal(err)
		}
		t.Logf("READY %s iface=%s", name, ifaceName)
		err = responder.Respond(ctx)
		if err != nil && err != context.DeadlineExceeded && err != context.Canceled {
			t.Fatal(err)
		}
		return
	}
	raw, err := newMDNSConn(ifaceName)
	if err != nil {
		t.Fatal(err)
	}
	trace := &lanTraceConn{MDNSConn: raw, drop: mode == "legacy", t: t}
	var conn MDNSConn = trace
	var legacy *lanLegacyConn
	options := BrowseOptions{Continuous: true, Interfaces: []string{ifaceName}}
	if mode == "legacy" {
		legacy = &lanLegacyConn{lookupConn: addLegacyQueries(ctx, trace), t: t}
		conn = legacy
		options.LegacyUnicast = true
		// Short interval exercises a second discovery after the ten-second expiry.
		options.LegacyInterval = 15 * time.Second
		if v := os.Getenv("DNSSD_LAN_INTERVAL"); v != "" {
			d, err := time.ParseDuration(v)
			if err != nil {
				t.Fatal(err)
			}
			options.LegacyInterval = d
		}
	}
	defer conn.Close()
	adds, removes := 0, 0
	expected := os.Getenv("DNSSD_LAN_EXPECT")
	err = browseWithOptions(ctx, service, conn, func(e BrowseEntry) {
		if e.Name != expected {
			return
		}
		adds++
		if e.Port != 12345 || e.Text["build"] != "ttl-scheduler" || len(e.IPs) == 0 {
			t.Errorf("incomplete: %+v", e)
		}
		t.Logf("ADD %s ips=%v", e.Name, e.IPs)
	}, func(e BrowseEntry) {
		if e.Name == expected {
			removes++
			t.Logf("REMOVE %s", e.Name)
		}
	}, options)
	if err != context.DeadlineExceeded && err != context.Canceled {
		t.Fatal(err)
	}
	t.Logf("RESULT mode=%s adds=%d removes=%d QM=%d received=%d", mode, adds, removes, trace.normal.Load(), trace.responses.Load())
	if adds == 0 {
		t.Fatal("remote peer not discovered")
	}
	if legacy != nil {
		t.Logf("RESULT legacy_queries=%d", legacy.sent)
		if adds < 2 || removes < 1 {
			t.Fatal("missing expiry/re-discovery")
		}
		if legacy.sent != 2 {
			t.Fatalf("unexpected legacy frequency: %d", legacy.sent)
		}
	}
}
