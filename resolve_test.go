package dnssd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func resolutionReply(iface string, rrs ...dns.RR) *Request {
	return &Request{iface: &net.Interface{Name: iface}, msg: &dns.Msg{MsgHdr: dns.MsgHdr{Response: true}, Answer: rrs}}
}

func TestResolveSplitAnswers(t *testing.T) {
	const instance = "Review._scm._tcp.local."
	srv := &dns.SRV{Hdr: dns.RR_Header{Name: instance, Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: 10}, Target: "peer.local.", Port: 1234}
	txt := &dns.TXT{Hdr: dns.RR_Header{Name: instance, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 10}, Txt: []string{"id=review-peer"}}
	empty := dns.Copy(txt).(*dns.TXT)
	empty.Txt = []string{""}
	negative := resolutionReply("first")
	negative.msg.Question = []dns.Question{{Name: instance, Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}
	nx := &Request{iface: negative.iface, msg: negative.msg.Copy()}
	nx.msg.Rcode = dns.RcodeNameError
	nsec := &dns.NSEC{Hdr: dns.RR_Header{Name: instance, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 10}, NextDomain: instance, TypeBitMap: []uint16{dns.TypeSRV}}
	other := dns.Copy(txt).(*dns.TXT)
	other.Hdr.Name = "Other._scm._tcp.local."
	upper := dns.Copy(txt).(*dns.TXT)
	upper.Hdr.Name = strings.ToUpper(instance)
	tests := []struct {
		name     string
		packets  []*Request
		wantText string
	}{
		{"srv-first", []*Request{resolutionReply("first", srv), resolutionReply("first", txt)}, "review-peer"},
		{"txt-first", []*Request{resolutionReply("first", txt), resolutionReply("first", srv)}, "review-peer"},
		{"combined", []*Request{resolutionReply("first", srv, txt)}, "review-peer"},
		{"empty-txt", []*Request{resolutionReply("first", empty), resolutionReply("first", srv)}, ""},
		{"no-data", []*Request{resolutionReply("first", srv), negative}, ""},
		{"nxdomain-before-srv", []*Request{nx, resolutionReply("first", srv)}, ""},
		{"nsec", []*Request{resolutionReply("first", srv, nsec)}, ""},
		{"duplicate-and-unrelated", []*Request{resolutionReply("first", srv), resolutionReply("first", srv, other), resolutionReply("first", txt)}, "review-peer"},
		{"case-insensitive", []*Request{resolutionReply("first", upper), resolutionReply("first", srv)}, "review-peer"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &forkConn{requests: make(chan *Request, len(tt.packets)+1)}
			// Addresses can arrive before either service record.
			c.requests <- resolutionReply("first", forkAddress("192.0.2.10", 10, false))
			for _, p := range tt.packets {
				c.requests <- p
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			got, err := lookupInstance(ctx, instance, c)
			if err != nil || got.Port != 1234 || got.Text["id"] != tt.wantText || len(got.IPs) != 1 {
				t.Fatalf("result: port=%d text=%v ips=%v err=%v", got.Port, got.Text, got.IPs, err)
			}
			if len(c.requests) != 0 {
				t.Fatalf("returned before consuming required responses: %d", len(c.requests))
			}
		})
	}
}

func TestResolveIncompleteAndCrossInterface(t *testing.T) {
	const instance = "Review._scm._tcp.local."
	srv := &dns.SRV{Hdr: dns.RR_Header{Name: instance, Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: 10}, Target: "peer.local.", Port: 1234}
	txt := &dns.TXT{Hdr: dns.RR_Header{Name: instance, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 10}, Txt: []string{"id=peer"}}
	for _, name := range []string{"missing-txt", "other-interface", "goodbye-txt", "not-a-response", "unrelated-empty-response"} {
		t.Run(name, func(t *testing.T) {
			c := &forkConn{requests: make(chan *Request, 2)}
			c.requests <- resolutionReply("first", srv)
			switch name {
			case "other-interface":
				c.requests <- resolutionReply("second", txt)
			case "goodbye-txt":
				goodbye := dns.Copy(txt)
				goodbye.Header().Ttl = 0
				c.requests <- resolutionReply("first", goodbye)
			case "not-a-response":
				p := resolutionReply("first", txt)
				p.msg.Response = false
				c.requests <- p
			case "unrelated-empty-response":
				p := resolutionReply("first")
				p.msg.Question = []dns.Question{{Name: "Other._scm._tcp.local.", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}
				c.requests <- p
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
			defer cancel()
			if _, err := lookupInstance(ctx, instance, c); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("incomplete resolution returned %v", err)
			}
		})
	}
	t.Run("closed-input", func(t *testing.T) {
		c := &forkConn{requests: make(chan *Request)}
		close(c.requests)
		if _, err := lookupInstance(context.Background(), instance, c); !errors.Is(err, io.EOF) {
			t.Fatal(err)
		}
	})
	t.Run("canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := lookupInstance(ctx, instance, &forkConn{requests: make(chan *Request)}); !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	})
}

func TestResolveDoesNotReuseExpiredTXT(t *testing.T) {
	const instance = "Review._scm._tcp.local."
	r := &instanceResolution{addresses: NewCache()}
	now := time.Unix(1000, 0)
	txt := &dns.TXT{Hdr: dns.RR_Header{Name: instance, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 1}, Txt: []string{"id=old"}}
	srv := &dns.SRV{Hdr: dns.RR_Header{Name: instance, Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: 10}, Target: "peer.local.", Port: 1234}
	if _, ok := r.update(instance, resolutionReply("first", txt), now); ok {
		t.Fatal("TXT alone completed")
	}
	if _, ok := r.update(instance, resolutionReply("first", srv), now.Add(time.Second)); ok {
		t.Fatal("expired TXT completed resolution")
	}
	txt.Txt = []string{"id=new"}
	got, ok := r.update(instance, resolutionReply("first", txt), now.Add(time.Second))
	if !ok || got.Text["id"] != "new" {
		t.Fatalf("fresh TXT did not complete: %v %v", got, ok)
	}
}

// Exercise separate legacy transactions on actual UDP sockets, with multicast
// receive deliberately disabled for the resolver.
func TestLegacyResolveSplitUDP(t *testing.T) {
	if os.Getenv("DNSSD_TEST_MULTICAST") != "1" {
		t.Skip("set DNSSD_TEST_MULTICAST=1 for network integration")
	}
	iface := testMulticastInterface(t)
	for _, txtFirst := range []bool{false, true} {
		t.Run(fmt.Sprintf("txt-first=%v", txtFirst), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			responder, err := newMDNSConn(iface.Name)
			if err != nil {
				t.Fatal(err)
			}
			defer responder.Close()
			instance := fmt.Sprintf("split-%x._dnssd-test._tcp.local.", time.Now().UnixNano())
			done := make(chan struct{})
			// Join the test responder before sending queries.
			requests := responder.Read(ctx)
			go func() {
				defer close(done)
				pending := make(map[string]map[uint16]*Request)
				for {
					select {
					case req, ok := <-requests:
						if !ok {
							return
						}
						if req.msg.Response || !isLegacyUnicastSource(req.from) || len(req.msg.Question) != 1 {
							continue
						}
						q := req.msg.Question[0]
						if q.Name != instance || (q.Qtype != dns.TypeSRV && q.Qtype != dns.TypeTXT) {
							continue
						}
						key := req.from.String()
						if pending[key] == nil {
							pending[key] = make(map[uint16]*Request)
						}
						pending[key][q.Qtype] = req
						pair := pending[key]
						if pair[dns.TypeSRV] == nil || pair[dns.TypeTXT] == nil {
							continue
						}
						order := []uint16{dns.TypeSRV, dns.TypeTXT}
						if txtFirst {
							order[0], order[1] = order[1], order[0]
						}
						for _, typ := range order {
							request := pair[typ]
							reply := new(dns.Msg)
							reply.SetReply(request.msg)
							reply.Authoritative = true
							h := dns.RR_Header{Name: instance, Rrtype: typ, Class: dns.ClassINET, Ttl: 10}
							if typ == dns.TypeSRV {
								reply.Answer = []dns.RR{&dns.SRV{Hdr: h, Target: "peer.local.", Port: 1234}}
							} else {
								reply.Answer = []dns.RR{&dns.TXT{Hdr: h, Txt: []string{"id=split-peer"}}}
							}
							if err := responder.SendResponse(&Response{msg: reply, addr: request.from, iface: request.iface}); err != nil {
								t.Errorf("send split response: %v", err)
								return
							}
						}
						delete(pending, key)
					case <-ctx.Done():
						return
					}
				}
			}()
			// Cleanup order matters: cancel readers before waiting on the goroutine.
			defer func() { cancel(); <-done }()
			conn := addLegacyQueries(ctx, &forkConn{requests: make(chan *Request)})
			defer conn.Close()
			got, err := lookupInstance(ctx, instance, conn)
			if err != nil || got.Port != 1234 || got.Text["id"] != "split-peer" {
				t.Fatalf("split UDP result: port=%d text=%v err=%v", got.Port, got.Text, err)
			}
		})
	}
}
