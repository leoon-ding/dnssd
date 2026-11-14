package dnssd

import (
	"github.com/miekg/dns"

	"context"
	"net"
	"sync"
	"testing"
	"time"
)

// Each simulated connection owns its receive interface and lifetime.
type testConn struct {
	read      chan *Request
	in, out   chan *dns.Msg
	iface     *net.Interface
	done      chan struct{}
	closeOnce sync.Once
	workers   sync.WaitGroup
}

func newTestConn(iface *net.Interface) *testConn {
	return &testConn{read: make(chan *Request), in: make(chan *dns.Msg, 128), out: make(chan *dns.Msg, 128), iface: iface, done: make(chan struct{})}
}
func newTestConnPair(t *testing.T, iface *net.Interface) (*testConn, *testConn) {
	t.Helper()
	a, b := newTestConn(iface), newTestConn(iface)
	a.in = b.out
	b.in = a.out
	t.Cleanup(func() { a.Close(); b.Close() })
	return a, b
}
func (c *testConn) send(m *dns.Msg) error {
	select {
	case c.out <- m.Copy():
		return nil
	case <-c.done:
		return context.Canceled
	}
}
func (c *testConn) SendQuery(q *Query) error       { return c.send(q.msg) }
func (c *testConn) SendResponse(r *Response) error { return c.send(r.msg) }
func (c *testConn) Read(ctx context.Context) <-chan *Request {
	ch := make(chan *Request)
	c.workers.Add(1)
	go func() { defer c.workers.Done(); c.start(ctx, ch) }()
	return ch
}
func (*testConn) Drain(context.Context) {}
func (c *testConn) Close()              { c.closeOnce.Do(func() { close(c.done) }); c.workers.Wait() }
func (c *testConn) start(ctx context.Context, ch chan<- *Request) {
	for {
		select {
		case msg := <-c.in:
			req := &Request{msg: msg, from: &net.UDPAddr{IP: net.ParseIP("192.0.2.2"), Port: 5353}, iface: c.iface}
			select {
			case ch <- req:
			case <-ctx.Done():
				return
			case <-c.done:
				return
			}
		case <-ctx.Done():
			return
		case <-c.done:
			return
		}
	}
}

// These tests mock the transport, but production query scheduling still
// enumerates interfaces. Select by capability, never by an OS-specific name.
func testMulticastInterface(t *testing.T) *net.Interface {
	t.Helper()
	for _, iface := range MulticastInterfaces() {
		if iface.Flags&net.FlagLoopback == 0 {
			return iface
		}
	}
	t.Skip("requires an active multicast interface for query scheduling")
	return nil
}

func startTestResponder(t *testing.T, ctx context.Context, c MDNSConn, srv Service) {
	t.Helper()
	r := newResponder(c)
	r.addManaged(srv)
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- r.Respond(runCtx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil && err != context.Canceled && err != context.DeadlineExceeded {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("responder did not stop")
		}
	})
}

// TestProbing tests probing by using 2 services with the same
// service instance name and host name.Once the first services
// is announced, the probing for the second service should give
func TestProbing(t *testing.T) {
	testIface := testMulticastInterface(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, otherConn := newTestConnPair(t, testIface)

	cfg := Config{
		Name:   "My Service",
		Type:   "_hap._tcp",
		Host:   "My Computer",
		Port:   12334,
		Ifaces: []string{testIface.Name},
	}
	srv, err := NewService(cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv.ifaceIPs = map[string][]net.IP{
		testIface.Name: []net.IP{net.IP{192, 168, 0, 122}},
	}

	rsrv, err := NewService(cfg.Copy())
	if err != nil {
		t.Fatal(err)
	}
	rsrv.ifaceIPs = map[string][]net.IP{testIface.Name: {net.IP{192, 168, 0, 123}}}
	startTestResponder(t, ctx, otherConn, rsrv)

	resolved, err := probeService(ctx, conn, srv, 500*time.Millisecond, true)

	if x := err; x != nil {
		t.Fatal(x)
	}

	if is, want := resolved.Host, "My-Computer-2"; is != want {
		t.Fatalf("is=%v want=%v", is, want)
	}

	if is, want := resolved.Name, "My Service (2)"; is != want {
		t.Fatalf("is=%v want=%v", is, want)
	}

	cancel()
}

func TestIsLexicographicLater(t *testing.T) {
	this := &dns.A{
		Hdr: dns.RR_Header{
			Name:   "MyPrinter.local.",
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    TTLHostname,
		},
		A: net.ParseIP("169.254.99.200"),
	}

	that := &dns.A{
		Hdr: dns.RR_Header{
			Name:   "MyPrinter.local.",
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    TTLHostname,
		},
		A: net.ParseIP("169.254.200.50"),
	}

	if is, want := compareIP(this.A.To4(), that.A.To4()), -1; is != want {
		t.Fatalf("is=%v want=%v", is, want)
	}

	if is, want := compareIP(that.A.To4(), this.A.To4()), 1; is != want {
		t.Fatalf("is=%v want=%v", is, want)
	}
}

func TestDenyingAs(t *testing.T) {
	tests := []struct {
		This   []*dns.A
		That   []*dns.A
		Result bool
	}{
		{
			This: []*dns.A{
				&dns.A{
					Hdr: dns.RR_Header{
						Name:   "MyPrinter.local.",
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    TTLHostname,
					},
					A: net.ParseIP("169.254.99.200"),
				},
			},
			That: []*dns.A{
				&dns.A{
					Hdr: dns.RR_Header{
						Name:   "MyPrinter.local.",
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    TTLHostname,
					},
					A: net.ParseIP("169.254.99.200"),
				},
			},
			Result: false,
		},
		{
			This: []*dns.A{
				&dns.A{
					Hdr: dns.RR_Header{
						Name:   "MyPrinter.local.",
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    TTLHostname,
					},
					A: net.ParseIP("169.254.99.200"),
				},
			},
			That:   []*dns.A{},
			Result: true,
		},
		{
			This: []*dns.A{},
			That: []*dns.A{
				&dns.A{
					Hdr: dns.RR_Header{
						Name:   "MyPrinter.local.",
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    TTLHostname,
					},
					A: net.ParseIP("169.254.99.200"),
				},
			},
			Result: true,
		},
		{
			This:   []*dns.A{},
			That:   []*dns.A{},
			Result: false,
		},
	}

	for _, test := range tests {
		if is, want := areDenyingAs(test.This, test.That), test.Result; is != want {
			t.Fatalf("%v != %v is=%v want=%v", test.This, test.That, is, want)
		}
	}
}
