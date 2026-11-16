package dnssd

import (
	"context"
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"net"
	"testing"
	"time"
)

func TestRemove(t *testing.T) {
	cfg := Config{
		Name: "Test",
		Type: "_asdf._tcp",
		Port: 1234,
	}
	si, err := NewService(cfg)
	if err != nil {
		t.Fatal(err)
	}

	msg := new(dns.Msg)
	msg.Answer = []dns.RR{SRV(si), TXT(si)}

	answers := []dns.RR{SRV(si), TXT(si), PTR(si)}
	unknown := remove(msg.Answer, answers)

	if x := len(unknown); x != 1 {
		t.Fatal(x)
	}

	rr := unknown[0]
	if _, ok := rr.(*dns.PTR); !ok {
		t.Fatal("Invalid type", rr)
	}
}

func TestRegisterServiceWithExplicitIP(t *testing.T) {
	testIface := testMulticastInterface(t)
	cfg := Config{
		Host:   "Computer",
		Name:   "Test",
		Type:   "_asdf._tcp",
		Domain: "local",
		Port:   12345,
		Ifaces: []string{testIface.Name},
	}
	sv, err := NewService(cfg)
	if err != nil {
		t.Fatal(err)
	}
	sv.ifaceIPs = map[string][]net.IP{
		testIface.Name: {net.IP{192, 168, 0, 123}},
	}

	conn, otherConn := newTestConnPair(t, testIface)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	startTestResponder(t, ctx, conn, sv)
	t.Run("resolver", func(t *testing.T) {

		lookupCtx, lookupCancel := context.WithTimeout(ctx, 5*time.Second)

		defer lookupCancel()
		defer cancel()

		srv, err := lookupInstance(lookupCtx, "Test._asdf._tcp.local.", otherConn)
		if err != nil {
			t.Fatal(err)
		}

		if is, want := srv.Name, "Test"; is != want {
			t.Fatalf("%v != %v", is, want)
		}

		if is, want := srv.Type, "_asdf._tcp"; is != want {
			t.Fatalf("%v != %v", is, want)
		}

		if is, want := srv.Host, "Computer"; is != want {
			t.Fatalf("%v != %v", is, want)
		}

		ips := srv.IPsAtInterface(&net.Interface{Name: testIface.Name})
		if is, want := len(ips), 1; is != want {
			t.Fatalf("%v != %v", is, want)
		}

		if is, want := ips[0].String(), "192.168.0.123"; is != want {
			t.Fatalf("%v != %v", is, want)
		}
	})
}

type expectedIP struct {
	advType  IPType
	expected []net.IP
}

func TestRegisterServiceWithSpecifiedAdvertisedIP(t *testing.T) {
	testIface := testMulticastInterface(t)

	v4 := net.IP{192, 168, 0, 123}
	v6 := net.ParseIP("fe80::1")

	var expectedIPs = map[string]expectedIP{
		"v4 only":            {IPv4, []net.IP{v4}},
		"v6 only":            {IPv6, []net.IP{v6}},
		"both / unspecified": {IPType(0), []net.IP{v4, v6}},
	}

	for name, expected := range expectedIPs {
		t.Run(name, func(t *testing.T) {
			cfg := Config{
				Host:            "Computer",
				Name:            "Test",
				Type:            "_asdf._tcp",
				Domain:          "local",
				Port:            12345,
				Ifaces:          []string{testIface.Name},
				AdvertiseIPType: expected.advType,
			}
			sv, err := NewService(cfg)
			if err != nil {
				t.Fatal(err)
			}
			sv.ifaceIPs = map[string][]net.IP{
				testIface.Name: {v4, v6},
			}

			conn, otherConn := newTestConnPair(t, testIface)

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			startTestResponder(t, ctx, conn, sv)
			t.Run("resolver", func(t *testing.T) {

				lookupCtx, lookupCancel := context.WithTimeout(ctx, 5*time.Second)

				defer lookupCancel()
				defer cancel()

				srv, err := lookupInstance(lookupCtx, "Test._asdf._tcp.local.", otherConn)
				if err != nil {
					t.Fatal(err)
				}

				if is, want := srv.Name, "Test"; is != want {
					t.Fatalf("%v != %v", is, want)
				}

				if is, want := srv.Type, "_asdf._tcp"; is != want {
					t.Fatalf("%v != %v", is, want)
				}

				if is, want := srv.Host, "Computer"; is != want {
					t.Fatalf("%v != %v", is, want)
				}

				ips := srv.IPsAtInterface(&net.Interface{Name: testIface.Name})
				if is, want := len(ips), len(expected.expected); is != want {
					t.Fatalf("%v != %v", is, want)
				}

				if !slicesEqual(ips, expected.expected) {
					t.Fatalf("addresses=%v want=%v", ips, expected.expected)
				}

			})
		})
	}
}

type readinessConn struct {
	forkConn
	readStarted bool
	closed      bool
}

func (c *readinessConn) Read(ctx context.Context) <-chan *Request {
	c.readStarted = true
	return c.requests
}
func (c *readinessConn) Close() { c.closed = true }

func TestResponderReadyAfterQueuedProbe(t *testing.T) {
	for _, outcome := range []string{"success", "failure", "cancel"} {
		t.Run(outcome, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			conn := &readinessConn{forkConn: forkConn{requests: make(chan *Request)}}
			r := newResponder(conn)
			entered, release, ready := make(chan struct{}), make(chan struct{}), make(chan struct{})
			probeErr := errors.New("probe failed")
			r.probe = func(ctx context.Context, s Service) (Service, error) {
				close(entered)
				select {
				case <-release:
				case <-ctx.Done():
					return s, ctx.Err()
				}
				if outcome == "failure" {
					return s, probeErr
				}
				return s, nil
			}
			r.onReady = func() {
				// Reentry proves readiness is not delivered under the responder lock.
				r.mutex.Lock()
				if !conn.readStarted || len(r.managed) != 1 || len(r.unmanaged) != 0 {
					t.Error("premature readiness")
				}
				r.mutex.Unlock()
				close(ready)
			}
			s := newService("ready._test._tcp.local.")
			s.Ifaces = []string{"ready-test"}
			if _, err := r.Add(*s); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- r.Respond(ctx) }()
			select {
			case <-entered:
			case <-ctx.Done():
				t.Fatal("probe not entered")
			}
			select {
			case <-ready:
				t.Fatal("ready before probe completes")
			default:
			}
			if outcome == "cancel" {
				cancel()
			} else {
				close(release)
			}
			if outcome == "success" {
				select {
				case <-ready:
				case <-ctx.Done():
					t.Fatal("readiness missing")
				}
				cancel()
			}
			select {
			case err := <-done:
				if outcome == "failure" && !errors.Is(err, probeErr) {
					t.Fatal(err)
				}
				if outcome != "failure" && !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("Respond did not drain")
			}
			if outcome != "success" {
				select {
				case <-ready:
					t.Fatal("failed startup reported ready")
				default:
				}
			}
			if !conn.closed || r.isRunning || r.runCtx != nil {
				t.Fatal("startup resources not released")
			}
			if _, err := r.Add(*s); err == nil {
				t.Fatal("closed responder accepted service")
			}
		})
	}
}

func TestResponderAddAfterReadyWaitsForProbe(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn := &readinessConn{forkConn: forkConn{requests: make(chan *Request)}}
	r := newResponder(conn)
	ready, entered, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	r.onReady = func() { close(ready) }
	r.probe = func(ctx context.Context, s Service) (Service, error) {
		close(entered)
		select {
		case <-release:
			return s, nil
		case <-ctx.Done():
			return s, ctx.Err()
		}
	}
	done := make(chan error, 1)
	go func() { done <- r.Respond(ctx) }()
	select {
	case <-ready:
	case <-ctx.Done():
		t.Fatal("readiness missing")
	}
	s := newService("ready._test._tcp.local.")
	s.Ifaces = []string{"ready-test"}
	added := make(chan error, 1)
	go func() { _, err := r.Add(*s); added <- err }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("probe not entered")
	}
	select {
	case <-added:
		t.Fatal("Add returned before probe")
	default:
	}
	close(release)
	if err := <-added; err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if !conn.closed {
		t.Fatal("connection not closed")
	}
}

func TestResponderProbePanicReleasesLockAndCleansUp(t *testing.T) {
	for _, partial := range []bool{false, true} {
		partial := partial
		t.Run(fmt.Sprint("partial=", partial), func(t *testing.T) {
			conn := &readinessConn{forkConn: forkConn{requests: make(chan *Request)}}
			r := newResponder(conn)
			panicValue := errors.New("probe panic")
			probes := 0
			r.probe = func(_ context.Context, s Service) (Service, error) {
				probes++
				if partial && probes == 1 {
					return s, nil
				}
				panic(panicValue)
			}
			ready := false
			r.onReady = func() { ready = true }
			s := newService("panic._test._tcp.local.")
			s.Ifaces = []string{"ready-test"}
			count := 1
			if partial {
				count = 2
			}
			for i := 0; i < count; i++ {
				if _, err := r.Add(*s); err != nil {
					t.Fatal(err)
				}
			}
			recovered := make(chan interface{}, 1)
			go func() {
				defer func() { recovered <- recover() }()
				_ = r.Respond(context.Background())
			}()
			select {
			case value := <-recovered:
				if value != panicValue {
					t.Fatalf("panic was lost: %v", value)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("panic cleanup deadlocked before caller could recover")
			}
			if !conn.closed || r.isRunning || r.runCtx != nil || ready {
				t.Fatal("panic did not complete startup cleanup")
			}
			added := make(chan error, 1)
			go func() { _, err := r.Add(*s); added <- err }()
			select {
			case err := <-added:
				if err == nil {
					t.Fatal("closed responder accepted service")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("Add blocked on leaked startup lock")
			}
		})
	}
}
