package dnssd

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"
)

// TestBrowseMulticast exercises real sockets. Enable explicitly on a host
// permitting multicast: DNSSD_TEST_MULTICAST=1 go test -run TestBrowseMulticast.
func TestBrowseMulticast(t *testing.T) {
	if os.Getenv("DNSSD_TEST_MULTICAST") != "1" {
		t.Skip("set DNSSD_TEST_MULTICAST=1 to run real multicast integration")
	}
	iface := testMulticastInterface(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	id := fmt.Sprintf("dnssd-test-%x", time.Now().UnixNano())
	srv, err := NewService(Config{Name: id, Host: id, Type: "_dnssd-test._tcp", Port: 12334, Ifaces: []string{iface.Name}, Text: map[string]string{"test": id}})
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
	responderDone := make(chan error, 1)
	go func() { responderDone <- responder.Respond(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-responderDone:
			if err != nil && err != context.Canceled && err != context.DeadlineExceeded {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("responder did not stop")
		}
	})
	found := make(chan BrowseEntry, 1)
	browseDone := make(chan error, 1)
	go func() {
		browseDone <- LookupTypeAtInterfaces(ctx, srv.ServiceName(), func(e BrowseEntry) {
			if e.Name == id {
				select {
				case found <- e:
				case <-ctx.Done():
				}
			}
		}, func(BrowseEntry) {}, iface.Name)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-browseDone:
		case <-time.After(3 * time.Second):
			t.Error("browser did not stop")
		}
	})
	select {
	case e := <-found:
		if e.Host != srv.Host || e.Port != srv.Port || e.Text["test"] != id || e.IfaceName != iface.Name || len(e.IPs) == 0 {
			t.Fatalf("unexpected discovery: %+v", e)
		}
	case err := <-responderDone:
		responderDone <- err
		t.Fatalf("responder stopped before discovery: %v", err)
	case <-ctx.Done():
		t.Fatalf("no multicast discovery on %s: %v", iface.Name, ctx.Err())
	}
}

func TestResponderStableInterfaces(t *testing.T) {
	if os.Getenv("DNSSD_TEST_MULTICAST") != "1" {
		t.Skip("set DNSSD_TEST_MULTICAST=1 for real socket integration")
	}
	testMulticastInterface(t)
	conn, err := newMDNSConn()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	r := newResponder(conn)
	for n := 0; n < 2; n++ {
		added, changed := r.updateUpIfaces()
		if len(added) != 0 || len(changed) != 0 {
			t.Fatalf("stable interfaces reported as changed: added=%v changed=%v", added, changed)
		}
	}
}
