package dnssd

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func TestBrowse(t *testing.T) {
	testIface := testMulticastInterface(t)

	localhost, err := os.Hostname()
	if err != nil {
		t.Fatal(err)
	}
	localhost = strings.TrimSuffix(strings.Replace(localhost, " ", "-", -1), ".local") // replace spaces with dashes and remove .local suffix
	for tName, hostValue := range map[string]string{
		"regular host": "My-Computer",
		"empty host":   "",
		"ip address":   "192.168.0.1",
	} {
		t.Run(tName, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cfg := Config{
				Name:   "My Service",
				Type:   "_test._tcp",
				Host:   hostValue,
				Port:   12334,
				Ifaces: []string{testIface.Name},
			}
			srv, err := NewService(cfg)
			if err != nil {
				t.Fatal(err)
			}
			srv.ifaceIPs = map[string][]net.IP{testIface.Name: {net.ParseIP("192.0.2.10")}}
			conn, browser := newTestConnPair(t, testIface)
			startTestResponder(t, ctx, conn, srv)

			resultChan := make(chan BrowseEntry, 1)
			browseDone := make(chan error, 1)
			t.Cleanup(func() {
				cancel()
				select {
				case <-browseDone:
				case <-time.After(time.Second):
					t.Error("browser did not stop")
				}
			})
			go func() {
				browseDone <- lookupType(ctx, fmt.Sprintf("%s.local.", cfg.Type), browser, func(entry BrowseEntry) {
					select {
					case resultChan <- entry:
					case <-ctx.Done():
					}
				}, func(BrowseEntry) {}, false, testIface.Name)
			}()

			select {
			case <-ctx.Done():
				t.Fatal("timeout")
			case entry := <-resultChan:
				if !slicesEqual(entry.IPs, []net.IP{net.ParseIP("192.0.2.10")}) {
					t.Fatalf("addresses=%v", entry.IPs)
				}
				if entry.Name != cfg.Name {
					t.Fatalf("is=%v want=%v", entry.Name, cfg.Name)
				}
				if tName == "empty host" {
					if entry.Host != localhost {
						t.Fatalf("is=%v want=%v", entry.Host, localhost)
					}
				} else {
					if entry.Host != cfg.Host {
						t.Fatalf("is=%v want=%v", entry.Host, cfg.Host)
					}
				}
				if entry.Port != cfg.Port {
					t.Fatalf("is=%v want=%v", entry.Port, cfg.Port)
				}
			}
		})
	}
}
