package dnssd

import (
	"github.com/brutella/dnssd/log"
	"github.com/miekg/dns"

	"context"
	"fmt"
	"math/rand"
	"net"
	"runtime"
	"sort"
	"strings"
	"time"
)

// BrowseEntry represents a discovered service instance.
type BrowseEntry struct {
	IPs       []net.IP
	Host      string
	Port      int
	IfaceName string
	Name      string
	Type      string
	Domain    string
	Text      map[string]string
}

// AddFunc is called when a service instance was found.
type AddFunc func(BrowseEntry)

// RmvFunc is called when a service instance disappared.
type RmvFunc func(BrowseEntry)

// LookupType browses for service instances.
func LookupType(ctx context.Context, service string, add AddFunc, rmv RmvFunc) (err error) {
	conn, err := newLookupConn(ctx, runtime.GOOS == "windows")
	if err != nil {
		return err
	}
	defer conn.Close()

	return lookupType(ctx, service, conn, add, rmv, false)
}

// LookupTypeAtInterface browses for service instances at specific network interfaces.
func LookupTypeAtInterfaces(ctx context.Context, service string, add AddFunc, rmv RmvFunc, ifaces ...string) (err error) {
	conn, err := newLookupConn(ctx, runtime.GOOS == "windows", ifaces...)
	if err != nil {
		return err
	}
	defer conn.Close()

	return lookupType(ctx, service, conn, add, rmv, false, ifaces...)
}

// LookupTypeContinuously brwoses for service instances using Continuous Multicast DNS Querying
func LookupTypeContinuously(ctx context.Context, service string, add AddFunc, rmv RmvFunc) (err error) {
	conn, err := newLookupConn(ctx, runtime.GOOS == "windows")
	if err != nil {
		return err
	}
	defer conn.Close()

	return lookupType(ctx, service, conn, add, rmv, true)
}

// ServiceInstanceName returns the service instance name
// in the form of <instance name>.<service>.<domain>.
// (Note the trailing dot.)
func (e BrowseEntry) EscapedServiceInstanceName() string {
	return fmt.Sprintf("%s.%s.%s.", escape.Replace(e.Name), e.Type, e.Domain)
}

// ServiceInstanceName returns the same as `ServiceInstanceName()`
// but removes any escape characters.
func (e BrowseEntry) ServiceInstanceName() string {
	return fmt.Sprintf("%s.%s.%s.", e.Name, e.Type, e.Domain)
}

// slicesEqual compares two slices of net.IP for equality regardless of order
func slicesEqual(a, b []net.IP) bool {
	if len(a) != len(b) {
		return false
	}

	// Create sorted copies to compare
	sortedA := make([]net.IP, len(a))
	sortedB := make([]net.IP, len(b))
	copy(sortedA, a)
	copy(sortedB, b)

	// Sort by string representation for consistent ordering
	sort.Slice(sortedA, func(i, j int) bool {
		return sortedA[i].String() < sortedA[j].String()
	})
	sort.Slice(sortedB, func(i, j int) bool {
		return sortedB[i].String() < sortedB[j].String()
	})

	// Compare sorted slices
	for i := range sortedA {
		if !sortedA[i].Equal(sortedB[i]) {
			return false
		}
	}
	return true
}

// mapsEqual compares two maps of string to string for equality
func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if other, ok := b[k]; !ok || other != v {
			return false
		}
	}
	return true
}

func lookupType(ctx context.Context, service string, conn MDNSConn, add AddFunc, rmv RmvFunc, continuous bool, ifaces ...string) (err error) {
	var cache = NewCache()

	m := new(dns.Msg)
	m.Question = []dns.Question{
		{
			Name:   service,
			Qtype:  dns.TypePTR,
			Qclass: dns.ClassINET,
		},
	}

	readCtx, readCancel := context.WithCancel(ctx)
	defer readCancel()

	ch := conn.Read(readCtx)

	// Schedule on the receive loop: cancellation cannot strand a query sender.
	queryTimer := time.NewTimer(time.Duration(rand.Intn(100)+20) * time.Millisecond)
	defer queryTimer.Stop()
	interval := time.Second
	nextQuery := time.Now().Add(120 * time.Millisecond)
	expiryTicker := time.NewTicker(250 * time.Millisecond)
	defer expiryTicker.Stop()
	networkTicker := time.NewTicker(2 * time.Second)
	defer networkTicker.Stop()
	networkState := browseNetworkState(ifaces...)
	lastNetworkCheck := time.Now()

	es := []*BrowseEntry{}
	syncEntries := func() {
		for _, srv := range cache.Services() {
			if srv.ServiceName() != service {
				continue
			}

			for ifaceName, ips := range srv.ifaceIPs {
				var found = false
				var existingEntry *BrowseEntry = nil
				var existingIndex = -1

				for i, e := range es {
					if e.Name == srv.Name && e.IfaceName == ifaceName {
						existingEntry = e
						existingIndex = i

						if slicesEqual(e.IPs, ips) && e.Port == srv.Port &&
							mapsEqual(e.Text, srv.Text) && e.Host == srv.Host {
							found = true
						}
						break
					}
				}

				if !found {
					// remove old entry
					if existingEntry != nil {
						rmv(cloneBrowseEntry(*existingEntry))
						es = append(es[:existingIndex], es[existingIndex+1:]...)
					}

					e := BrowseEntry{
						IPs:       ips,
						Host:      srv.Host,
						Port:      srv.Port,
						IfaceName: ifaceName,
						Name:      srv.Name,
						Type:      srv.Type,
						Domain:    srv.Domain,
						Text:      srv.Text,
					}
					e = cloneBrowseEntry(e)
					es = append(es, &e)
					add(cloneBrowseEntry(e))
				}
			}
		}

		tmp := []*BrowseEntry{}
		for _, e := range es {
			var found = false
			for _, srv := range cache.Services() {
				if srv.ServiceInstanceName() == e.ServiceInstanceName() && len(srv.ifaceIPs[e.IfaceName]) > 0 {
					found = true
					break
				}
			}

			if found {
				tmp = append(tmp, e)
			} else {
				// TODO
				rmv(cloneBrowseEntry(*e))
			}
		}
		es = tmp
	}
	for {
		select {
		case <-queryTimer.C:
			// Do not attach synthesized known answers: the service cache does not
			// retain per-interface PTR TTLs and cannot safely suppress responses.
			for _, iface := range MulticastInterfaces(ifaces...) {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				if err := conn.SendQuery(&Query{msg: m.Copy(), iface: iface}); err != nil {
					log.Debug.Println("SendQuery:", err)
				}
			}
			if continuous {
				delay := cache.refreshDelay(interval, service)
				queryTimer.Reset(delay)
				nextQuery = time.Now().Add(delay)
				interval *= 2
				if interval > time.Hour {
					interval = time.Hour
				}
			}
		case now := <-networkTicker.C:
			state := browseNetworkState(ifaces...)
			// A delayed ticker may be the first activity after system resume.
			resumed := now.UnixNano()-lastNetworkCheck.UnixNano() > int64(5*time.Second)
			lastNetworkCheck = now
			if state != networkState || resumed {
				networkState = state
				if continuous {
					interval = time.Second
					queryTimer.Reset(time.Millisecond)
					nextQuery = time.Now().Add(time.Millisecond)
				}
			}
		case <-expiryTicker.C:
			cache.removeExpired()
			syncEntries()

		case req, ok := <-ch:
			if !ok {
				return nil
			}
			log.Debug.Printf("Receive message at %s\n%s\n", req.IfaceName(), req.msg)
			cache.UpdateFrom(req)
			if continuous {
				delay := cache.refreshDelay(interval, service)
				if deadline := time.Now().Add(delay); deadline.Before(nextQuery) {
					queryTimer.Reset(delay)
					nextQuery = deadline
				}
			}
			syncEntries()
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// cloneBrowseEntry isolates cache, comparison state and callback ownership.
func cloneBrowseEntry(e BrowseEntry) BrowseEntry {
	ips := make([]net.IP, len(e.IPs))
	for i, ip := range e.IPs {
		ips[i] = append(net.IP(nil), ip...)
	}
	e.IPs = ips
	text := make(map[string]string, len(e.Text))
	for k, v := range e.Text {
		text[k] = v
	}
	e.Text = text
	return e
}

// BrowseOptions controls an explicitly configured browser. Existing browse
// APIs enable legacy unicast queries by default on Windows only.
type BrowseOptions struct {
	Interfaces []string
	Continuous bool
	// LegacyUnicast adds ephemeral-port queries alongside multicast browsing.
	// Requests still use multicast; this cannot discover unknown hosts when
	// outbound multicast is blocked.
	LegacyUnicast bool
}

func LookupTypeWithOptions(ctx context.Context, service string, add AddFunc, rmv RmvFunc, options BrowseOptions) error {
	conn, err := newLookupConn(ctx, options.LegacyUnicast, options.Interfaces...)
	if err != nil {
		return err
	}
	defer conn.Close()
	return lookupType(ctx, service, conn, add, rmv, options.Continuous, options.Interfaces...)
}

func browseNetworkState(filters ...string) string {
	var state []string
	for _, iface := range MulticastInterfaces(filters...) {
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			state = append(state, fmt.Sprintf("%d/%s/%s", iface.Index, iface.Name, addr))
		}
	}
	sort.Strings(state)
	return strings.Join(state, ";")
}
