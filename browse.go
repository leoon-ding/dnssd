package dnssd

import (
	"github.com/brutella/dnssd/log"

	"context"
	"fmt"
	"net"
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
	conn, err := newLookupConn(ctx, false)
	if err != nil {
		return err
	}
	defer conn.Close()

	return lookupType(ctx, service, conn, add, rmv, false)
}

// LookupTypeAtInterface browses for service instances at specific network interfaces.
func LookupTypeAtInterfaces(ctx context.Context, service string, add AddFunc, rmv RmvFunc, ifaces ...string) (err error) {
	conn, err := newLookupConn(ctx, false, ifaces...)
	if err != nil {
		return err
	}
	defer conn.Close()

	return lookupType(ctx, service, conn, add, rmv, false, ifaces...)
}

// LookupTypeContinuously brwoses for service instances using Continuous Multicast DNS Querying
func LookupTypeContinuously(ctx context.Context, service string, add AddFunc, rmv RmvFunc) (err error) {
	conn, err := newLookupConn(ctx, false)
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

	return browseWithOptions(ctx, service, conn, add, rmv, BrowseOptions{Continuous: continuous, Interfaces: ifaces})
}

func browseWithOptions(ctx context.Context, service string, conn MDNSConn, add AddFunc, rmv RmvFunc, options BrowseOptions) error {
	cache := NewCache()
	records := newBrowseRecords(service)
	scheduler := newBrowseSchedule(time.Now(), options)
	queryTimer := time.NewTimer(0)
	defer queryTimer.Stop()
	networkTicker := time.NewTicker(5 * time.Second)
	defer networkTicker.Stop()
	interfaces := MulticastInterfaces(options.Interfaces...)
	scheduler.setInterfaces(interfaces)
	networkState := browseNetworkState(options.Interfaces...)
	lastNetworkCheck := time.Now()
	readCtx, readCancel := context.WithCancel(ctx)
	defer readCancel()
	ch := conn.Read(readCtx)

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
		now := time.Now()
		deadline := scheduler.next(records, now)
		delay := time.Hour
		if !deadline.IsZero() {
			delay = deadline.Sub(now)
			if delay < 0 {
				delay = 0
			}
		}
		if !queryTimer.Stop() {
			select {
			case <-queryTimer.C:
			default:
			}
		}
		queryTimer.Reset(delay)
		select {
		case <-queryTimer.C:
			now = time.Now()
			if records.expire(now) {
				cache = records.snapshot(now)
				syncEntries()
			}
			for _, iface := range interfaces {
				for _, batch := range scheduler.queries(records, iface, now) {
					if ctx.Err() != nil {
						return ctx.Err()
					}
					q := &Query{msg: batch.msg, iface: iface}
					var err error
					if batch.legacy {
						if sender, ok := conn.(interface{ SendLegacyQuery(*Query) error }); ok {
							err = sender.SendLegacyQuery(q)
						}
					} else {
						err = conn.SendQuery(q)
					}
					if err != nil {
						log.Debug.Println("Browse query:", err)
					}
				}
			}
			scheduler.advance(now)
		case now := <-networkTicker.C:
			state := browseNetworkState(options.Interfaces...)
			resumed := now.Sub(lastNetworkCheck) > 15*time.Second
			lastNetworkCheck = now
			if state != networkState || resumed {
				networkState = state
				nextInterfaces := MulticastInterfaces(options.Interfaces...)
				joinBrowseInterfaces(conn, interfaces, nextInterfaces)
				interfaces = nextInterfaces
				scheduler.setInterfaces(interfaces)
				records = newBrowseRecords(service)
				cache = NewCache()
				syncEntries()
				if options.Continuous {
					scheduler.restart(now)
				}
			}
		case req, ok := <-ch:
			if !ok {
				return ctx.Err()
			}
			if records.update(req, time.Now()) {
				cache = records.snapshot(time.Now())
				syncEntries()
			}
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

// BrowseOptions controls browsing. Legacy discovery is opt-in on every platform.
type BrowseOptions struct {
	Interfaces []string
	Continuous bool
	// LegacyUnicast enables independent ephemeral-port supplemental discovery.
	// Requests still use multicast; this cannot discover unknown hosts when
	// outbound multicast is blocked.
	LegacyUnicast bool
	// LegacyInterval defaults to five minutes. It must be at least ten seconds.
	// With Continuous false, legacy discovery runs only at startup.
	LegacyInterval time.Duration
}

func LookupTypeWithOptions(ctx context.Context, service string, add AddFunc, rmv RmvFunc, options BrowseOptions) error {
	if options.LegacyInterval < 0 || (options.LegacyInterval > 0 && options.LegacyInterval < 10*time.Second) {
		return fmt.Errorf("LegacyInterval must be zero or at least ten seconds")
	}
	conn, err := newLookupConn(ctx, options.LegacyUnicast, options.Interfaces...)
	if err != nil {
		return err
	}
	defer conn.Close()
	return browseWithOptions(ctx, service, conn, add, rmv, options)
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

// Join newly appearing links without repeatedly rejoining unchanged groups.
func joinBrowseInterfaces(conn MDNSConn, previous, current []*net.Interface) {
	if legacy, ok := conn.(*lookupConn); ok {
		conn = legacy.MDNSConn
	}
	joiner, ok := conn.(interface{ JoinGroup(*net.Interface) error })
	if !ok {
		return
	}
	for _, iface := range current {
		found := false
		for _, old := range previous {
			if old.Index == iface.Index && old.Name == iface.Name {
				found = true
				break
			}
		}
		if !found {
			if err := joiner.JoinGroup(iface); err != nil {
				log.Debug.Println("Browse JoinGroup:", err)
			}
		}
	}
}
