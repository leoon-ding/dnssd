package dnssd

import (
	"github.com/brutella/dnssd/log"
	"github.com/miekg/dns"

	"context"
	"fmt"
	"math/rand"
	"net"
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
	conn, err := newMDNSConn()
	if err != nil {
		return err
	}
	defer conn.close()

	return lookupType(ctx, service, conn, add, rmv, false)
}

// LookupTypeAtInterface browses for service instances at specific network interfaces.
func LookupTypeAtInterfaces(ctx context.Context, service string, add AddFunc, rmv RmvFunc, ifaces ...string) (err error) {
	conn, err := newMDNSConn(ifaces...)
	if err != nil {
		return err
	}
	defer conn.close()

	return lookupType(ctx, service, conn, add, rmv, false, ifaces...)
}

// LookupTypeContinuously brwoses for service instances using Continuous Multicast DNS Querying
func LookupTypeContinuously(ctx context.Context, service string, add AddFunc, rmv RmvFunc) (err error) {
	conn, err := newMDNSConn()
	if err != nil {
		return err
	}
	defer conn.close()

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

	qs := make(chan *Query)
	go func() {
		query := func() {
			for _, iface := range MulticastInterfaces(ifaces...) {
				iface := iface
				q := &Query{msg: m.Copy(), iface: iface}
				qs <- q
			}
		}

		// Add random delay（between 20ms and 120ms）for first query
		time.Sleep(time.Duration(rand.Intn(100)+20) * time.Millisecond)

		if continuous {
			counter := 0
			interval := time.Duration(0)
			for {
				query()

				if interval < time.Hour {
					// Exponential backoff: increase the interval
					interval = time.Duration(1<<counter) * time.Second
					if interval >= time.Hour || interval < 0 {
						// If the interval exceeds 60 minutes or is negative (overflow),
						// Cap the interval to 60 minutes
						interval = time.Hour
					}
				}

				select {
				case <-time.After(interval):
					counter += 1

				case <-ctx.Done():
					return
				}
			}
		} else {
			query()
		}
	}()

	es := []*BrowseEntry{}
	for {
		select {
		case q := <-qs:
			log.Debug.Printf("Send browsing query at %s\n%s\n", q.IfaceName(), q.msg)
			// Known-Answer Supression
			answer := make([]dns.RR, 0)
			for _, srv := range cache.Services() {
				if srv.ServiceName() != service {
					continue
				}

				if time.Until(srv.expiration) > srv.TTL/2 {
					answer = append(answer, PTR(*srv))
				}
			}
			q.msg.Answer = answer
			if err := conn.SendQuery(q); err != nil {
				log.Debug.Println("SendQuery:", err)
			}

		case req := <-ch:
			log.Debug.Printf("Receive message at %s\n%s\n", req.IfaceName(), req.msg)
			cache.UpdateFrom(req)
			for _, srv := range cache.Services() {
				if srv.ServiceName() != service {
					continue
				}

				for ifaceName, ips := range srv.ifaceIPs {
					var found = false
					for _, e := range es {
						if e.Name == srv.Name && e.IfaceName == ifaceName {
							found = true
							break
						}
					}
					if !found {
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
						es = append(es, &e)
						add(e)
					}
				}
			}

			tmp := []*BrowseEntry{}
			for _, e := range es {
				var found = false
				for _, srv := range cache.Services() {
					if srv.ServiceInstanceName() == e.ServiceInstanceName() {
						found = true
						break
					}
				}

				if found {
					tmp = append(tmp, e)
				} else {
					// TODO
					rmv(*e)
				}
			}
			es = tmp
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
