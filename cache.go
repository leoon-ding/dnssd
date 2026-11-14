package dnssd

import (
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Cache stores services in memory.
type Cache struct {
	services  map[string]*Service
	addresses map[addressKey]cachedAddress
	now       func() time.Time
}

// NewCache returns a new in-memory cache.
func NewCache() *Cache {
	return &Cache{
		services:  make(map[string]*Service),
		addresses: make(map[addressKey]cachedAddress),
		now:       time.Now,
	}
}

// Services returns a list of stored services.
func (c *Cache) Services() []*Service {
	tmp := []*Service{}
	for _, s := range c.services {
		tmp = append(tmp, s)
	}
	return tmp
}

// UpdateFrom updates the cache from resource records in msg.
// Handles cache-flush bit to replace outdated cache entries according to RFC 6762
func (c *Cache) UpdateFrom(req *Request) (adds []*Service, rmvs []*Service) {
	var answers []dns.RR
	answers = append(answers, req.msg.Answer...)
	answers = append(answers, req.msg.Extra...)
	sort.Stable(byType(answers))

	for _, answer := range answers {

		switch rr := answer.(type) {
		case *dns.PTR:
			ttl := time.Duration(rr.Hdr.Ttl) * time.Second

			var entry *Service
			if e, ok := c.services[rr.Ptr]; !ok {
				if ttl == 0 {
					// Ignore new records with no ttl
					break
				}
				entry = newService(rr.Ptr)
				adds = append(adds, entry)
				c.services[entry.EscapedServiceInstanceName()] = entry
			} else {
				entry = e
			}

			entry.TTL = ttl
			entry.expiration = c.now().Add(ttl)

		case *dns.SRV:
			ttl := time.Duration(rr.Hdr.Ttl) * time.Second
			var entry *Service
			if e, ok := c.services[rr.Hdr.Name]; !ok {
				if ttl == 0 {
					// Ignore new records with no ttl
					break
				}
				entry = newService(rr.Hdr.Name)
				adds = append(adds, entry)
				c.services[entry.EscapedServiceInstanceName()] = entry
			} else {
				entry = e
			}

			entry.SetHostname(rr.Target)
			entry.TTL = ttl
			entry.expiration = c.now().Add(ttl)
			entry.Port = int(rr.Port)

		case *dns.TXT:
			if entry, ok := c.services[rr.Hdr.Name]; ok {
				text := make(map[string]string)
				for _, txt := range rr.Txt {
					elems := strings.SplitN(txt, "=", 2)
					if len(elems) == 2 {
						key := elems[0]
						value := elems[1]
						text[key] = value
					}
				}

				// A TXT RR is a complete value, including when received via legacy unicast.
				entry.Text = text

				entry.TTL = time.Duration(rr.Hdr.Ttl) * time.Second
				entry.expiration = c.now().Add(entry.TTL)
			}
		default:
			// ignore
		}
	}

	c.updateAddresses(req, answers)
	rmvs = c.removeExpired()

	return
}

func (c *Cache) removeExpired() []*Service {
	var outdated []*Service
	var services = c.services
	for key, srv := range services {
		if !c.now().Before(srv.expiration) {
			outdated = append(outdated, srv)
			delete(c.services, key)
		}
	}

	c.expireAddresses()
	return outdated
}

type byType []dns.RR

func (a byType) Len() int      { return len(a) }
func (a byType) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a byType) Less(i, j int) bool {
	priority := func(rr dns.RR) int {
		switch rr.(type) {
		case *dns.PTR, *dns.SRV:
			return 0
		}
		return 1
	}
	return priority(a[i]) < priority(a[j])
}

// filterRecords returns
// - A and AAAA records for the same hostname as in defined by the service
// - SRV records related to the same service instance name
func filterRecords(req *Request, service *Service) []dns.RR {
	if req.iface != nil && service != nil && len(service.Ifaces) > 0 {
		if !service.IsVisibleAtInterface(req.iface.Name) {
			// Ignore records if the request coming from an ignored interface.
			return []dns.RR{}
		}
	}

	var all []dns.RR
	all = append(all, req.msg.Answer...)
	all = append(all, req.msg.Ns...)
	all = append(all, req.msg.Extra...)

	if service == nil {
		return all
	}

	var answers []dns.RR
	for _, answer := range all {
		switch rr := answer.(type) {
		case *dns.SRV:
			if rr.Target == service.Hostname() {
				// Ignore records coming from ourself
				continue
			}
			if rr.Hdr.Name != service.EscapedServiceInstanceName() {
				// Ignore records from other service instances
				continue
			}
		case *dns.A:
			if rr.Hdr.Name != service.Hostname() {
				// Ignore IPv4 address from other hosts
				continue
			}

			ip := rr.A.To4()
			if service.HasIPOnAnyInterface(ip) {
				// Ignore this record because we know that the service
				// has this ip address but on a different interface.
				continue
			}

		case *dns.AAAA:
			if rr.Hdr.Name != service.Hostname() {
				// Ignore IPv6 address from other hosts
				continue
			}

			ip := rr.AAAA.To16()
			if service.HasIPOnAnyInterface(ip) {
				// Ignore this record because we know that the service
				// has this ip address but on a different interface.
				continue
			}
		}
		answers = append(answers, answer)
	}

	return answers
}
