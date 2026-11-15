package dnssd

import (
	"github.com/miekg/dns"
	"net"
	"strings"
	"time"
)

// Address records are scoped to the receiving link. The one-second flush
// grace period preserves RRsets split over multiple packets (RFC 6762 10.2).
type addressKey struct {
	host, iface, ip string
	typ             uint16
}
type cachedAddress struct {
	ip                net.IP
	received, expires time.Time
}

func (c *Cache) updateAddresses(req *Request, records []dns.RR) {
	now := c.now()
	incoming := map[addressKey]cachedAddress{}
	flush := map[addressKey]bool{}
	for _, rr := range records {
		var ip net.IP
		switch r := rr.(type) {
		case *dns.A:
			ip = r.A
		case *dns.AAAA:
			ip = r.AAAA
		default:
			continue
		}
		h := rr.Header()
		if h.Class&0x7fff != dns.ClassINET {
			continue
		}
		key := addressKey{strings.ToLower(h.Name), req.IfaceName(), ip.String(), h.Rrtype}
		ttl := time.Duration(h.Ttl) * time.Second
		if ttl == 0 {
			if old, ok := c.addresses[key]; ok {
				deadline := now.Add(time.Second)
				if old.expires.After(deadline) {
					old.expires = deadline
					c.addresses[key] = old
				}
			}
			continue
		}
		incoming[key] = cachedAddress{append(net.IP(nil), ip...), now, now.Add(ttl)}
		if h.Class&0x8000 != 0 {
			key.ip = ""
			flush[key] = true
		}
	}
	for key, old := range c.addresses {
		scope := key
		scope.ip = ""
		if flush[scope] && now.Sub(old.received) >= time.Second {
			if _, present := incoming[key]; !present && old.expires.After(now.Add(time.Second)) {
				old.expires = now.Add(time.Second)
				c.addresses[key] = old
			}
		}
	}
	for key, record := range incoming {
		c.addresses[key] = record
	}
}

func (c *Cache) expireAddresses() {
	now := c.now()
	for key, record := range c.addresses {
		if !now.Before(record.expires) {
			delete(c.addresses, key)
		}
	}
	for _, srv := range c.services {
		srv.IPs = nil
		srv.ifaceIPs = map[string][]net.IP{}
		for key, record := range c.addresses {
			if strings.EqualFold(key.host, srv.Hostname()) {
				if key.iface == "?" {
					srv.addIP(record.ip, nil)
				} else {
					srv.addIP(record.ip, &net.Interface{Name: key.iface})
				}
			}
		}
	}
}
