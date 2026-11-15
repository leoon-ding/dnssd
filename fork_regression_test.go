package dnssd

import (
	"context"
	"github.com/miekg/dns"
	"net"
	"sync"
	"testing"
	"time"
)

func forkCache() (*Cache, *Service, *net.Interface, *time.Time) {
	c := NewCache()
	now := time.Unix(1000, 0)
	c.now = func() time.Time { return now }
	s := newService("Peer._scm._tcp.local.")
	s.SetHostname("peer.local.")
	s.expiration = now.Add(time.Hour)
	c.services[s.EscapedServiceInstanceName()] = s
	return c, s, &net.Interface{Name: "first", Index: 7}, &now
}
func forkAddress(ip string, ttl uint32, flush bool) dns.RR {
	class := uint16(dns.ClassINET)
	if flush {
		class |= 0x8000
	}
	h := dns.RR_Header{Name: "peer.local.", Class: class, Ttl: ttl}
	addr := net.ParseIP(ip)
	if addr.To4() != nil {
		h.Rrtype = dns.TypeA
		return &dns.A{Hdr: h, A: addr}
	}
	h.Rrtype = dns.TypeAAAA
	return &dns.AAAA{Hdr: h, AAAA: addr}
}
func TestForkCacheFlushRRSet(t *testing.T) {
	for _, ips := range [][]string{{"192.168.1.10", "192.168.1.11"}, {"fd00::10", "fd00::11"}} {
		c, s, i, now := forkCache()
		send := func(addrs ...string) {
			m := &dns.Msg{}
			for _, ip := range addrs {
				m.Answer = append(m.Answer, forkAddress(ip, 120, true))
			}
			c.UpdateFrom(&Request{iface: i, msg: m})
		}
		send(ips...)
		if len(s.IPs) != 2 {
			t.Fatalf("RRset lost: %v", s.IPs)
		}
		*now = now.Add(2 * time.Second)
		send(ips[1])
		if len(s.IPs) != 2 {
			t.Fatal("flush removed old record before grace")
		}
		*now = now.Add(time.Second)
		c.removeExpired()
		if len(s.IPs) != 1 || !s.IPs[0].Equal(net.ParseIP(ips[1])) {
			t.Fatalf("old record not flushed: %v", s.IPs)
		}
		c, s, i, now = forkCache()
		send(ips[0])
		*now = now.Add(100 * time.Millisecond)
		send(ips[1])
		*now = now.Add(2 * time.Second)
		c.removeExpired()
		if len(s.IPs) != 2 {
			t.Fatalf("split RRset lost: %v", s.IPs)
		}
	}
}
func TestForkAddressScopesAndExpiry(t *testing.T) {
	c, s, i, now := forkCache()
	j := &net.Interface{Name: "second", Index: 8}
	c.UpdateFrom(&Request{iface: i, msg: &dns.Msg{Answer: []dns.RR{forkAddress("192.168.1.10", 2, true)}}})
	c.UpdateFrom(&Request{iface: j, msg: &dns.Msg{Answer: []dns.RR{forkAddress("10.0.0.10", 120, true)}}})
	*now = now.Add(2 * time.Second)
	c.removeExpired()
	if len(s.IPs) != 1 || len(s.ifaceIPs[j.Name]) != 1 || len(s.ifaceIPs[i.Name]) != 0 {
		t.Fatalf("bad scope/expiry: %v", s.ifaceIPs)
	}
}
func TestForkClearAddressScope(t *testing.T) {
	for _, ips := range [][]string{{"192.168.1.10", "10.0.0.10"}, {"fd00::10", "fd00::11"}} {
		_, s, i, _ := forkCache()
		j := &net.Interface{Name: "second"}
		s.addIP(net.ParseIP(ips[0]), i)
		s.addIP(net.ParseIP(ips[1]), j)
		if net.ParseIP(ips[0]).To4() != nil {
			s.clearIPv4Records(i)
		} else {
			s.clearIPv6Records(i)
		}
		if len(s.IPs) != 1 || !s.IPs[0].Equal(net.ParseIP(ips[1])) {
			t.Fatalf("other interface cleared: %v", s.IPs)
		}
	}
}
func TestForkTXTSnapshotAndDeletion(t *testing.T) {
	c, s, i, _ := forkCache()
	send := func(txt ...string) {
		c.UpdateFrom(&Request{iface: i, msg: &dns.Msg{Answer: []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: s.EscapedServiceInstanceName(), Rrtype: dns.TypeTXT, Class: 1, Ttl: 120}, Txt: txt}}}})
	}
	send("ver=1", "removed=yes")
	e := BrowseEntry{Text: s.Text}
	send("ver=2")
	if e.Text["ver"] != "1" || len(s.Text) != 1 || mapsEqual(e.Text, s.Text) {
		t.Fatal("TXT snapshot or replacement broken")
	}
	if mapsEqual(map[string]string{"a": ""}, map[string]string{"b": ""}) {
		t.Fatal("different empty-valued keys compare equal")
	}
	original := BrowseEntry{Text: map[string]string{"v": "1"}, IPs: []net.IP{net.ParseIP("192.168.1.1")}}
	copy := cloneBrowseEntry(original)
	copy.Text["v"] = "2"
	copy.IPs[0][0] ^= 255
	if original.Text["v"] != "1" || original.IPs[0].Equal(copy.IPs[0]) {
		t.Fatal("callback aliases internal state")
	}
}

type forkConn struct{ requests chan *Request }

func (c *forkConn) Read(context.Context) <-chan *Request { return c.requests }
func (*forkConn) SendQuery(*Query) error                 { return nil }
func (*forkConn) SendResponse(*Response) error           { return nil }
func (*forkConn) Drain(context.Context)                  {}
func (*forkConn) Close()                                 {}

func TestForkBrowseExpiresWithoutTraffic(t *testing.T) {
	c := &forkConn{make(chan *Request, 1)}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	srv := newService("Peer._scm._tcp.local.")
	srv.SetHostname("peer.local.")
	srv.Port = 1234
	records := []dns.RR{PTR(*srv), SRV(*srv), TXT(*srv), forkAddress("192.168.1.10", 1, true)}
	for _, rr := range records {
		rr.Header().Ttl = 1
	}
	c.requests <- &Request{iface: &net.Interface{Name: "test"}, msg: &dns.Msg{Answer: records}}
	added, removed := 0, 0
	err := lookupType(ctx, srv.ServiceName(), c, func(e BrowseEntry) { added++; e.Text["changed"] = "yes" }, func(BrowseEntry) { removed++; cancel() }, true, "no-such-interface")
	if err != context.Canceled || added != 1 || removed != 1 {
		t.Fatalf("err=%v add=%d remove=%d", err, added, removed)
	}
}
func TestForkBrowseCancellationAndClosedInput(t *testing.T) {
	for n := 0; n < 50; n++ {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		c := &forkConn{make(chan *Request)}
		if err := lookupType(ctx, "_scm._tcp.local.", c, func(BrowseEntry) {}, func(BrowseEntry) {}, true); err != context.Canceled {
			t.Fatal(err)
		}
	}
	c := &forkConn{make(chan *Request)}
	close(c.requests)
	if err := lookupType(context.Background(), "_scm._tcp.local.", c, func(BrowseEntry) {}, func(BrowseEntry) {}, true); err != nil {
		t.Fatal(err)
	}
}
func TestForkReprobeStopped(t *testing.T) {
	r := &responder{mutex: &sync.Mutex{}}
	r.reprobe(&serviceHandle{service: newService("Peer._scm._tcp.local.")})
	if len(r.managed) != 0 {
		t.Fatal("stopped responder revived")
	}
}

func TestForkDetachMultipleManagedServices(t *testing.T) {
	r := &responder{}
	for _, name := range []string{"One", "Two", "Three"} {
		r.managed = append(r.managed, &serviceHandle{service: newService(name + "._scm._tcp.local.")})
	}
	original := append([]*serviceHandle(nil), r.managed...)
	pending := r.takeManaged()
	if len(pending) != 3 || len(r.managed) != 0 {
		t.Fatal("batch not detached")
	}
	for i, h := range pending {
		if h != original[i] {
			t.Fatal("service skipped or duplicated")
		}
	}
}
func TestForkServiceCopyIsolation(t *testing.T) {
	_, s, i, _ := forkCache()
	s.addIP(net.ParseIP("192.168.1.10"), i)
	s.Text["v"] = "1"
	s.Ifaces = []string{i.Name}
	copy := s.Copy()
	copy.Text["v"] = "2"
	copy.IPs[0][0] ^= 255
	copy.ifaceIPs[i.Name][0][1] ^= 255
	copy.Ifaces[0] = "changed"
	if s.Text["v"] != "1" || s.Ifaces[0] != i.Name || !s.IPs[0].Equal(net.ParseIP("192.168.1.10")) {
		t.Fatal("copy aliases service state")
	}
}
func TestForkAddressGoodbyeAndRescue(t *testing.T) {
	c, s, i, now := forkCache()
	send := func(ttl uint32) {
		c.UpdateFrom(&Request{iface: i, msg: &dns.Msg{Answer: []dns.RR{forkAddress("192.168.1.10", ttl, true)}}})
	}
	send(120)
	send(0)
	if len(s.IPs) != 1 {
		t.Fatal("goodbye ignored grace")
	}
	*now = now.Add(500 * time.Millisecond)
	send(120)
	*now = now.Add(time.Second)
	c.removeExpired()
	if len(s.IPs) != 1 {
		t.Fatal("refresh failed to rescue address")
	}
	send(0)
	*now = now.Add(time.Second)
	c.removeExpired()
	if len(s.IPs) != 0 {
		t.Fatal("goodbye did not expire")
	}
}
