package dnssd

import (
	"context"
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"net"
	"os"
	"reflect"
	"testing"
	"time"
)

func TestLegacyResponseValidation(t *testing.T) {
	_, network, _ := net.ParseCIDR("192.0.2.0/24")
	e := &legacyEndpoint{network: network}
	q := dns.Question{Name: "_scm._tcp.local.", Qtype: dns.TypePTR, Qclass: dns.ClassINET}
	now := time.Now()
	p := legacyQuestion{q, now.Add(time.Second)}
	good := &dns.Msg{MsgHdr: dns.MsgHdr{Response: true}, Question: []dns.Question{q}}
	source := &net.UDPAddr{IP: net.ParseIP("192.0.2.3"), Port: 5353}
	if !validLegacyResponse(good, source, e, p, now) {
		t.Fatal("valid response rejected")
	}
	for name, mutate := range map[string]func(*dns.Msg){"query": func(m *dns.Msg) { m.Response = false }, "truncated": func(m *dns.Msg) { m.Truncated = true }, "wrong question": func(m *dns.Msg) { m.Question[0].Name = "_other._tcp.local." }, "no question": func(m *dns.Msg) { m.Question = nil }, "wrong type": func(m *dns.Msg) { m.Question[0].Qtype = dns.TypeA }, "error": func(m *dns.Msg) { m.Rcode = dns.RcodeServerFailure }} {
		t.Run(name, func(t *testing.T) {
			m := good.Copy()
			mutate(m)
			if validLegacyResponse(m, source, e, p, now) {
				t.Fatal("invalid response accepted")
			}
		})
	}
	if validLegacyResponse(good, source, e, p, now.Add(time.Second)) {
		t.Fatal("expired response accepted")
	}
	for _, src := range []*net.UDPAddr{{IP: source.IP, Port: 12345}, {IP: net.ParseIP("198.51.100.3"), Port: 5353}} {
		if validLegacyResponse(good, src, e, p, now) {
			t.Fatal("invalid source accepted")
		}
	}
}

func TestLegacyResponderWireSemantics(t *testing.T) {
	iface := &net.Interface{Name: "legacy-test"}
	c := newTestConn(iface)
	defer c.Close()
	r := newResponder(c)
	s := newService("Peer._scm._tcp.local.")
	s.SetHostname("peer.local.")
	s.Port = 1234
	s.ifaceIPs[iface.Name] = []net.IP{net.ParseIP("192.0.2.3")}
	q := dns.Question{Name: s.ServiceName(), Qtype: dns.TypePTR, Qclass: dns.ClassINET}
	request := &dns.Msg{MsgHdr: dns.MsgHdr{Id: 54321}, Question: []dns.Question{q}}
	r.handleQuery(&Request{msg: request, iface: iface, from: &net.UDPAddr{IP: net.ParseIP("192.0.2.4"), Port: 41000}}, []*Service{s})
	select {
	case response := <-c.out:
		if response.Id != 54321 || !response.Response || len(response.Question) != 1 || response.Question[0] != q {
			t.Fatalf("legacy header/questions changed: %v", response)
		}
		if len(response.Answer) == 0 || len(response.Extra) == 0 {
			t.Fatal("incomplete answer")
		}
		for _, rrs := range [][]dns.RR{response.Answer, response.Ns, response.Extra} {
			for _, rr := range rrs {
				if rr.Header().Ttl > 10 || rr.Header().Class&0x8000 != 0 {
					t.Fatalf("invalid legacy record: %v", rr)
				}
			}
		}
	case <-time.After(time.Second):
		t.Fatal("no response")
	}
	m := &dns.Msg{Answer: []dns.RR{forkAddress("192.0.2.1", 0, true)}, Extra: []dns.RR{forkAddress("192.0.2.2", 120, true)}}
	normalizeLegacyRecords(m)
	if m.Answer[0].Header().Ttl != 0 || m.Extra[0].Header().Ttl != 10 || m.Extra[0].Header().Class != dns.ClassINET {
		t.Fatal("TTL/flush normalization failed")
	}
}

func TestLegacyCloseReleasesSocket(t *testing.T) {
	c := addLegacyQueries(context.Background(), &forkConn{requests: make(chan *Request)})
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	addr := socket.LocalAddr().(*net.UDPAddr)
	e := &legacyEndpoint{conn: socket, pending: make(map[uint16]legacyQuestion)}
	c.mu.Lock()
	c.endpoints["test"] = e
	c.workers.Add(1)
	c.mu.Unlock()
	go func() { defer c.workers.Done(); c.receiveLegacy(e) }()
	done := make(chan struct{})
	go func() { c.Close(); c.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close blocked on reader")
	}
	again, err := net.ListenUDP("udp4", addr)
	if err != nil {
		t.Fatalf("socket not released: %v", err)
	}
	again.Close()
}

// The standard receive channel is deliberately silent: all discoveries must
// arrive on our ephemeral socket, even while other listeners share 5353.
func TestLegacyBrowseWithoutMulticastReceive(t *testing.T) {
	if os.Getenv("DNSSD_TEST_MULTICAST") != "1" {
		t.Skip("set DNSSD_TEST_MULTICAST=1 for legacy network integration")
	}
	iface := testMulticastInterface(t)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	base, err := newMDNSConn(iface.Name)
	if err != nil {
		t.Fatal(err)
	}
	id := fmt.Sprintf("legacy-%x", time.Now().UnixNano())
	srv, err := NewService(Config{Name: id, Host: id, Type: "_dnssd-test._tcp", Port: 12345, Ifaces: []string{iface.Name}})
	if err != nil {
		t.Fatal(err)
	}
	startTestResponder(t, ctx, base, srv)
	c := addLegacyQueries(ctx, &forkConn{requests: make(chan *Request)})
	defer c.Close()
	count := 0
	err = lookupType(ctx, srv.ServiceName(), c, func(e BrowseEntry) {
		if e.Name == id {
			count++
			if e.Port != 12345 || len(e.IPs) == 0 {
				t.Error("incomplete legacy discovery")
			}
			cancel()
		}
	}, func(BrowseEntry) {}, true, iface.Name)
	if err != context.Canceled || count != 1 {
		t.Fatalf("legacy discovery failed: count=%d err=%v", count, err)
	}
}

func TestLegacyAndMulticastDeduplicate(t *testing.T) {
	if os.Getenv("DNSSD_TEST_MULTICAST") != "1" {
		t.Skip("set DNSSD_TEST_MULTICAST=1 for dual transport integration")
	}
	iface := testMulticastInterface(t)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	base, err := newMDNSConn(iface.Name)
	if err != nil {
		t.Fatal(err)
	}
	id := fmt.Sprintf("dual-%x", time.Now().UnixNano())
	srv, err := NewService(Config{Name: id, Host: id, Type: "_dnssd-test._tcp", Port: 12345, Ifaces: []string{iface.Name}})
	if err != nil {
		t.Fatal(err)
	}
	startTestResponder(t, ctx, base, srv)
	adds, removes := 0, 0
	var timer *time.Timer
	err = LookupTypeWithOptions(ctx, srv.ServiceName(), func(e BrowseEntry) {
		if e.Name == id {
			adds++
			if timer == nil {
				timer = time.AfterFunc(3*time.Second, cancel)
			}
		}
	}, func(e BrowseEntry) {
		if e.Name == id {
			removes++
		}
	}, BrowseOptions{Interfaces: []string{iface.Name}, Continuous: true, LegacyUnicast: true})
	if timer != nil {
		timer.Stop()
	}
	if err != context.Canceled || adds != 1 || removes != 0 {
		t.Fatalf("duplicate/unstable discovery: adds=%d removes=%d err=%v", adds, removes, err)
	}
}

func TestLegacyReaderFailureRetiresEndpoint(t *testing.T) {
	c := addLegacyQueries(context.Background(), &forkConn{requests: make(chan *Request)})
	defer c.Close()
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	e := &legacyEndpoint{conn: socket, pending: make(map[uint16]legacyQuestion)}
	c.mu.Lock()
	c.endpoints["test"] = e
	c.workers.Add(1)
	c.mu.Unlock()
	finished := make(chan struct{})
	go func() { defer c.workers.Done(); c.receiveLegacy(e); close(finished) }()
	socket.Close() // simulate a socket failure while the lookup is still active
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("failed reader did not exit")
	}
	c.mu.Lock()
	_, exists := c.endpoints["test"]
	c.mu.Unlock()
	if exists {
		t.Fatal("failed socket retained, preventing replacement")
	}
	if c.ctx.Err() != nil {
		t.Fatal("one endpoint failure canceled the browser")
	}
}
func TestLegacyPrefixChangeUpdatesSourceFilter(t *testing.T) {
	e := &legacyEndpoint{network: &net.IPNet{IP: net.ParseIP("192.0.2.10"), Mask: net.CIDRMask(24, 32)}}
	q := dns.Question{Name: "_scm._tcp.local.", Qtype: dns.TypePTR, Qclass: dns.ClassINET}
	now := time.Now()
	pending := legacyQuestion{question: q, expires: now.Add(time.Second)}
	response := &dns.Msg{MsgHdr: dns.MsgHdr{Response: true}, Question: []dns.Question{q}}
	source := &net.UDPAddr{IP: net.ParseIP("192.0.3.20"), Port: 5353}
	if validLegacyResponse(response, source, e, pending, now) {
		t.Fatal("source should not match original /24")
	}
	if !e.refreshNetwork([]net.Addr{&net.IPNet{IP: net.ParseIP("192.0.2.10"), Mask: net.CIDRMask(23, 32)}}) {
		t.Fatal("bound address should survive prefix change")
	}
	if !validLegacyResponse(response, source, e, pending, now) {
		t.Fatal("source rejected after prefix expansion")
	}
	if !e.refreshNetwork([]net.Addr{&net.IPNet{IP: net.ParseIP("192.0.2.10"), Mask: net.CIDRMask(24, 32)}}) {
		t.Fatal("bound address disappeared")
	}
	if validLegacyResponse(response, source, e, pending, now) {
		t.Fatal("stale broad prefix accepted source")
	}
}

func legacyTestAddresses(cidrs ...string) []net.Addr {
	var out []net.Addr
	for _, cidr := range cidrs {
		ip, network, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(err)
		}
		network.IP = ip
		out = append(out, network)
	}
	return out
}

func TestLegacyAddressCandidatesRetainAlternatives(t *testing.T) {
	addrs := legacyTestAddresses("192.0.2.20/24", "198.51.100.10/24", "192.0.2.10/24", "2001:db8:1::2/64", "2001:db8:1::1/64", "2001:db8:2::1/64", "fe80::1/64", "127.0.0.1/8", "::1/128")
	expected := []string{"192.0.2.10/24", "192.0.2.20/24", "198.51.100.10/24", "2001:db8:1::1/64", "2001:db8:1::2/64", "2001:db8:2::1/64", "fe80::1/64"}
	check := func() {
		got := legacyNetworks(addrs)
		if len(got) != len(expected) {
			t.Fatalf("prefixes: %v", got)
		}
		for i, n := range got {
			if n.String() != expected[i] {
				t.Fatalf("prefixes: %v", got)
			}
		}
	}
	check()
	for i, j := 0, len(addrs)-1; i < j; i, j = i+1, j-1 {
		addrs[i], addrs[j] = addrs[j], addrs[i]
	}
	check()
}

func TestLegacySourceFilterTracksAllInterfacePrefixes(t *testing.T) {
	e := &legacyEndpoint{iface: net.Interface{Name: "test", Index: 7}, network: legacyTestAddresses("192.0.2.10/24")[0].(*net.IPNet)}
	now := time.Now()
	q := dns.Question{Name: "_scm._tcp.local.", Qtype: dns.TypePTR, Qclass: dns.ClassINET}
	p := legacyQuestion{q, now.Add(time.Second)}
	m := &dns.Msg{MsgHdr: dns.MsgHdr{Response: true}, Question: []dns.Question{q}}
	accepts := func(ip string) bool {
		return validLegacyResponse(m, &net.UDPAddr{IP: net.ParseIP(ip), Port: 5353}, e, p, now)
	}
	if !e.refreshNetwork(legacyTestAddresses("192.0.2.10/24", "198.51.100.10/24")) {
		t.Fatal("bound address missing")
	}
	if !accepts("192.0.2.30") || !accepts("198.51.100.30") || accepts("203.0.113.30") {
		t.Fatal("incorrect multi-prefix filter")
	}
	if !e.refreshNetwork(legacyTestAddresses("192.0.2.10/24")) || accepts("198.51.100.30") {
		t.Fatal("removed prefix still accepted")
	}
	if e.refreshNetwork(legacyTestAddresses("198.51.100.10/24")) {
		t.Fatal("removed bound address survived")
	}
}

func TestLegacyIPv6SourceScope(t *testing.T) {
	e := &legacyEndpoint{iface: net.Interface{Name: "test", Index: 7}, network: legacyTestAddresses("2001:db8:1::1/64")[0].(*net.IPNet)}
	e.refreshNetwork(legacyTestAddresses("2001:db8:1::1/64", "2001:db8:2::1/64"))
	for _, tt := range []struct {
		ip, zone string
		want     bool
	}{
		{"2001:db8:2::2", "", true}, {"2001:db8:3::2", "", false},
		{"fe80::2", "test", true}, {"fe80::2", "7", true}, {"fe80::2", "other", false},
		{"192.0.2.3", "", false},
	} {
		if got := e.acceptsSource(&net.UDPAddr{IP: net.ParseIP(tt.ip), Zone: tt.zone}); got != tt.want {
			t.Fatalf("%+v: %v", tt, got)
		}
	}
}

func TestLegacyNegativeTXTValidation(t *testing.T) {
	e := &legacyEndpoint{network: legacyTestAddresses("192.0.2.10/24")[0].(*net.IPNet)}
	now := time.Now()
	q := dns.Question{Name: "Peer._scm._tcp.local.", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}
	p := legacyQuestion{q, now.Add(time.Second)}
	m := &dns.Msg{MsgHdr: dns.MsgHdr{Response: true, Rcode: dns.RcodeNameError}, Question: []dns.Question{q}}
	from := &net.UDPAddr{IP: net.ParseIP("192.0.2.20"), Port: 5353}
	if !validLegacyResponse(m, from, e, p, now) {
		t.Fatal("explicit TXT absence rejected")
	}
	m.Question[0].Name = "Other._scm._tcp.local."
	if validLegacyResponse(m, from, e, p, now) {
		t.Fatal("unrelated denial accepted")
	}
	m.Question[0] = q
	m.Opcode = dns.OpcodeUpdate
	if validLegacyResponse(m, from, e, p, now) {
		t.Fatal("wrong opcode accepted")
	}
	m.Opcode = dns.OpcodeQuery
	p.question.Qtype = dns.TypeSRV
	m.Question[0].Qtype = dns.TypeSRV
	if validLegacyResponse(m, from, e, p, now) {
		t.Fatal("SRV NXDOMAIN accepted as TXT completion")
	}
}

func TestLegacyEndpointBindFallback(t *testing.T) {
	for _, tt := range []struct {
		name  string
		cidrs []string
	}{
		{"ipv4", []string{"192.0.2.10/24", "192.0.2.20/24", "192.0.2.30/24", "198.51.100.10/24"}},
		{"ipv6", []string{"2001:db8:1::1/64", "2001:db8:1::2/64", "2001:db8:1::3/64", "2001:db8:2::1/64"}},
	} {
		for _, failCount := range []int{0, 1, 3} {
			t.Run(fmt.Sprintf("%s/fail-%d", tt.name, failCount), func(t *testing.T) {
				sink, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
				if err != nil {
					t.Fatal(err)
				}
				defer sink.Close()
				c := addLegacyQueries(context.Background(), &forkConn{requests: make(chan *Request)})
				defer c.Close()
				iface := &net.Interface{Name: "bind-fallback", Index: 7}
				q := &Query{iface: iface, msg: &dns.Msg{Question: []dns.Question{{Name: "_test._tcp.local.", Qtype: dns.TypePTR, Qclass: dns.ClassINET}}}}
				addrs := legacyTestAddresses(tt.cidrs...)
				// Enumeration order must not change the deterministic fallback sequence.
				for i, j := 0, len(addrs)-1; i < j; i, j = i+1, j-1 {
					addrs[i], addrs[j] = addrs[j], addrs[i]
				}
				bindErr := errors.New("injected bind failure")
				var attempts []string
				open := func(iface *net.Interface, network *net.IPNet) (*legacyEndpoint, error) {
					attempts = append(attempts, network.String())
					for i := 0; i < failCount; i++ {
						if network.String() == tt.cidrs[i] {
							return nil, bindErr
						}
					}
					socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
					if err != nil {
						return nil, err
					}
					// Only binding is substituted. The production query packing, sending,
					// pending transactions, endpoint registration and cleanup all run.
					return &legacyEndpoint{conn: socket, iface: *iface, network: network, destination: sink.LocalAddr().(*net.UDPAddr), pending: make(map[uint16]legacyQuestion)}, nil
				}
				c.mu.Lock()
				err = c.sendLegacyQueries(q, addrs, open)
				endpointCount := len(c.endpoints)
				c.mu.Unlock()
				if (failCount > 0) != errors.Is(err, bindErr) {
					t.Fatalf("unexpected bind diagnostics: %v", err)
				}
				stop := failCount + 1
				if stop > 3 {
					stop = 3
				}
				expected := append(append([]string(nil), tt.cidrs[:stop]...), tt.cidrs[3])
				if !reflect.DeepEqual(attempts, expected) {
					t.Fatalf("attempts=%v want=%v", attempts, expected)
				}
				wantEndpoints := 2
				if failCount == 3 {
					wantEndpoints = 1
				}
				if endpointCount != wantEndpoints {
					t.Fatalf("endpoints=%d want=%d", endpointCount, wantEndpoints)
				}
				sink.SetReadDeadline(time.Now().Add(time.Second))
				sources := make(map[string]bool)
				packet := make([]byte, 1500)
				for i := 0; i < wantEndpoints; i++ {
					n, source, err := sink.ReadFromUDP(packet)
					if err != nil {
						t.Fatalf("successful fallback did not send: %v", err)
					}
					m := new(dns.Msg)
					if err := m.Unpack(packet[:n]); err != nil {
						t.Fatal(err)
					}
					if len(m.Question) != 1 || m.Question[0] != q.msg.Question[0] {
						t.Fatalf("wrong query: %v", m)
					}
					sources[source.String()] = true
				}
				if len(sources) != wantEndpoints {
					t.Fatalf("queries did not come from distinct endpoints: %v", sources)
				}
			})
		}
	}
}
