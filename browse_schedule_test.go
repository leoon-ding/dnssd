package dnssd

import (
	"context"
	"github.com/miekg/dns"
	"net"
	"testing"
	"time"
)

func scheduleFixture() (*browseRecords, *Request, time.Time) {
	now := time.Unix(1000, 0)
	srv := newService("Peer._scm._tcp.local.")
	srv.SetHostname("peer.local.")
	srv.Port = 1234
	rrs := []dns.RR{PTR(*srv), SRV(*srv), TXT(*srv), forkAddress("192.0.2.1", 120, true)}
	for _, r := range rrs {
		r.Header().Ttl = 120
	}
	req := &Request{iface: &net.Interface{Name: "test", Index: 7}, msg: &dns.Msg{MsgHdr: dns.MsgHdr{Response: true}, Answer: rrs}}
	b := newBrowseRecords(srv.ServiceName())
	b.update(req, now)
	return b, req, now
}
func TestBrowseRenewalStagesAndReset(t *testing.T) {
	b, req, now := scheduleFixture()
	s := newBrowseSchedule(now, BrowseOptions{Continuous: true})
	s.discovery = time.Time{}
	for stage := 0; stage < 4; stage++ {
		for _, r := range b.records {
			low := now.Add(time.Duration(80+5*stage) * 120 * time.Second / 100)
			high := low.Add(2400 * time.Millisecond)
			if r.refresh.Before(low) || r.refresh.After(high) {
				t.Fatalf("stage %d deadline=%v", stage, r.refresh)
			}
		}
		// All four records have reached this retry stage.
		at := now.Add(time.Duration(82+stage*5) * 120 * time.Second / 100)
		batches := s.queries(b, req.iface, at)
		if len(batches) != 1 || batches[0].legacy || len(batches[0].msg.Question) != 4 {
			t.Fatalf("stage %d: %#v", stage, batches)
		}
		for _, q := range batches[0].msg.Question {
			if q.Qclass != dns.ClassINET {
				t.Fatal("renewal must be QM")
			}
		}
	}
	for _, r := range b.records {
		if !r.refresh.IsZero() {
			t.Fatal("more than four retries")
		}
	}
	renewed := now.Add(118 * time.Second)
	b.update(req, renewed)
	for _, r := range b.records {
		if r.stage != 0 || r.refresh.Before(renewed.Add(96*time.Second)) {
			t.Fatal("answer did not reset renewal")
		}
	}
}
func TestLegacyDoesNotRenewOrShortenNormal(t *testing.T) {
	for _, legacyFirst := range []bool{false, true} {
		b, req, now := scheduleFixture()
		legacy := &Request{iface: req.iface, msg: req.msg.Copy(), legacy: true}
		for _, rr := range legacy.msg.Answer {
			rr.Header().Ttl = 10
		}
		if legacyFirst {
			b = newBrowseRecords(b.service)
			b.update(legacy, now)
			b.update(req, now)
		} else {
			b.update(legacy, now)
		}
		if len(b.records) != 8 {
			t.Fatal("provenance lost")
		}
		for _, r := range b.records {
			if r.legacy && !r.refresh.IsZero() {
				t.Fatal("legacy scheduled renewal")
			}
		}
		b.expire(now.Add(11 * time.Second))
		if len(b.records) != 4 || len(b.snapshot(now.Add(11*time.Second)).Services()) != 1 {
			t.Fatal("legacy expiry removed normal service")
		}
	}
}
func TestLegacyOnlyExpiresWithoutRenewal(t *testing.T) {
	_, req, now := scheduleFixture()
	req.legacy = true
	b := newBrowseRecords("_scm._tcp.local.")
	b.update(req, now)
	s := newBrowseSchedule(now, BrowseOptions{Continuous: true, LegacyUnicast: true})
	s.advance(now.Add(time.Second))
	s.discovery = now.Add(time.Hour)
	if s.legacy.Before(now.Add(270*time.Second)) || s.legacy.After(now.Add(331*time.Second)) {
		t.Fatal(s.legacy)
	}
	if got := s.next(b, now); !got.Equal(now.Add(10 * time.Second)) {
		t.Fatal(got)
	}
	if got := s.queries(b, req.iface, now.Add(8*time.Second)); len(got) != 0 {
		t.Fatal("legacy TTL triggered query")
	}
	b.expire(now.Add(10 * time.Second))
	if len(b.snapshot(now.Add(10*time.Second)).Services()) != 0 {
		t.Fatal("expired result retained")
	}
	if got := s.next(b, now.Add(10*time.Second)); !got.Equal(s.legacy) {
		t.Fatal("wrong next query", got)
	}
}
func TestBrowseCoalescesSamePathButNotLegacy(t *testing.T) {
	b, req, now := scheduleFixture()
	s := newBrowseSchedule(now, BrowseOptions{Continuous: true, LegacyUnicast: true})
	at := now.Add(98 * time.Second)
	s.discovery = at
	s.legacy = at
	for _, r := range b.records {
		r.refresh = at
	}
	batches := s.queries(b, req.iface, at)
	if len(batches) != 2 || len(batches[0].msg.Question) != 4 || !batches[1].legacy {
		t.Fatal("lost or duplicated questions", batches)
	}
	s.advance(at)
	for _, r := range b.records {
		r.refresh = at.Add(100 * time.Millisecond)
	}
	if len(s.queries(b, req.iface, at.Add(100*time.Millisecond))) != 0 {
		t.Fatal("short duplicate")
	}
	other := *req.iface
	other.Name = "other"
	s.discovery = at
	if len(s.queries(b, &other, at)) != 1 {
		t.Fatal("different interface suppressed")
	}
}
func TestKnownAnswersUseActualPTRTTLAndInterface(t *testing.T) {
	b, req, now := scheduleFixture()
	q := []dns.Question{{Name: b.service, Qtype: dns.TypePTR, Qclass: dns.ClassINET}}
	ka := b.knownAnswers(req.iface.Name, q, now.Add(20*time.Second))
	if len(ka) != 1 || ka[0].Header().Ttl != 100 {
		t.Fatal(ka)
	}
	if len(b.knownAnswers("other", q, now)) != 0 || len(b.knownAnswers(req.iface.Name, q, now.Add(61*time.Second))) != 0 {
		t.Fatal("unsafe suppression")
	}
	for _, r := range b.records {
		r.legacy = true
	}
	if len(b.knownAnswers(req.iface.Name, q, now)) != 0 {
		t.Fatal("legacy known answers")
	}
}
func TestIndependentMetadataExpiry(t *testing.T) {
	b, req, now := scheduleFixture()
	for _, rr := range req.msg.Answer {
		if rr.Header().Rrtype == dns.TypeTXT {
			rr.Header().Ttl = 1
			rr.(*dns.TXT).Txt = []string{"v=1"}
		}
	}
	b.update(req, now)
	b.expire(now.Add(2 * time.Second))
	services := b.snapshot(now.Add(2 * time.Second)).Services()
	if len(services) != 1 || services[0].Port != 1234 || len(services[0].IPs) != 1 || len(services[0].Text) != 0 {
		t.Fatalf("%+v", services)
	}
}
func TestBrowseFlushGraceAndRescue(t *testing.T) {
	b, req, now := scheduleFixture()
	addr := forkAddress("192.0.2.2", 120, true)
	b.update(&Request{iface: req.iface, msg: &dns.Msg{Answer: []dns.RR{addr}}}, now.Add(2*time.Second))
	if len(b.snapshot(now.Add(2 * time.Second)).Services()[0].IPs) != 2 {
		t.Fatal("flush missing grace")
	}
	b.expire(now.Add(3 * time.Second))
	if len(b.snapshot(now.Add(3 * time.Second)).Services()[0].IPs) != 1 {
		t.Fatal("flush failed")
	}
	goodbye := dns.Copy(addr)
	goodbye.Header().Ttl = 0
	b.update(&Request{iface: req.iface, msg: &dns.Msg{Answer: []dns.RR{goodbye}}}, now.Add(4*time.Second))
	b.update(&Request{iface: req.iface, msg: &dns.Msg{Answer: []dns.RR{addr}}}, now.Add(4500*time.Millisecond))
	b.expire(now.Add(6 * time.Second))
	if len(b.snapshot(now.Add(6 * time.Second)).Services()[0].IPs) != 1 {
		t.Fatal("rescue failed")
	}
}
func TestDefaultLegacyDisabledAndIntervalValidation(t *testing.T) {
	_, _, now := scheduleFixture()
	s := newBrowseSchedule(now, BrowseOptions{Continuous: true})
	if !s.legacy.IsZero() {
		t.Fatal("default enabled")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, d := range []time.Duration{-1, time.Second} {
		if err := LookupTypeWithOptions(ctx, "_scm._tcp.local.", nil, nil, BrowseOptions{LegacyInterval: d}); err == nil {
			t.Fatal("invalid interval")
		}
	}
}
func TestAddressBeforeMetadataAndNoUnrelatedRefresh(t *testing.T) {
	_, req, now := scheduleFixture()
	b := newBrowseRecords("_scm._tcp.local.")
	b.update(&Request{iface: req.iface, msg: &dns.Msg{Answer: req.msg.Answer[3:]}}, now)
	s := newBrowseSchedule(now, BrowseOptions{Continuous: true})
	s.discovery = time.Time{}
	if len(s.queries(b, req.iface, now.Add(99*time.Second))) != 0 {
		t.Fatal("unreferenced address refreshed")
	}
	b.update(&Request{iface: req.iface, msg: &dns.Msg{Answer: req.msg.Answer[:3]}}, now)
	if len(b.snapshot(now).Services()[0].IPs) != 1 {
		t.Fatal("early address lost")
	}
}
func TestDuplicateReplyDoesNotRebuildSnapshot(t *testing.T) {
	b, req, now := scheduleFixture()
	if b.update(req, now.Add(time.Second)) {
		t.Fatal("unchanged reply caused snapshot rebuild")
	}
	for _, r := range b.records {
		if !r.received.Equal(now.Add(time.Second)) {
			t.Fatal("TTL not renewed")
		}
	}
}

func TestNormalGoodbyeDoesNotResurrectLegacy(t *testing.T) {
	b, req, now := scheduleFixture()
	legacy := &Request{iface: req.iface, msg: req.msg.Copy(), legacy: true}
	b.update(legacy, now)
	goodbye := req.msg.Copy()
	for _, rr := range goodbye.Answer {
		rr.Header().Ttl = 0
	}
	b.update(&Request{iface: req.iface, msg: goodbye}, now.Add(time.Second))
	b.expire(now.Add(2 * time.Second))
	if len(b.snapshot(now.Add(2*time.Second)).Services()) != 0 {
		t.Fatal("legacy resurrected a withdrawn service")
	}
}
func TestLegacyMetadataUpdateReplacesPreviousObservation(t *testing.T) {
	_, req, now := scheduleFixture()
	req.legacy = true
	b := newBrowseRecords("_scm._tcp.local.")
	b.update(req, now)
	txt := dns.Copy(req.msg.Answer[2]).(*dns.TXT)
	txt.Txt = []string{"v=new"}
	b.update(&Request{iface: req.iface, legacy: true, msg: &dns.Msg{Answer: []dns.RR{txt}}}, now.Add(time.Second))
	if got := b.snapshot(now.Add(time.Second)).Services()[0].Text["v"]; got != "new" {
		t.Fatal(got)
	}
	count := 0
	for _, r := range b.records {
		if _, ok := r.rr.(*dns.TXT); ok {
			count++
		}
	}
	if count != 1 {
		t.Fatal("old unique observation retained")
	}
}
func TestUnavailableInterfaceDoesNotSpinRefreshTimer(t *testing.T) {
	b, _, now := scheduleFixture()
	s := newBrowseSchedule(now, BrowseOptions{Continuous: true})
	s.discovery = time.Time{}
	s.setInterfaces(nil)
	if got := s.next(b, now.Add(100*time.Second)); !got.Equal(now.Add(120 * time.Second)) {
		t.Fatal(got)
	}
}
func TestNearbyRenewalsBatchWithoutEarlyRefresh(t *testing.T) {
	b, req, now := scheduleFixture()
	s := newBrowseSchedule(now, BrowseOptions{Continuous: true})
	s.discovery = time.Time{}
	i := 0
	for _, r := range b.records {
		r.refresh = now.Add(97*time.Second + time.Duration(i)*time.Millisecond)
		i++
	}
	if batches := s.queries(b, req.iface, now.Add(97*time.Second)); len(batches) != 1 || len(batches[0].msg.Question) != 4 {
		t.Fatal("nearby queries not combined")
	}
}

func TestSharedPTRKeepsLegacyOnlyInstances(t *testing.T) {
	for _, legacyFirst := range []bool{false, true} {
		b, normal, now := scheduleFixture()
		srv := newService("LegacyOnly._scm._tcp.local.")
		srv.SetHostname("legacy-only.local.")
		srv.Port = 4567
		addr := forkAddress("192.0.2.2", 10, false)
		addr.Header().Name = srv.Hostname()
		legacy := &Request{iface: normal.iface, legacy: true, msg: &dns.Msg{MsgHdr: dns.MsgHdr{Response: true}, Answer: []dns.RR{PTR(*srv), SRV(*srv), TXT(*srv), addr}}}
		if legacyFirst {
			b = newBrowseRecords(b.service)
			b.update(legacy, now)
			b.update(normal, now)
		} else {
			b.update(legacy, now)
		}
		services := b.snapshot(now).Services()
		if len(services) != 2 {
			t.Fatalf("legacyFirst=%v: shared PTR member hidden: %+v", legacyFirst, services)
		}
		// The identical normal instance observed via legacy must not duplicate it.
		b.update(&Request{iface: normal.iface, legacy: true, msg: normal.msg.Copy()}, now)
		if len(b.snapshot(now).Services()) != 2 {
			t.Fatal("identical PTR not deduplicated")
		}
		b.expire(now.Add(11 * time.Second))
		services = b.snapshot(now.Add(11 * time.Second)).Services()
		if len(services) != 1 || services[0].Name != "Peer" {
			t.Fatal("source expiry affected another PTR member")
		}
	}
}

func TestUniqueMetadataRescueUpdatesSnapshot(t *testing.T) {
	for _, typ := range []uint16{dns.TypeTXT, dns.TypeSRV} {
		t.Run(dns.TypeToString[typ], func(t *testing.T) {
			b, req, now := scheduleFixture()
			var original dns.RR
			for _, rr := range req.msg.Answer {
				if rr.Header().Rrtype == typ {
					original = dns.Copy(rr)
				}
			}
			original.Header().Class |= 0x8000
			replacement := dns.Copy(original)
			switch rr := replacement.(type) {
			case *dns.TXT:
				rr.Txt = []string{"version=new"}
			case *dns.SRV:
				rr.Port = 5678
			}
			send := func(rr dns.RR, at time.Time) bool {
				return b.update(&Request{iface: req.iface, msg: &dns.Msg{MsgHdr: dns.MsgHdr{Response: true}, Answer: []dns.RR{rr}}}, at)
			}
			if !send(replacement, now.Add(2*time.Second)) {
				t.Fatal("new value not reported")
			}
			published := b.snapshot(now.Add(2 * time.Second))
			if send(original, now.Add(2200*time.Millisecond)) {
				published = b.snapshot(now.Add(2200 * time.Millisecond))
			} else {
				t.Fatal("existing value became newest without invalidating snapshot")
			}
			service := published.Services()[0]
			if typ == dns.TypeTXT && len(service.Text) != 0 {
				t.Fatal("stale TXT remained")
			}
			if typ == dns.TypeSRV && service.Port != 1234 {
				t.Fatal("stale SRV port remained")
			}
			// Once the competing value ages out, unchanged answers remain cheap.
			b.expire(now.Add(123 * time.Second))
		})
	}
}
