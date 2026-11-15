package dnssd

import (
	"fmt"
	"math/rand"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Each wire record keeps its own lifetime and transport provenance.
// Legacy observations never participate in normal mDNS renewal/known answers.
type browseRecord struct {
	rr                         dns.RR
	iface                      net.Interface
	legacy                     bool
	received, expires, refresh time.Time
	stage                      int
}
type browseRecords struct {
	service string
	records map[string]*browseRecord
}

func newBrowseRecords(service string) *browseRecords {
	return &browseRecords{strings.ToLower(service), make(map[string]*browseRecord)}
}
func rrSet(rr dns.RR, iface string) string {
	h := rr.Header()
	return fmt.Sprintf("%s/%s/%d/%d", iface, strings.ToLower(h.Name), h.Rrtype, h.Class&0x7fff)
}
func rrIdentity(rr dns.RR, iface string, legacy bool) string {
	c := dns.Copy(rr)
	c.Header().Name = strings.ToLower(c.Header().Name)
	c.Header().Class &= 0x7fff
	c.Header().Ttl = 0
	switch r := c.(type) {
	case *dns.PTR:
		r.Ptr = strings.ToLower(r.Ptr)
	case *dns.SRV:
		r.Target = strings.ToLower(r.Target)
	}
	return fmt.Sprintf("%s/%t/%s", iface, legacy, c.String())
}
func (r *browseRecord) schedule() {
	if r.legacy || r.stage >= 4 {
		r.refresh = time.Time{}
		return
	}
	ttl := time.Duration(r.rr.Header().Ttl) * time.Second
	r.refresh = r.received.Add(time.Duration(float64(ttl) * (0.80 + float64(r.stage)*0.05 + rand.Float64()*0.02)))
}
func (b *browseRecords) update(req *Request, now time.Time) bool {
	if req == nil || req.msg == nil || req.iface == nil {
		return false
	}
	// Real queries have questions; do not mistake their known answers for replies.
	if !req.msg.Response && len(req.msg.Question) != 0 {
		return false
	}
	if req.msg.Truncated || req.msg.Rcode != dns.RcodeSuccess {
		return false
	}
	incoming := append(append([]dns.RR{}, req.msg.Answer...), req.msg.Extra...)
	accepted := map[string]dns.RR{}
	flush := map[string]bool{}
	for _, rr := range incoming {
		h := rr.Header()
		if h.Class&0x7fff != dns.ClassINET {
			continue
		}
		name := strings.ToLower(h.Name)
		relevant := false
		switch r := rr.(type) {
		case *dns.PTR:
			relevant = name == b.service && strings.HasSuffix(strings.ToLower(r.Ptr), "."+b.service)
		case *dns.SRV, *dns.TXT:
			relevant = strings.HasSuffix(name, "."+b.service)
		case *dns.A, *dns.AAAA:
			relevant = true // Retain addresses that arrive before their SRV packet.
		}
		if !relevant {
			continue
		}
		rr = dns.Copy(rr)
		if req.legacy {
			rr.Header().Class &= 0x7fff
			if rr.Header().Ttl > 10 {
				rr.Header().Ttl = 10
			}
		}
		key := rrIdentity(rr, req.iface.Name, req.legacy)
		accepted[key] = rr
		if !req.legacy && h.Class&0x8000 != 0 && h.Ttl > 0 {
			flush[rrSet(rr, req.iface.Name)] = true
		}
	}
	changed := b.expire(now)
	for _, old := range b.records {
		if req.legacy != old.legacy && req.legacy {
			continue
		}
		if flush[rrSet(old.rr, old.iface.Name)] && now.Sub(old.received) >= time.Second {
			if _, present := accepted[rrIdentity(old.rr, old.iface.Name, req.legacy)]; !present && old.expires.After(now.Add(time.Second)) {
				old.expires = now.Add(time.Second)
				old.refresh = time.Time{}
				changed = true
			}
		}
	}
	for key, rr := range accepted {
		if rr.Header().Ttl == 0 {
			keys := []string{key}
			if !req.legacy {
				keys = append(keys, rrIdentity(rr, req.iface.Name, true))
			}
			for _, k := range keys {
				if old := b.records[k]; old != nil && old.expires.After(now.Add(time.Second)) {
					old.expires = now.Add(time.Second)
					old.refresh = time.Time{}
					changed = true
				}
			}
			continue
		}
		// Legacy has no cache-flush bit, but a new unique metadata answer replaces
		// the previous observation rather than resurrecting it after expiry.
		if req.legacy && (rr.Header().Rrtype == dns.TypeSRV || rr.Header().Rrtype == dns.TypeTXT) {
			for k, old := range b.records {
				if k != key && old.legacy && rrSet(old.rr, old.iface.Name) == rrSet(rr, req.iface.Name) {
					delete(b.records, k)
					changed = true
				}
			}
		}

		r := &browseRecord{rr: rr, iface: *req.iface, legacy: req.legacy, received: now, expires: now.Add(time.Duration(rr.Header().Ttl) * time.Second)}
		r.schedule()
		if old := b.records[key]; old == nil {
			changed = true
		} else if rr.Header().Rrtype == dns.TypeSRV || rr.Header().Rrtype == dns.TypeTXT {
			// During flush grace multiple unique values may coexist. Refreshing an
			// existing identity can make it the newest value, changing the public view.
			for otherKey, other := range b.records {
				if otherKey != key && other.legacy == req.legacy &&
					rrSet(other.rr, other.iface.Name) == rrSet(rr, req.iface.Name) &&
					now.Before(other.expires) && !other.received.Before(old.received) {
					changed = true
					break
				}
			}
		}
		b.records[key] = r
	}
	return changed
}
func (b *browseRecords) expire(now time.Time) bool {
	changed := false
	for key, r := range b.records {
		if !now.Before(r.expires) {
			delete(b.records, key)
			changed = true
		}
	}
	return changed
}

// Shared PTR members name different service instances. A normal observation
// supersedes only the identical legacy member, not the entire browse answer set.
func normalPreferenceKey(r *browseRecord) string {
	if r.rr.Header().Rrtype == dns.TypePTR {
		return rrIdentity(r.rr, r.iface.Name, false)
	}
	return rrSet(r.rr, r.iface.Name)
}

// Normal unique RRsets and identical shared members take precedence over legacy.
// Expiring one source never removes the other source's still-valid records.
func (b *browseRecords) selected(now time.Time) []*browseRecord {
	normal := map[string]bool{}
	newest := map[string]*browseRecord{}
	for _, r := range b.records {
		if !r.legacy && now.Before(r.expires) {
			normal[normalPreferenceKey(r)] = true
		}
	}
	for _, r := range b.records {
		if !now.Before(r.expires) || (r.legacy && normal[normalPreferenceKey(r)]) {
			continue
		}
		switch r.rr.(type) {
		case *dns.SRV, *dns.TXT:
			key := rrSet(r.rr, r.iface.Name)
			if prev := newest[key]; prev == nil || r.received.After(prev.received) || (r.received.Equal(prev.received) && rrIdentity(r.rr, r.iface.Name, r.legacy) < rrIdentity(prev.rr, prev.iface.Name, prev.legacy)) {
				newest[key] = r
			}
		}
	}
	var result []*browseRecord
	for _, r := range b.records {
		if chosen := newest[rrSet(r.rr, r.iface.Name)]; chosen != nil && chosen != r {
			continue
		}
		if now.Before(r.expires) && (!r.legacy || !normal[normalPreferenceKey(r)]) {
			result = append(result, r)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return rrIdentity(result[i].rr, result[i].iface.Name, result[i].legacy) < rrIdentity(result[j].rr, result[j].iface.Name, result[j].legacy)
	})
	return result
}

// Build the dependency graph once per scheduling pass, not once per record.
func (b *browseRecords) active(now time.Time) map[*browseRecord]bool {
	instances := map[string]bool{}
	hosts := map[string]bool{}
	for _, r := range b.records {
		if p, ok := r.rr.(*dns.PTR); ok && !r.legacy && now.Before(r.expires) {
			instances[r.iface.Name+"/"+strings.ToLower(p.Ptr)] = true
		}
	}
	for _, r := range b.records {
		if srv, ok := r.rr.(*dns.SRV); ok && !r.legacy && now.Before(r.expires) && instances[r.iface.Name+"/"+strings.ToLower(srv.Hdr.Name)] {
			hosts[r.iface.Name+"/"+strings.ToLower(srv.Target)] = true
		}
	}
	result := map[*browseRecord]bool{}
	for _, r := range b.records {
		if r.legacy || !now.Before(r.expires) {
			continue
		}
		key := r.iface.Name + "/" + strings.ToLower(r.rr.Header().Name)
		switch r.rr.(type) {
		case *dns.PTR:
			result[r] = true
		case *dns.SRV, *dns.TXT:
			result[r] = instances[key]
		case *dns.A, *dns.AAAA:
			result[r] = hosts[key]
		}
	}
	return result
}
func (b *browseRecords) snapshot(now time.Time) *Cache {
	result := NewCache()
	selected := b.selected(now)
	metadata := map[string][]*browseRecord{}
	addresses := map[string][]*browseRecord{}
	for _, r := range selected {
		key := r.iface.Name + "/" + strings.ToLower(r.rr.Header().Name)
		switch r.rr.(type) {
		case *dns.SRV, *dns.TXT:
			metadata[key] = append(metadata[key], r)
		case *dns.A, *dns.AAAA:
			addresses[key] = append(addresses[key], r)
		}
	}
	for _, r := range selected {
		ptr, ok := r.rr.(*dns.PTR)
		if !ok {
			continue
		}
		key := r.iface.Name + "/" + strings.ToLower(ptr.Ptr)
		srv := newService(ptr.Ptr)
		complete := false
		for _, m := range metadata[key] {
			switch rr := m.rr.(type) {
			case *dns.SRV:
				srv.SetHostname(rr.Target)
				srv.Port = int(rr.Port)
				complete = true
			case *dns.TXT:
				srv.Text = map[string]string{}
				for _, t := range rr.Txt {
					kv := strings.SplitN(t, "=", 2)
					if len(kv) == 2 {
						srv.Text[kv[0]] = kv[1]
					}
				}
			}
		}
		if !complete {
			continue
		}
		for _, addr := range addresses[r.iface.Name+"/"+strings.ToLower(srv.Hostname())] {
			switch rr := addr.rr.(type) {
			case *dns.A:
				srv.addIP(rr.A, &r.iface)
			case *dns.AAAA:
				srv.addIP(rr.AAAA, &r.iface)
			}
		}
		srv.expiration = r.expires
		srv.TTL = time.Duration(ptr.Hdr.Ttl) * time.Second
		result.services[key] = srv
	}
	return result
}
func (b *browseRecords) knownAnswers(iface string, questions []dns.Question, now time.Time) []dns.RR {
	var answers []dns.RR
	for _, r := range b.records {
		if r.legacy || r.iface.Name != iface || r.rr.Header().Rrtype != dns.TypePTR {
			continue
		}
		left := r.expires.Sub(now)
		if left <= time.Duration(r.rr.Header().Ttl)*time.Second/2 {
			continue
		}
		for _, q := range questions {
			if q.Qtype == dns.TypePTR && strings.EqualFold(q.Name, r.rr.Header().Name) {
				rr := dns.Copy(r.rr)
				rr.Header().Class &= 0x7fff
				rr.Header().Ttl = uint32(left / time.Second)
				answers = append(answers, rr)
				break
			}
		}
	}
	return answers
}

type browseBatch struct {
	msg    *dns.Msg
	legacy bool
}
type browseSchedule struct {
	available         map[string]bool
	options           BrowseOptions
	discovery, legacy time.Time
	interval          time.Duration
	last              map[string]time.Time
}

func (s *browseSchedule) setInterfaces(ifaces []*net.Interface) {
	s.available = map[string]bool{}
	for _, iface := range ifaces {
		s.available[iface.Name] = true
	}
}
func refreshDue(r *browseRecord, now time.Time) bool {
	// Batch nearby deadlines, without pulling any retry before its TTL fraction.
	floor := r.received.Add(time.Duration(float64(time.Duration(r.rr.Header().Ttl)*time.Second) * (0.80 + float64(r.stage)*0.05)))
	return !r.refresh.IsZero() && !now.Before(floor) && !r.refresh.After(now.Add(20*time.Millisecond))
}
func newBrowseSchedule(now time.Time, options BrowseOptions) *browseSchedule {
	if options.LegacyInterval == 0 {
		options.LegacyInterval = 5 * time.Minute
	}
	s := &browseSchedule{options: options, interval: time.Second, last: make(map[string]time.Time)}
	s.restart(now)
	return s
}
func (s *browseSchedule) restart(now time.Time) {
	s.interval = time.Second
	s.discovery = now.Add(time.Duration(20+rand.Intn(100)) * time.Millisecond)
	if s.options.LegacyUnicast {
		s.legacy = s.discovery
	}
}
func earlier(a, b time.Time) time.Time {
	if b.IsZero() {
		return a
	}
	if a.IsZero() || b.Before(a) {
		return b
	}
	return a
}
func due(t, now time.Time) bool { return !t.IsZero() && !t.After(now) }
func (s *browseSchedule) next(b *browseRecords, now time.Time) time.Time {
	active := b.active(now)
	next := earlier(s.discovery, s.legacy)
	for _, r := range b.records {
		next = earlier(next, r.expires)
		if s.options.Continuous && !r.legacy && active[r] && (s.available == nil || s.available[r.iface.Name]) {
			next = earlier(next, r.refresh)
		}
	}
	return next
}
func questionKey(q dns.Question) string {
	return fmt.Sprintf("%s/%d/%d", strings.ToLower(q.Name), q.Qtype, q.Qclass&0x7fff)
}
func (s *browseSchedule) queries(b *browseRecords, iface *net.Interface, now time.Time) []browseBatch {
	active := b.active(now)
	questions := map[string]dns.Question{}
	ptr := dns.Question{Name: b.service, Qtype: dns.TypePTR, Qclass: dns.ClassINET}
	if due(s.discovery, now) {
		questions[questionKey(ptr)] = ptr
	}
	if s.options.Continuous {
		for _, r := range b.records {
			if r.legacy || r.iface.Name != iface.Name || !now.Before(r.expires) || !active[r] || !refreshDue(r, now) {
				continue
			}
			q := dns.Question{Name: r.rr.Header().Name, Qtype: r.rr.Header().Rrtype, Qclass: dns.ClassINET}
			questions[questionKey(q)] = q
		}
	}
	var qs []dns.Question
	for key, q := range questions {
		k := iface.Name + "/" + key
		if last := s.last[k]; !last.IsZero() && now.Sub(last) < time.Second {
			for _, r := range b.records {
				if !r.legacy && r.iface.Name == iface.Name && questionKey(dns.Question{Name: r.rr.Header().Name, Qtype: r.rr.Header().Rrtype, Qclass: dns.ClassINET}) == key && refreshDue(r, now) {
					r.refresh = last.Add(time.Second)
				}
			}
			continue
		}
		s.last[k] = now
		qs = append(qs, q)
		for _, r := range b.records {
			if !r.legacy && r.iface.Name == iface.Name && questionKey(dns.Question{Name: r.rr.Header().Name, Qtype: r.rr.Header().Rrtype, Qclass: dns.ClassINET}) == key && refreshDue(r, now) {
				r.stage++
				r.schedule()
			}
		}
	}
	sort.Slice(qs, func(i, j int) bool { return questionKey(qs[i]) < questionKey(qs[j]) })
	var result []browseBatch
	// Bound packet size; multiple due questions are batched rather than separately sent.
	for len(qs) > 0 {
		n := len(qs)
		if n > 8 {
			n = 8
		}
		for n > 1 && (&dns.Msg{Question: qs[:n]}).Len() > 1400 {
			n--
		}
		group := qs[:n]
		qs = qs[n:]
		m := &dns.Msg{Question: group, Answer: b.knownAnswers(iface.Name, group, now)}
		// Never send an oversized known-answer list without the multipacket protocol.
		// Drop answers if necessary: extra responses are safer than false suppression.
		for m.Len() > 1400 && len(m.Answer) > 0 {
			m.Answer = m.Answer[:len(m.Answer)-1]
		}
		result = append(result, browseBatch{msg: m})
	}
	// Legacy cannot be suppressed by a normal query: it has a different reply port.
	if due(s.legacy, now) {
		result = append(result, browseBatch{msg: &dns.Msg{Question: []dns.Question{ptr}}, legacy: true})
	}
	return result
}
func (s *browseSchedule) advance(now time.Time) {
	if due(s.discovery, now) {
		s.discovery = time.Time{}
		if s.options.Continuous {
			s.discovery = now.Add(s.interval)
			s.interval *= 2
			if s.interval > time.Hour {
				s.interval = time.Hour
			}
		}
	}
	if due(s.legacy, now) {
		s.legacy = time.Time{}
		if s.options.Continuous {
			s.legacy = now.Add(time.Duration(float64(s.options.LegacyInterval) * (0.9 + rand.Float64()*0.2)))
		}
	}
	for key, t := range s.last {
		if now.Sub(t) > time.Hour {
			delete(s.last, key)
		}
	}
}
