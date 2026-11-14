package dnssd

import (
	"context"
	"io"
	"runtime"
	"strings"
	"time"

	"github.com/brutella/dnssd/log"
	"github.com/miekg/dns"
)

// LookupInstance resolves a service by its service instance name.
func LookupInstance(ctx context.Context, instance string) (Service, error) {
	var srv Service

	conn, err := newLookupConn(ctx, runtime.GOOS == "windows")
	if err != nil {
		return srv, err
	}

	defer conn.Close()
	return lookupInstance(ctx, instance, conn)
}

func lookupInstance(ctx context.Context, instance string, conn MDNSConn) (srv Service, err error) {
	pending := make(map[string]*instanceResolution)

	m := new(dns.Msg)

	srvQ := dns.Question{
		Name:   instance,
		Qtype:  dns.TypeSRV,
		Qclass: dns.ClassINET,
	}
	txtQ := dns.Question{
		Name:   instance,
		Qtype:  dns.TypeTXT,
		Qclass: dns.ClassINET,
	}
	setQuestionUnicast(&srvQ)
	setQuestionUnicast(&txtQ)

	m.Question = []dns.Question{srvQ, txtQ}

	readCtx, readCancel := context.WithCancel(ctx)
	defer readCancel()

	ch := conn.Read(readCtx)

	qs := make(chan *Query)
	go func() {
		for _, iface := range MulticastInterfaces() {
			iface := iface
			q := &Query{msg: m, iface: iface}
			select {
			case qs <- q:
			case <-readCtx.Done():
				return
			}
		}
	}()

	for {
		if ctx.Err() != nil {
			return srv, ctx.Err()
		}
		select {
		case q := <-qs:
			if err := conn.SendQuery(q); err != nil {
				log.Info.Println("dnssd:", err)
			}
		case req, ok := <-ch:
			if !ok {
				return srv, io.EOF
			}
			if req == nil || req.msg == nil {
				continue
			}
			// Never combine metadata from different links.
			key := req.IfaceName()
			r := pending[key]
			if r == nil {
				r = &instanceResolution{addresses: NewCache()}
				pending[key] = r
			}
			if result, complete := r.update(instance, req, time.Now()); complete {
				return result, nil
			}
		case <-ctx.Done():
			err = ctx.Err()
			return
		}
	}
}

// instanceResolution retains independently arriving SRV/TXT answers. A TXT
// answer may be empty; absence of a packet is not an empty answer.
type instanceResolution struct {
	addresses          *Cache
	srv                *dns.SRV
	txt                *dns.TXT
	srvUntil, txtUntil time.Time
}

func (r *instanceResolution) update(instance string, req *Request, now time.Time) (Service, bool) {
	m := req.msg
	if !m.Response || m.Opcode != dns.OpcodeQuery || m.Truncated ||
		(m.Rcode != dns.RcodeSuccess && m.Rcode != dns.RcodeNameError) {
		return Service{}, false
	}
	addressMsg := new(dns.Msg)
	positiveTXT := false
	var negativeTTL uint32
	for _, section := range [][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range section {
			h := rr.Header()
			if h.Class&0x7fff != dns.ClassINET {
				continue
			}
			if m.Rcode == dns.RcodeSuccess {
				switch rr.(type) {
				case *dns.A, *dns.AAAA:
					addressMsg.Answer = append(addressMsg.Answer, rr)
				}
			}
			if !strings.EqualFold(h.Name, instance) || m.Rcode != dns.RcodeSuccess {
				continue
			}
			switch v := rr.(type) {
			case *dns.SRV:
				r.srv = dns.Copy(v).(*dns.SRV)
				r.srvUntil = now.Add(time.Duration(h.Ttl) * time.Second)
			case *dns.TXT:
				positiveTXT = true
				r.txt = dns.Copy(v).(*dns.TXT)
				r.txtUntil = now.Add(time.Duration(h.Ttl) * time.Second)
			case *dns.NSEC:
				// mDNS NSEC denies types only for its owner name.
				hasTXT := false
				for _, typ := range v.TypeBitMap {
					hasTXT = hasTXT || typ == dns.TypeTXT
				}
				if !hasTXT && strings.EqualFold(v.NextDomain, instance) {
					negativeTTL = h.Ttl
				}
			}
		}
	}
	// The legacy transport has already matched transaction ID and question.
	// An explicit empty TXT reply is distinct from a lost or delayed reply.
	if len(m.Answer) == 0 && len(m.Question) == 1 {
		q := m.Question[0]
		if strings.EqualFold(q.Name, instance) && q.Qtype == dns.TypeTXT && q.Qclass == dns.ClassINET {
			negativeTTL = 10
		}
	}
	if !positiveTXT && negativeTTL > 0 && !now.Before(r.txtUntil) {
		r.txt = &dns.TXT{Hdr: dns.RR_Header{Name: instance, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: negativeTTL}}
		r.txtUntil = now.Add(time.Duration(negativeTTL) * time.Second)
	}
	r.addresses.now = func() time.Time { return now }
	r.addresses.UpdateFrom(&Request{msg: addressMsg, iface: req.iface})
	if r.srv == nil || r.txt == nil || !now.Before(r.srvUntil) || !now.Before(r.txtUntil) {
		return Service{}, false
	}
	// Only publish a service when both questions have completed. Canonicalize
	// the owner name for the cache, whose keys are case-sensitive.
	srv := dns.Copy(r.srv).(*dns.SRV)
	txt := dns.Copy(r.txt).(*dns.TXT)
	srv.Hdr.Name, txt.Hdr.Name = instance, instance
	srv.Hdr.Ttl = remainingResolutionTTL(r.srvUntil, now)
	txt.Hdr.Ttl = remainingResolutionTTL(r.txtUntil, now)
	r.addresses.UpdateFrom(&Request{msg: &dns.Msg{Answer: []dns.RR{srv, txt}}, iface: req.iface})
	service, ok := r.addresses.services[instance]
	if !ok {
		return Service{}, false
	}
	return *service.Copy(), true
}

func remainingResolutionTTL(until, now time.Time) uint32 {
	return uint32((until.Sub(now) + time.Second - 1) / time.Second)
}
