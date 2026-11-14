package dnssd

import (
	"context"
	"runtime"

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
	var cache = NewCache()

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
		select {
		case q := <-qs:
			if err := conn.SendQuery(q); err != nil {
				log.Info.Println("dnssd:", err)
			}
		case req := <-ch:
			cache.UpdateFrom(req)
			if s, ok := cache.services[instance]; ok {
				srv = *s
				return
			}
		case <-ctx.Done():
			err = ctx.Err()
			return
		}
	}
}
