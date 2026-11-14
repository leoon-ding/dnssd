package dnssd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/brutella/dnssd/log"
	"github.com/miekg/dns"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const legacyWindow = 5 * time.Second

type legacyQuestion struct {
	question dns.Question
	expires  time.Time
}
type legacyEndpoint struct {
	conn        *net.UDPConn
	iface       net.Interface
	network     *net.IPNet
	destination *net.UDPAddr
	pending     map[uint16]legacyQuestion // protected by lookupConn.mu
}

// lookupConn adds independently owned reply ports to browsing only. Probing
// and announcements continue to use the standard multicast transport.
type lookupConn struct {
	MDNSConn
	ctx       context.Context
	cancel    context.CancelFunc
	out       chan *Request
	mu        sync.Mutex
	endpoints map[string]*legacyEndpoint
	closed    bool
	workers   sync.WaitGroup
}

func newLookupConn(ctx context.Context, legacy bool, ifaces ...string) (MDNSConn, error) {
	base, err := newMDNSConn(ifaces...)
	if err != nil {
		return nil, err
	}
	if !legacy {
		return base, nil
	}
	return addLegacyQueries(ctx, base), nil
}

func addLegacyQueries(ctx context.Context, base MDNSConn) *lookupConn {
	ctx, cancel := context.WithCancel(ctx)
	c := &lookupConn{MDNSConn: base, ctx: ctx, cancel: cancel, out: make(chan *Request), endpoints: make(map[string]*legacyEndpoint)}
	c.workers.Add(1)
	go func() {
		defer c.workers.Done()
		ch := base.Read(ctx)
		for {
			select {
			case req, ok := <-ch:
				if !ok {
					return
				}
				select {
				case c.out <- req:
				case <-ctx.Done():
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	return c
}
func (c *lookupConn) Read(context.Context) <-chan *Request { return c.out }
func (c *lookupConn) Close() {
	c.mu.Lock()
	if !c.closed {
		c.closed = true
		c.cancel()
		for _, e := range c.endpoints {
			e.conn.Close()
		}
		c.endpoints = map[string]*legacyEndpoint{}
		c.MDNSConn.Close()
	}
	c.mu.Unlock()
	c.workers.Wait()
}

func (c *lookupConn) SendQuery(q *Query) error {
	// Send a private copy: the multicast writer sanitizes its input.
	multicastErr := c.MDNSConn.SendQuery(&Query{msg: q.msg.Copy(), iface: q.iface})
	if q.iface == nil {
		return multicastErr
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.ctx.Err() != nil {
		return context.Canceled
	}
	// Drop sockets whose bound address/interface disappeared (including DHCP changes).
	for key, e := range c.endpoints {
		iface, err := net.InterfaceByIndex(e.iface.Index)
		alive := false
		if err == nil && iface.Name == e.iface.Name && iface.Flags&net.FlagUp != 0 {
			addrs, _ := iface.Addrs()
			alive = e.refreshNetwork(addrs)
		}
		if !alive {
			e.conn.Close()
			delete(c.endpoints, key)
		}
	}
	addrs, err := q.iface.Addrs()
	if err != nil {
		return errors.Join(multicastErr, err)
	}
	used := map[bool]bool{}
	var errs []error
	for _, a := range addrs {
		ip, network, err := net.ParseCIDR(a.String())
		if err != nil || ip.IsLoopback() || ip.IsUnspecified() {
			continue
		}
		v4 := ip.To4() != nil
		if used[v4] || (!v4 && !EnableIPv6LinkLocalMulticast) {
			continue
		}
		key := fmt.Sprintf("%d/%s/%s", q.iface.Index, q.iface.Name, ip)
		e := c.endpoints[key]
		if e == nil {
			network.IP = ip
			e, err = openLegacyEndpoint(q.iface, network)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			c.endpoints[key] = e
			c.workers.Add(1)
			go func() { defer c.workers.Done(); c.receiveLegacy(e) }()
		}
		used[v4] = true
		now := time.Now()
		for id, p := range e.pending {
			if !now.Before(p.expires) {
				delete(e.pending, id)
			}
		}
		for _, question := range q.msg.Question {
			if len(e.pending) >= 256 {
				errs = append(errs, errors.New("too many pending legacy queries"))
				break
			}
			question.Qclass &= 0x7fff
			id := dns.Id()
			for {
				if _, exists := e.pending[id]; !exists {
					break
				}
				id++
			}
			m := &dns.Msg{MsgHdr: dns.MsgHdr{Id: id}, Question: []dns.Question{question}}
			packet, err := m.Pack()
			if err != nil {
				errs = append(errs, err)
				continue
			}
			e.pending[id] = legacyQuestion{question, now.Add(legacyWindow)}
			e.conn.SetWriteDeadline(now.Add(time.Second))
			if _, err = e.conn.WriteToUDP(packet, e.destination); err != nil {
				delete(e.pending, id)
				errs = append(errs, err)
				e.conn.Close()
				delete(c.endpoints, key)
				break
			}
		}
	}
	if err := errors.Join(errs...); err != nil {
		log.Debug.Println("Legacy query:", err)
	}
	return errors.Join(append(errs, multicastErr)...)
}

func openLegacyEndpoint(iface *net.Interface, network *net.IPNet) (*legacyEndpoint, error) {
	addr := &net.UDPAddr{IP: network.IP}
	family := "udp4"
	destination := &net.UDPAddr{IP: IPv4LinkLocalMulticast, Port: 5353}
	if network.IP.To4() == nil {
		family = "udp6"
		addr.Zone = iface.Name
		destination = &net.UDPAddr{IP: IPv6LinkLocalMulticast, Port: 5353, Zone: iface.Name}
	}
	conn, err := net.ListenUDP(family, addr)
	if err != nil {
		return nil, err
	}
	if family == "udp4" {
		p := ipv4.NewPacketConn(conn)
		err = p.SetMulticastInterface(iface)
		if err == nil {
			err = p.SetMulticastTTL(255)
		}
	} else {
		p := ipv6.NewPacketConn(conn)
		err = p.SetMulticastInterface(iface)
		if err == nil {
			err = p.SetMulticastHopLimit(255)
		}
	}
	if err != nil {
		conn.Close()
		return nil, err
	}
	return &legacyEndpoint{conn: conn, iface: *iface, network: network, destination: destination, pending: make(map[uint16]legacyQuestion)}, nil
}

func (c *lookupConn) receiveLegacy(e *legacyEndpoint) {
	defer func() {
		e.conn.Close()
		c.mu.Lock()
		defer c.mu.Unlock()
		for key, current := range c.endpoints {
			if current == e {
				delete(c.endpoints, key)
			}
		}
	}()
	packet := make([]byte, 65536)
	for {
		n, from, err := e.conn.ReadFromUDP(packet)
		if err != nil {
			return
		}
		m := new(dns.Msg)
		if m.Unpack(packet[:n]) != nil {
			continue
		}
		c.mu.Lock()
		p, ok := e.pending[m.Id]
		valid := ok && validLegacyResponse(m, from, e, p, time.Now())
		c.mu.Unlock()
		if !valid {
			continue
		}
		// Some deployed responders use multicast TTLs/flush bits for legacy replies.
		// Bound their cache lifetime and never apply their flush bits to multicast RRsets.
		normalizeLegacyRecords(m)
		select {
		case c.out <- &Request{msg: m, from: from, iface: &e.iface}:
		case <-c.ctx.Done():
			return
		}
	}
}
func validLegacyResponse(m *dns.Msg, from *net.UDPAddr, e *legacyEndpoint, p legacyQuestion, now time.Time) bool {
	if !m.Response || shouldIgnore(m) || m.Truncated || !now.Before(p.expires) || from.Port != 5353 || len(m.Question) != 1 {
		return false
	}
	if !e.network.Contains(from.IP) && !(e.network.IP.To4() == nil && from.IP.IsLinkLocalUnicast()) {
		return false
	}
	q := m.Question[0]
	return strings.EqualFold(q.Name, p.question.Name) && q.Qtype == p.question.Qtype && q.Qclass == p.question.Qclass
}
func normalizeLegacyRecords(m *dns.Msg) {
	for _, section := range [][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range section {
			h := rr.Header()
			h.Class &= 0x7fff
			if h.Ttl > 10 {
				h.Ttl = 10
			}
		}
	}
}

// refreshNetwork updates the receive filter even if only the prefix changed.
// The caller holds lookupConn.mu, as does response validation.
func (e *legacyEndpoint) refreshNetwork(addrs []net.Addr) bool {
	for _, addr := range addrs {
		ip, network, err := net.ParseCIDR(addr.String())
		if err == nil && ip.Equal(e.network.IP) {
			network.IP = ip
			e.network = network
			return true
		}
	}
	return false
}
