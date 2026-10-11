package gvisor

// The catcher behind NetworkGateway, the platform-independent part: DNS
// answered with addresses standing for names, the name a connection was made
// for, and the hand-off to the gateway. netns_linux.go catches the
// connections.

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// netnsArg runs agentbox's binary as the namespace helper (netns_linux.go).
const netnsArg = "__agentbox-netns"

// fakeNet is where names get their stand-in addresses (RFC 2544's benchmark
// range: never a real destination).
var fakeNet = netip.MustParsePrefix("198.18.0.0/15")

// fakeDNS maps each name asked for to an address in fakeNet and back.
// Addresses are reused oldest first once the range is spent.
type fakeDNS struct {
	mu     sync.Mutex
	next   uint32
	byName map[string]netip.Addr
	byAddr map[netip.Addr]string
}

func newFakeDNS() *fakeDNS {
	return &fakeDNS{byName: map[string]netip.Addr{}, byAddr: map[netip.Addr]string{}}
}

func (f *fakeDNS) addr(name string) netip.Addr {
	f.mu.Lock()
	defer f.mu.Unlock()
	if a, ok := f.byName[name]; ok {
		return a
	}
	size := uint32(1) << (32 - fakeNet.Bits())
	f.next++
	if f.next >= size-1 { // skip the network and broadcast addresses
		f.next = 1
	}
	b := fakeNet.Addr().As4()
	binary.BigEndian.PutUint32(b[:], binary.BigEndian.Uint32(b[:])+f.next)
	a := netip.AddrFrom4(b)
	if old, ok := f.byAddr[a]; ok {
		delete(f.byName, old)
	}
	f.byName[name], f.byAddr[a] = a, name
	return a
}

func (f *fakeDNS) name(a netip.Addr) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n, ok := f.byAddr[a]
	return n, ok
}

// answer is the reply to one DNS query (nil: drop it). An A query gets the
// name's stand-in address; any other type an empty answer, so programs fall
// back to IPv4; a malformed name NXDOMAIN.
func (f *fakeDNS) answer(q []byte) []byte {
	if len(q) < 12 || q[2]&0x80 != 0 || binary.BigEndian.Uint16(q[4:6]) != 1 {
		return nil
	}
	p := 12
	var labels []string
	for {
		if p >= len(q) {
			return nil
		}
		l := int(q[p])
		p++
		if l == 0 {
			break
		}
		if l > 63 || p+l > len(q) {
			return nil
		}
		labels = append(labels, string(q[p:p+l]))
		p += l
	}
	if p+4 > len(q) {
		return nil
	}
	qtype, qclass := binary.BigEndian.Uint16(q[p:]), binary.BigEndian.Uint16(q[p+2:])
	question := q[12 : p+4]
	name := strings.ToLower(strings.Join(labels, "."))

	r := make([]byte, 12, 12+len(question)+16)
	copy(r, q[:2])
	flags := uint16(0x8080) | uint16(q[2]&0x01)<<8 // QR, RA, the query's RD
	ancount := uint16(0)
	var rr []byte
	switch {
	case q[2]&0x78 != 0: // not a standard query
		flags |= 4 // NOTIMP
	case !validName(name):
		flags |= 3 // NXDOMAIN
	case qtype == 1 && qclass == 1:
		a := f.addr(name).As4()
		rr = append([]byte{0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4}, a[:]...)
		ancount = 1
	}
	binary.BigEndian.PutUint16(r[2:], flags)
	binary.BigEndian.PutUint16(r[4:], 1)
	binary.BigEndian.PutUint16(r[6:], ancount)
	return append(append(r, question...), rr...)
}

// validName accepts host names safe to hand on: letters, digits, '-', '_'
// in dot-separated labels.
func validName(n string) bool {
	if n == "" || len(n) > 253 {
		return false
	}
	for _, l := range strings.Split(n, ".") {
		if l == "" || len(l) > 63 {
			return false
		}
		for _, c := range l {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}

// tlsServerName is the server name in a TLS ClientHello, or "".
func tlsServerName(b []byte) string {
	// record header (5), handshake type and length (4), version (2), random (32)
	if len(b) < 44 || b[0] != 0x16 || b[5] != 0x01 {
		return ""
	}
	p := 43
	u16 := func(i int) int { return int(b[i])<<8 | int(b[i+1]) }
	p += 1 + int(b[p]) // session id
	if p+2 > len(b) {
		return ""
	}
	p += 2 + u16(p) // cipher suites
	if p+1 > len(b) {
		return ""
	}
	p += 1 + int(b[p]) // compression methods
	if p+2 > len(b) {
		return ""
	}
	end := min(p+2+u16(p), len(b))
	p += 2
	for p+4 <= end {
		typ, l := u16(p), u16(p+2)
		p += 4
		// server_name: list length (2), name type (1), name length (2), name
		if typ == 0 && p+5 <= end && b[p+2] == 0 {
			if n := u16(p + 3); p+5+n <= end {
				if name := strings.ToLower(string(b[p+5 : p+5+n])); validName(name) {
					return name
				}
			}
			return ""
		}
		p += l
	}
	return ""
}

// httpHost is the host in a plain HTTP request's Host header, or "".
func httpHost(b []byte) string {
	head, _, _ := bytes.Cut(b, []byte("\r\n\r\n"))
	for _, line := range strings.Split(string(head), "\r\n")[1:] {
		k, v, ok := strings.Cut(line, ":")
		if !ok || !strings.EqualFold(strings.TrimSpace(k), "host") {
			continue
		}
		v = strings.ToLower(strings.TrimSpace(v))
		if h, _, err := net.SplitHostPort(v); err == nil {
			v = h
		}
		if validName(v) {
			return v
		}
		return ""
	}
	return ""
}

// peek reads what a client sends first, until done says it has enough, the
// client stops for wait, or max bytes. It is forwarded afterwards.
func peek(c net.Conn, wait time.Duration, max int, done func([]byte) bool) []byte {
	c.SetReadDeadline(time.Now().Add(wait))
	defer c.SetReadDeadline(time.Time{})
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	for len(buf) < max && !done(buf) {
		n, err := c.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil {
			break
		}
	}
	return buf
}

func tlsHelloDone(b []byte) bool { return len(b) >= 5 && len(b) >= 5+(int(b[3])<<8|int(b[4])) }
func httpHeadDone(b []byte) bool { return bytes.Contains(b, []byte("\r\n\r\n")) }

// target is the "host:port" a caught connection to dst goes to: the name its
// stand-in address stands for, else for HTTPS and HTTP the name the client
// sends first (head, forwarded later), else dst itself. ok is false for a
// connection to drop.
func (f *fakeDNS) target(c net.Conn, dst netip.AddrPort) (target string, head []byte, ok bool) {
	port := fmt.Sprint(dst.Port())
	if fakeNet.Contains(dst.Addr()) {
		n, ok := f.name(dst.Addr())
		return net.JoinHostPort(n, port), nil, ok
	}
	if dst.Addr().IsLoopback() || dst.Addr().IsUnspecified() {
		return "", nil, false // not caught: a connection straight to the catcher
	}
	name := ""
	switch dst.Port() {
	case 443:
		head = peek(c, 3*time.Second, 16<<10, tlsHelloDone)
		name = tlsServerName(head)
	case 80:
		head = peek(c, 3*time.Second, 16<<10, httpHeadDone)
		name = httpHost(head)
	}
	if name == "" {
		name = dst.Addr().String()
	}
	return net.JoinHostPort(name, port), head, true
}

// relay hands c to the gateway as "CONNECT target", then copies both ways.
// A refusal resets c.
func relay(c *net.TCPConn, gateway, target string, head []byte) {
	refuse := func() { c.SetLinger(0); c.Close() }
	g, err := net.DialTimeout("unix", gateway, 10*time.Second)
	if err != nil {
		refuse()
		return
	}
	defer g.Close()
	if _, err := fmt.Fprintf(g, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		refuse()
		return
	}
	br := bufio.NewReader(g)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil || resp.StatusCode != http.StatusOK {
		refuse()
		return
	}
	if _, err := g.Write(head); err != nil {
		refuse()
		return
	}
	go func() {
		io.Copy(g, c)
		g.(*net.UnixConn).CloseWrite()
	}()
	io.Copy(c, br)
	c.Close()
}
