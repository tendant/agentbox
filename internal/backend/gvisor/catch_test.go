package gvisor

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func dnsQuery(name string, qtype uint16) []byte {
	q := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, l := range strings.Split(name, ".") {
		q = append(q, byte(len(l)))
		q = append(q, l...)
	}
	q = append(q, 0, byte(qtype>>8), byte(qtype), 0, 1)
	return q
}

func TestFakeDNS(t *testing.T) {
	f := newFakeDNS()
	r := f.answer(dnsQuery("Example.COM", 1))
	if r == nil || r[0] != 0x12 || r[1] != 0x34 || r[3]&0x0f != 0 || binary.BigEndian.Uint16(r[6:]) != 1 {
		t.Fatalf("A answer % x", r)
	}
	a := netip.AddrFrom4([4]byte(r[len(r)-4:]))
	if !fakeNet.Contains(a) {
		t.Errorf("address %v outside %v", a, fakeNet)
	}
	if n, ok := f.name(a); !ok || n != "example.com" {
		t.Errorf("name for %v: %q %v", a, n, ok)
	}
	if again := f.answer(dnsQuery("example.com", 1)); netip.AddrFrom4([4]byte(again[len(again)-4:])) != a {
		t.Error("a name keeps its address")
	}
	if r := f.answer(dnsQuery("example.com", 28)); binary.BigEndian.Uint16(r[6:]) != 0 || r[3]&0x0f != 0 {
		t.Errorf("AAAA: want an empty answer, got % x", r)
	}
	if r := f.answer(dnsQuery("bad name.com", 1)); r[3]&0x0f != 3 {
		t.Errorf("bad name: want NXDOMAIN, got % x", r)
	}
	if f.answer([]byte{1, 2, 3}) != nil {
		t.Error("a short packet is dropped")
	}
	// The range wraps, forgetting the oldest names.
	f2 := newFakeDNS()
	first := f2.addr("first.test")
	for i := 0; i < 1<<17; i++ {
		f2.addr("n" + strconv.Itoa(i) + ".test")
	}
	if n, _ := f2.name(first); n == "first.test" {
		t.Error("the oldest name was not reused")
	}
}

// A real ClientHello, from crypto/tls.
func clientHello(t *testing.T, name string) []byte {
	c, s := net.Pipe()
	go tls.Client(c, &tls.Config{ServerName: name, InsecureSkipVerify: name == ""}).Handshake()
	b := peek(s, 2*time.Second, 16<<10, tlsHelloDone)
	c.Close()
	return b
}

func TestServerNames(t *testing.T) {
	if n := tlsServerName(clientHello(t, "api.example.com")); n != "api.example.com" {
		t.Errorf("SNI %q", n)
	}
	if n := tlsServerName(clientHello(t, "")); n != "" {
		t.Errorf("no SNI: %q", n)
	}
	for _, b := range [][]byte{nil, []byte("\x16\x03\x01\x00"), make([]byte, 60)} {
		if n := tlsServerName(b); n != "" {
			t.Errorf("garbage: %q", n)
		}
	}
	if n := httpHost([]byte("GET / HTTP/1.1\r\nUser-Agent: x\r\nhost: Example.org:8080\r\n\r\n")); n != "example.org" {
		t.Errorf("Host %q", n)
	}
	if n := httpHost([]byte("GET / HTTP/1.1\r\nHost: a b\r\n\r\n")); n != "" {
		t.Errorf("bad Host %q", n)
	}
}

// fakeGateway accepts CONNECTs on a Unix socket, records the targets,
// refuses "denied.test", answers an HTTP GET with "VIA target" and echoes
// anything else's first line.
func fakeGateway(t *testing.T) (string, chan string) {
	sock := filepath.Join(t.TempDir(), "gw.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	got := make(chan string, 16)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				br := bufio.NewReader(c)
				req, err := http.ReadRequest(br)
				if err != nil {
					return
				}
				got <- req.Host
				if strings.HasPrefix(req.Host, "denied.test") {
					io.WriteString(c, "HTTP/1.1 403 Forbidden\r\n\r\n")
					return
				}
				io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
				line, _ := br.ReadString('\n')
				if strings.HasPrefix(line, "GET ") {
					body := "VIA " + req.Host + "\n"
					io.WriteString(c, "HTTP/1.0 200 OK\r\nContent-Length: "+strconv.Itoa(len(body))+"\r\n\r\n"+body)
					return
				}
				io.WriteString(c, "ECHO "+line)
			}()
		}
	}()
	return sock, got
}

func TestRelay(t *testing.T) {
	sock, got := fakeGateway(t)
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	defer l.Close()
	go func() {
		for _, target := range []string{"example.com:443", "denied.test:443"} {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go relay(c.(*net.TCPConn), sock, target, []byte("HEAD "))
		}
	}()
	c, _ := net.Dial("tcp", l.Addr().String())
	io.WriteString(c, "hello\n")
	line, _ := bufio.NewReader(c).ReadString('\n')
	c.Close()
	if line != "ECHO HEAD hello\n" || <-got != "example.com:443" {
		t.Errorf("relay: %q", line)
	}
	// Refused: the client's connection is reset.
	c, _ = net.Dial("tcp", l.Addr().String())
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err := c.Read(make([]byte, 10))
	if err == nil || <-got != "denied.test:443" {
		t.Errorf("refused: %v", err)
	}
}

func TestTarget(t *testing.T) {
	f := newFakeDNS()
	a := f.addr("github.com")
	c, s := net.Pipe()
	defer c.Close()
	if tg, _, ok := f.target(s, netip.AddrPortFrom(a, 22)); !ok || tg != "github.com:22" {
		t.Errorf("stand-in address: %q %v", tg, ok)
	}
	if _, _, ok := f.target(s, netip.AddrPortFrom(netip.MustParseAddr("198.18.200.1"), 443)); ok {
		t.Error("an unknown stand-in address must be dropped")
	}
	if _, _, ok := f.target(s, netip.MustParseAddrPort("127.0.0.1:15001")); ok {
		t.Error("loopback must be dropped")
	}
	if tg, _, _ := f.target(s, netip.MustParseAddrPort("203.0.113.9:22")); tg != "203.0.113.9:22" {
		t.Errorf("literal address: %q", tg)
	}
	go io.WriteString(c, "GET / HTTP/1.1\r\nHost: example.net\r\n\r\n")
	if tg, head, _ := f.target(s, netip.MustParseAddrPort("203.0.113.9:80")); tg != "example.net:80" || len(head) == 0 {
		t.Errorf("HTTP Host: %q %q", tg, head)
	}
}
