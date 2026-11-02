package egress

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// inspected is a gateway inspecting HTTPS to example.com (an httptest TLS
// server, HTTP/1.1 and HTTP/2), with what it reported.
type inspected struct {
	g        *Gateway
	in       *Inspector
	upstream *httptest.Server
	mu       sync.Mutex
	reqs     []RequestInfo
	skipped  []string
}

func inspectSetup(t *testing.T, mod func(*Config), handler http.Handler) *inspected {
	t.Helper()
	up := httptest.NewUnstartedServer(handler)
	up.EnableHTTP2 = true
	up.StartTLS()
	t.Cleanup(up.Close)
	in, err := NewInspector()
	if err != nil {
		t.Fatal(err)
	}
	x := &inspected{in: in, upstream: up}
	roots := x509.NewCertPool()
	roots.AddCert(up.Certificate())
	cfg := Config{
		Allow:   []string{"example.com", "other.example.com"},
		Resolve: func(context.Context, string) ([]netipAddr, error) { return []netipAddr{mustAddr("203.0.113.10")}, nil },
		Dial: func(ctx context.Context, n, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, n, up.Listener.Addr().String())
		},
		Inspect: in, UpstreamRoots: roots,
		OnRequest:    func(r RequestInfo) { x.mu.Lock(); x.reqs = append(x.reqs, r); x.mu.Unlock() },
		OnInspection: func(h, why string) { x.mu.Lock(); x.skipped = append(x.skipped, h+":"+why); x.mu.Unlock() },
	}
	if mod != nil {
		mod(&cfg)
	}
	g, err := Start(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { g.Close() })
	x.g = g
	return x
}

// client goes through the gateway, trusting roots.
func (x *inspected) client(roots *x509.CertPool, h2 bool) *http.Client {
	pu, _ := url.Parse("http://" + x.g.Addr())
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(pu),
		TLSClientConfig: &tls.Config{RootCAs: roots}, ForceAttemptHTTP2: h2}}
}

func (x *inspected) trusting() *x509.CertPool {
	p := x509.NewCertPool()
	p.AppendCertsFromPEM(x.in.CertPEM())
	return p
}

func (x *inspected) reported() ([]RequestInfo, []string) {
	// A request is reported when its handler returns, just after the
	// client has the response.
	time.Sleep(50 * time.Millisecond)
	x.mu.Lock()
	defer x.mu.Unlock()
	return append([]RequestInfo(nil), x.reqs...), append([]string(nil), x.skipped...)
}

func TestInspectReportsRequests(t *testing.T) {
	x := inspectSetup(t, nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("token") != "secret" {
			http.Error(w, "query lost", 400)
			return
		}
		b, _ := io.ReadAll(r.Body)
		w.WriteHeader(201)
		fmt.Fprintf(w, "got %d via %s", len(b), r.Proto)
	}))
	for _, h2 := range []bool{false, true} {
		resp, err := x.client(x.trusting(), h2).Post("https://example.com/repos/acme/web/issues?token=secret", "text/plain", strings.NewReader("hello"))
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		want := "HTTP/1.1"
		if h2 {
			want = "HTTP/2.0"
		}
		if resp.StatusCode != 201 || !strings.HasPrefix(string(b), "got 5 via ") || resp.Proto != want {
			t.Errorf("h2=%v: %d %q %s", h2, resp.StatusCode, b, resp.Proto)
		}
	}
	reqs, skipped := x.reported()
	if len(reqs) != 2 || len(skipped) != 0 {
		t.Fatalf("reported %+v, skipped %v", reqs, skipped)
	}
	for i, r := range reqs {
		if r.Host != "example.com" || r.Method != "POST" || r.Path != "/repos/acme/web/issues" || r.Status != 201 ||
			r.RequestBytes != 5 || r.ResponseBytes == 0 || r.Error != "" {
			t.Errorf("request %d: %+v", i, r)
		}
	}
	if reqs[1].Protocol != "HTTP/2.0" {
		t.Errorf("protocol %s", reqs[1].Protocol)
	}
}

// A client that does not trust the run's certificate fails that request;
// the host then passes through, uninspected, for the rest of the run.
func TestInspectRefusedThenPassThrough(t *testing.T) {
	x := inspectSetup(t, nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	upstreamOnly := x509.NewCertPool()
	upstreamOnly.AddCert(x.upstream.Certificate())
	c := x.client(upstreamOnly, false)
	if _, err := c.Get("https://example.com/a"); err == nil {
		t.Fatal("an untrusting client got through inspection")
	}
	resp, err := x.client(upstreamOnly, false).Get("https://example.com/b")
	if err != nil {
		t.Fatalf("after the refusal: %v", err)
	}
	resp.Body.Close()
	reqs, skipped := x.reported()
	if len(reqs) != 0 || len(skipped) != 1 || skipped[0] != "example.com:"+InspectClientRefused {
		t.Errorf("reported %+v, skipped %v", reqs, skipped)
	}
}

func TestInspectExcepted(t *testing.T) {
	x := inspectSetup(t, func(c *Config) { c.InspectExcept = []string{"example.com"} },
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	upstreamOnly := x509.NewCertPool()
	upstreamOnly.AddCert(x.upstream.Certificate())
	for i := 0; i < 2; i++ {
		resp, err := x.client(upstreamOnly, false).Get("https://example.com/x")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	reqs, skipped := x.reported()
	if len(reqs) != 0 || len(skipped) != 1 || skipped[0] != "example.com:"+InspectExcepted {
		t.Errorf("reported %+v, skipped %v", reqs, skipped)
	}
}

// A streamed response reaches the client as it is sent, not at its end.
func TestInspectStreams(t *testing.T) {
	release := make(chan struct{})
	x := inspectSetup(t, nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		<-release
		io.WriteString(w, "data: second\n\n")
	}))
	resp, err := x.client(x.trusting(), true).Get("https://example.com/events")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	line, err := bufio.NewReader(resp.Body).ReadString('\n')
	close(release)
	if err != nil || line != "data: first\n" {
		t.Errorf("first event %q %v", line, err)
	}
}

// An upgrade (WebSocket) is joined through and reported once it ends.
func TestInspectUpgrade(t *testing.T) {
	x := inspectSetup(t, nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, brw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		defer c.Close()
		io.WriteString(c, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		line, _ := brw.ReadString('\n')
		io.WriteString(c, "echo "+line)
	}))
	conn, err := net.Dial("tcp", x.g.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	br := bufio.NewReader(conn)
	if line, _ := br.ReadString('\n'); !strings.Contains(line, "200") {
		t.Fatalf("connect: %q", line)
	}
	br.ReadString('\n')
	tc := tls.Client(conn, &tls.Config{ServerName: "example.com", RootCAs: x.trusting(), NextProtos: []string{"http/1.1"}})
	fmt.Fprintf(tc, "GET /socket HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
	tr := bufio.NewReader(tc)
	resp, err := http.ReadResponse(tr, nil)
	if err != nil || resp.StatusCode != 101 {
		t.Fatalf("upgrade: %v %+v", err, resp)
	}
	io.WriteString(tc, "ping\n")
	if line, _ := tr.ReadString('\n'); line != "echo ping\n" {
		t.Errorf("echo %q", line)
	}
	tc.Close()
	reqs, _ := x.reported()
	if len(reqs) != 1 || reqs[0].Status != 101 || reqs[0].Path != "/socket" || reqs[0].ResponseBytes == 0 {
		t.Errorf("reported %+v", reqs)
	}
}

// Plain HTTP tunnelled through CONNECT (transparent egress hands port 80
// over that way) is read and reported too.
func TestInspectPlainTunnel(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(204)
	}))
	t.Cleanup(plain.Close)
	x := inspectSetup(t, func(c *Config) {
		c.Dial = func(ctx context.Context, n, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, n, plain.Listener.Addr().String())
		}
	}, http.NotFoundHandler())
	conn, err := net.Dial("tcp", x.g.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "CONNECT example.com:80 HTTP/1.1\r\nHost: example.com:80\r\n\r\n")
	br := bufio.NewReader(conn)
	if resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect}); err != nil || resp.StatusCode != 200 {
		t.Fatalf("connect: %v", err)
	}
	fmt.Fprintf(conn, "DELETE /items/7?x=1 HTTP/1.1\r\nHost: example.com\r\n\r\n")
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != 204 {
		t.Fatalf("request: %v %+v", err, resp)
	}
	conn.Close()
	reqs, _ := x.reported()
	if len(reqs) != 1 || reqs[0].Method != "DELETE" || reqs[0].Path != "/items/7" || reqs[0].Status != 204 {
		t.Errorf("reported %+v", reqs)
	}
}
