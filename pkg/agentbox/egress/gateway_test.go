package egress

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
)

type env struct {
	g        *Gateway
	resolved []string
	events   []string
	dialed   []string
	mu       sync.Mutex
}

func setup(t *testing.T, cfg Config, ips map[string]string) *env {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "upstream-ok") }))
	t.Cleanup(up.Close)
	e := &env{}
	cfg.Resolve = func(_ context.Context, h string) ([]netipAddr, error) {
		e.mu.Lock()
		e.resolved = append(e.resolved, h)
		e.mu.Unlock()
		ip, ok := ips[h]
		if !ok {
			return nil, fmt.Errorf("nxdomain")
		}
		return []netipAddr{mustAddr(ip)}, nil
	}
	cfg.Dial = func(ctx context.Context, n, addr string) (net.Conn, error) {
		e.mu.Lock()
		e.dialed = append(e.dialed, addr)
		e.mu.Unlock()
		return (&net.Dialer{}).DialContext(ctx, n, up.Listener.Addr().String())
	}
	cfg.OnEvent = func(k, h string) { e.mu.Lock(); e.events = append(e.events, k+":"+h); e.mu.Unlock() }
	g, err := Start(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { g.Close() })
	e.g = g
	return e
}

// connect issues CONNECT and returns the status line.
func connect(t *testing.T, e *env, target string) string {
	c, err := net.Dial("tcp", e.g.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	line, _ := bufio.NewReader(c).ReadString('\n')
	return strings.TrimSpace(line)
}

func httpGet(t *testing.T, e *env, rawurl string) (int, string) {
	pu, _ := url.Parse("http://" + e.g.Addr())
	cl := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu)}}
	resp, err := cl.Get(rawurl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestAllowedAndDenied(t *testing.T) {
	e := setup(t, Config{Allow: []string{"api.github.com", "*.pypi.org", "@vcs"}, Sets: map[string][]string{"@vcs": {"gitlab.com"}}},
		map[string]string{"api.github.com": "140.82.112.5", "files.pypi.org": "151.101.0.223", "gitlab.com": "172.65.251.78", "evil.com": "6.6.6.6"})
	for _, ok := range []string{"api.github.com:443", "files.pypi.org:443", "gitlab.com:443"} {
		if got := connect(t, e, ok); !strings.Contains(got, "200") {
			t.Errorf("%s: %s", ok, got)
		}
	}
	for _, bad := range []string{"evil.com:443", "a.b.pypi.org:443", "pypi.org:443", "api.github.com:22", "api.github.com:8080"} {
		if got := connect(t, e, bad); !strings.Contains(got, "403") {
			t.Errorf("%s should be denied: %s", bad, got)
		}
	}
	for _, h := range e.resolved {
		if h == "evil.com" || h == "a.b.pypi.org" {
			t.Errorf("denied name %s was resolved (DNS must be policy-gated)", h)
		}
	}
	// The dialled address is the validated IP, not a sandbox-chosen name.
	if e.dialed[0] != "140.82.112.5:443" {
		t.Errorf("dialed %v", e.dialed)
	}
}

func TestPlainHTTPForward(t *testing.T) {
	e := setup(t, Config{Allow: []string{"example.com"}}, map[string]string{"example.com": "93.184.216.34", "other.com": "1.2.3.4"})
	if code, body := httpGet(t, e, "http://example.com/x"); code != 200 || body != "upstream-ok" {
		t.Errorf("%d %q", code, body)
	}
	if code, _ := httpGet(t, e, "http://other.com/x"); code != 403 {
		t.Errorf("other.com: %d", code)
	}
}

func TestRebindingAndInternalAddresses(t *testing.T) {
	e := setup(t, Config{Allow: []string{"rebind.example.com", "granted.example.com", "169.254.169.254", "10.1.2.3", "10.9.0.0/16"}},
		map[string]string{"rebind.example.com": "127.0.0.1", "granted.example.com": "10.9.4.4"})
	if got := connect(t, e, "rebind.example.com:443"); !strings.Contains(got, "403") {
		t.Errorf("name resolving to loopback must be denied: %s", got)
	}
	// An explicit CIDR grant covering the resolved address permits it.
	if got := connect(t, e, "granted.example.com:443"); !strings.Contains(got, "200") {
		t.Errorf("explicitly granted internal CIDR: %s", got)
	}
	// IP literals need an explicit grant; metadata is only reachable if listed.
	if got := connect(t, e, "169.254.169.254:80"); !strings.Contains(got, "200") {
		t.Errorf("explicit IP grant: %s", got)
	}
	e2 := setup(t, Config{Allow: []string{"example.com"}}, nil)
	for _, ip := range []string{"169.254.169.254:80", "127.0.0.1:443", "10.0.0.1:443", "1.1.1.1:443"} {
		if got := connect(t, e2, ip); !strings.Contains(got, "403") {
			t.Errorf("%s must be denied without a grant: %s", ip, got)
		}
	}
	if len(e2.dialed) != 0 {
		t.Errorf("denied destinations were dialled: %v", e2.dialed)
	}
}

func TestBadConfig(t *testing.T) {
	if _, err := Start(Config{Allow: []string{"*.*.com"}}); err == nil {
		t.Error("bad pattern must fail")
	}
	if _, err := Start(Config{Allow: []string{"@nope"}}); err == nil {
		t.Error("unknown set must fail")
	}
}

// "*" is any public host or IP; sensitive addresses still need an explicit
// grant, and names resolving to them are refused.
func TestAnyPublicHost(t *testing.T) {
	e := setup(t, Config{Allow: []string{"*"}},
		map[string]string{"github.com": "140.82.112.3", "rebind.example.com": "10.0.0.5", "meta.example.com": "169.254.169.254"})
	for _, ok := range []string{"github.com:443", "1.1.1.1:443"} {
		if got := connect(t, e, ok); !strings.Contains(got, "200") {
			t.Errorf("%s: %s", ok, got)
		}
	}
	for _, bad := range []string{"169.254.169.254:80", "127.0.0.1:443", "10.0.0.1:443", "192.168.1.1:443",
		"rebind.example.com:443", "meta.example.com:80", "github.com:22"} {
		if got := connect(t, e, bad); !strings.Contains(got, "403") {
			t.Errorf("%s must be denied under *: %s", bad, got)
		}
	}
}

func TestUnixSocket(t *testing.T) {
	dir, err := os.MkdirTemp("", "eg")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := dir + "/egress.sock"
	e := setup(t, Config{Allow: []string{"example.com"}, UnixSocket: sock}, map[string]string{"example.com": "93.184.216.34"})
	if e.g.Addr() != sock {
		t.Errorf("Addr %q", e.g.Addr())
	}
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprintf(c, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	if line, _ := bufio.NewReader(c).ReadString('\n'); !strings.Contains(line, "200") {
		t.Errorf("over the socket: %q", line)
	}
	if fi, err := os.Stat(sock); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("socket mode %v %v", fi, err)
	}
}

// A name that does not resolve was not refused by policy: no "denied" event
// (a run ending mid-lookup made allowed hosts look refused).
func TestUnresolvedIsNotDenied(t *testing.T) {
	var ev []string
	g, err := Start(Config{Allow: []string{"*"}, OnEvent: func(k, h string) { ev = append(ev, k+" "+h) },
		Resolve: func(context.Context, string) ([]netipAddr, error) { return nil, fmt.Errorf("no such host") }})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	if _, err := g.dial(context.Background(), "nowhere.invalid:443"); err == nil {
		t.Fatal("an unresolved name must not connect")
	}
	if len(ev) != 0 {
		t.Errorf("events %v", ev)
	}
}
