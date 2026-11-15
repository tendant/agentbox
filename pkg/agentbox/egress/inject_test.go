package egress

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
)

// echoAuth answers with the Authorization header it got.
var echoAuth = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "auth=["+r.Header.Get("Authorization")+"]")
})

func getVia(t *testing.T, x *inspected, h2 bool, url, auth string) string {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	resp, err := x.client(x.trusting(), h2).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

// An inspected HTTPS request to a rule's host gets the rule's header, over
// whatever the client sent, and is reported with the rule's name; another
// host gets nothing.
func TestInjectSetsTheCredential(t *testing.T) {
	x := inspectSetup(t, func(c *Config) {
		c.Inject = []InjectRule{{Host: "example.com", Header: "authorization", Value: "Bearer real-token", Name: "GITHUB_TOKEN"}}
	}, echoAuth)
	for _, h2 := range []bool{false, true} {
		if got := getVia(t, x, h2, "https://example.com/user", ""); got != "auth=[Bearer real-token]" {
			t.Errorf("h2=%v: %s", h2, got)
		}
	}
	if got := getVia(t, x, false, "https://example.com/user", "Bearer the-agents-own"); got != "auth=[Bearer real-token]" {
		t.Errorf("the client's header was kept: %s", got)
	}
	if got := getVia(t, x, false, "https://other.example.com/user", ""); got != "auth=[]" {
		t.Errorf("another host got the credential: %s", got)
	}
	reqs, _ := x.reported()
	if len(reqs) != 4 {
		t.Fatalf("reported %+v", reqs)
	}
	for i, r := range reqs[:3] {
		if len(r.Credentials) != 1 || r.Credentials[0] != "GITHUB_TOKEN" {
			t.Errorf("request %d: credentials %v", i, r.Credentials)
		}
	}
	if reqs[3].Credentials != nil {
		t.Errorf("other host: credentials %v", reqs[3].Credentials)
	}
}

// Plain HTTP never carries an injected credential.
func TestInjectNeverInTheClear(t *testing.T) {
	var got string
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
		w.WriteHeader(204)
	}))
	t.Cleanup(plain.Close)
	x := inspectSetup(t, func(c *Config) {
		c.Dial = func(ctx context.Context, n, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, n, plain.Listener.Addr().String())
		}
		c.Inject = []InjectRule{{Host: "example.com", Header: "Authorization", Value: "Bearer real-token", Name: "T"}}
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
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	if resp, err := http.ReadResponse(br, nil); err != nil || resp.StatusCode != 204 {
		t.Fatalf("request: %v", err)
	}
	if got != "" {
		t.Errorf("plain HTTP carried %q", got)
	}
}

// InspectOnly limits inspection to its hosts: others pass through,
// uninspected and unreported.
func TestInspectOnly(t *testing.T) {
	x := inspectSetup(t, func(c *Config) { c.InspectOnly = []string{"example.com"} }, echoAuth)
	getVia(t, x, false, "https://example.com/a", "")
	// other.example.com is not inspected: the client sees the upstream's
	// own certificate, which it does not trust here.
	req, _ := http.NewRequest("GET", "https://other.example.com/b", nil)
	if _, err := x.client(x.trusting(), false).Do(req); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Errorf("other host was inspected: %v", err)
	}
	reqs, _ := x.reported()
	if len(reqs) != 1 || reqs[0].Host != "example.com" {
		t.Errorf("reported %+v", reqs)
	}
}

func TestInjectRulesChecked(t *testing.T) {
	ok := InjectRule{Host: "api.example.com", Header: "Authorization", Value: "Bearer x", Name: "T"}
	for name, mod := range map[string]func(*InjectRule){
		"wildcard all": func(r *InjectRule) { r.Host = "*" },
		"set":          func(r *InjectRule) { r.Host = "@github" },
		"cidr":         func(r *InjectRule) { r.Host = "10.0.0.0/8" },
		"port":         func(r *InjectRule) { r.Host = "api.example.com:443" },
		"host header":  func(r *InjectRule) { r.Header = "Host" },
		"hop header":   func(r *InjectRule) { r.Header = "Connection" },
		"bad header":   func(r *InjectRule) { r.Header = "Auth orization" },
		"newline":      func(r *InjectRule) { r.Value = "Bearer x\r\nX-Evil: 1" },
		"empty value":  func(r *InjectRule) { r.Value = "" },
		"no name":      func(r *InjectRule) { r.Name = "" },
	} {
		r := ok
		mod(&r)
		if _, err := newInjector([]InjectRule{r}); err == nil {
			t.Errorf("%s: accepted %+v", name, r)
		}
	}
	if _, err := newInjector([]InjectRule{ok, {Host: "*.example.com", Header: "X-Api-Key", Value: "k", Name: "K"}}); err != nil {
		t.Error(err)
	}
	if _, err := Start(Config{Allow: []string{"*"}, Inject: []InjectRule{ok}}); err == nil {
		t.Error("inject without inspection started")
	}
}

// addrConn is a connection to a test server that reports addr as its peer:
// the address the gateway resolved and dialled.
type addrConn struct {
	net.Conn
	addr net.Addr
}

func (c addrConn) RemoteAddr() net.Addr { return c.addr }

// plainSetup is a gateway whose example.com resolves to ip, served by a
// plain HTTP server that records the Authorization it got, with a Plain
// rule for example.com.
func plainSetup(t *testing.T, ip string) (*inspected, func() string) {
	t.Helper()
	var mu sync.Mutex
	var got string
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = r.Header.Get("Authorization")
		mu.Unlock()
		w.WriteHeader(204)
	}))
	t.Cleanup(plain.Close)
	x := inspectSetup(t, func(c *Config) {
		c.Allow = append(c.Allow, "192.168.0.0/16", "127.0.0.0/8")
		c.Resolve = func(context.Context, string) ([]netipAddr, error) { return []netipAddr{mustAddr(ip)}, nil }
		c.Dial = func(ctx context.Context, n, addr string) (net.Conn, error) {
			conn, err := (&net.Dialer{}).DialContext(ctx, n, plain.Listener.Addr().String())
			if err != nil {
				return nil, err
			}
			ta, _ := net.ResolveTCPAddr("tcp", addr)
			return addrConn{conn, ta}, nil
		}
		c.Inject = []InjectRule{{Host: "example.com", Header: "Authorization", Value: "Bearer real-token", Name: "LEDGER_KEY", Plain: true}}
	}, http.NotFoundHandler())
	return x, func() string { mu.Lock(); defer mu.Unlock(); return got }
}

// plainViaProxy sends a plain HTTP request through the gateway as a proxy.
func plainViaProxy(t *testing.T, x *inspected) {
	t.Helper()
	resp, err := x.client(nil, false).Get("http://example.com/v1/decisions")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 204 {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

// plainViaTunnel sends a plain HTTP request through a CONNECT tunnel to
// port 80 (as transparent mode does).
func plainViaTunnel(t *testing.T, x *inspected) {
	t.Helper()
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
	fmt.Fprintf(conn, "GET /v1/decisions HTTP/1.1\r\nHost: example.com\r\n\r\n")
	if resp, err := http.ReadResponse(br, nil); err != nil || resp.StatusCode != 204 {
		t.Fatalf("request: %v", err)
	}
}

// A Plain rule sets its credential on plain HTTP to a Tailscale or
// loopback address, by both paths, and names it on the record.
func TestInjectPlainOverTrustedPaths(t *testing.T) {
	for _, ip := range []string{"100.98.79.90", "127.0.0.1"} {
		for name, send := range map[string]func(*testing.T, *inspected){"proxy": plainViaProxy, "tunnel": plainViaTunnel} {
			x, got := plainSetup(t, ip)
			send(t, x)
			if got() != "Bearer real-token" {
				t.Errorf("%s via %s: upstream got %q", ip, name, got())
			}
			reqs, _ := x.reported()
			if len(reqs) != 1 || len(reqs[0].Credentials) != 1 || reqs[0].Credentials[0] != "LEDGER_KEY" || reqs[0].CredentialsWithheld != nil {
				t.Errorf("%s via %s: reported %+v", ip, name, reqs)
			}
		}
	}
}

// To any other address, public or LAN, the name matching is not enough: the
// credential is withheld, and the record says so.
func TestInjectPlainWithheldElsewhere(t *testing.T) {
	for _, ip := range []string{"203.0.113.10", "192.168.3.199"} {
		for name, send := range map[string]func(*testing.T, *inspected){"proxy": plainViaProxy, "tunnel": plainViaTunnel} {
			x, got := plainSetup(t, ip)
			send(t, x)
			if got() != "" {
				t.Errorf("%s via %s: the credential went out in the clear: %q", ip, name, got())
			}
			reqs, _ := x.reported()
			if len(reqs) != 1 || reqs[0].Credentials != nil || len(reqs[0].CredentialsWithheld) != 1 || reqs[0].CredentialsWithheld[0] != "LEDGER_KEY" {
				t.Errorf("%s via %s: reported %+v", ip, name, reqs)
			}
		}
	}
}

// A Plain rule still sets its credential on HTTPS, as any rule does.
func TestInjectPlainRuleCoversHTTPS(t *testing.T) {
	x := inspectSetup(t, func(c *Config) {
		c.Inject = []InjectRule{{Host: "example.com", Header: "Authorization", Value: "Bearer real-token", Name: "T", Plain: true}}
	}, echoAuth)
	if got := getVia(t, x, false, "https://example.com/user", ""); got != "auth=[Bearer real-token]" {
		t.Errorf("https: %s", got)
	}
}

func TestTrustedPlain(t *testing.T) {
	for ip, want := range map[string]bool{
		"127.0.0.1": true, "::1": true, "100.64.0.1": true, "100.98.79.90": true, "100.127.255.254": true,
		"fd7a:115c:a1e0::1": true, "::ffff:100.98.79.90": true,
		"100.128.0.1": false, "100.63.255.255": false, "192.168.3.199": false, "10.0.0.1": false,
		"203.0.113.10": false, "fd00::1": false, "169.254.169.254": false,
	} {
		if got := TrustedPlain(netip.MustParseAddr(ip)); got != want {
			t.Errorf("TrustedPlain(%s) = %v, want %v", ip, got, want)
		}
	}
}
