package egress

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
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
