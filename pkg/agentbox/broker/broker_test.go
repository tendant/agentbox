package broker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
)

func setup(t *testing.T, mod func(*Config)) (*Proxy, *httptest.Server, *[]http.Header) {
	var seen []http.Header
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Header.Clone())
		io.WriteString(w, strings.Repeat("r", 100))
	}))
	t.Cleanup(up.Close)
	u, _ := url.Parse(up.URL)
	cfg := Config{Upstream: u, AuthHeader: "x-api-key", AuthValue: "REAL-PROVIDER-KEY", PathPrefixes: []string{"/v1/"}}
	if mod != nil {
		mod(&cfg)
	}
	p, err := Start(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	return p, up, &seen
}

func do(p *Proxy, path, token, body string) (*http.Response, string) {
	req, _ := http.NewRequest("POST", p.BaseURL()+path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func TestInjectsCredentialAndHidesIt(t *testing.T) {
	p, _, seen := setup(t, nil)
	resp, body := do(p, "/v1/messages", p.Token(), "{}")
	if resp.StatusCode != 200 || len(body) != 100 {
		t.Fatalf("%d %d", resp.StatusCode, len(body))
	}
	h := (*seen)[0]
	if h.Get("X-Api-Key") != "REAL-PROVIDER-KEY" || h.Get("Authorization") != "" {
		t.Errorf("upstream headers: %v", h)
	}
	if strings.Contains(p.BaseURL(), "REAL") || strings.Contains(p.Token(), "REAL") {
		t.Error("secret leaked to sandbox-visible values")
	}
}

func TestRejectsUnauthorizedAndPaths(t *testing.T) {
	var events []string
	p, _, seen := setup(t, func(c *Config) { c.OnEvent = func(k string) { events = append(events, k) } })
	if r, _ := do(p, "/v1/x", "wrong", ""); r.StatusCode != 401 {
		t.Errorf("wrong token: %d", r.StatusCode)
	}
	if r, _ := do(p, "/v1/x", "", ""); r.StatusCode != 401 {
		t.Errorf("no token: %d", r.StatusCode)
	}
	if r, _ := do(p, "/other", p.Token(), ""); r.StatusCode != 403 {
		t.Errorf("path: %d", r.StatusCode)
	}
	if len(*seen) != 0 {
		t.Error("denied requests must not reach upstream")
	}
}

func TestLimits(t *testing.T) {
	p, _, _ := setup(t, func(c *Config) { c.MaxRequestB = 10 })
	if r, _ := do(p, "/v1/x", p.Token(), strings.Repeat("a", 50)); r.StatusCode != 413 {
		t.Errorf("big request: %d", r.StatusCode)
	}
	p, _, _ = setup(t, func(c *Config) { c.RatePerMinute = 2 })
	var codes []int
	for i := 0; i < 3; i++ {
		r, _ := do(p, "/v1/x", p.Token(), "")
		codes = append(codes, r.StatusCode)
	}
	if codes[0] != 200 || codes[1] != 200 || codes[2] != 429 {
		t.Errorf("rate: %v", codes)
	}
	p, _, _ = setup(t, func(c *Config) { c.MaxTotalB = 150 })
	r1, b1 := do(p, "/v1/x", p.Token(), "")
	_, b2 := do(p, "/v1/x", p.Token(), "")
	r3, _ := do(p, "/v1/x", p.Token(), "")
	if r1.StatusCode != 200 || len(b1) != 100 || len(b2) >= 100 || r3.StatusCode != 429 {
		t.Errorf("budget: %d %d %d %d", r1.StatusCode, len(b1), len(b2), r3.StatusCode)
	}
}

func TestCredentialPerRequest(t *testing.T) {
	n := 0
	fail := false
	p, _, seen := setup(t, func(c *Config) {
		c.AuthHeader, c.AuthValue = "", ""
		c.Credential = func(context.Context) (http.Header, error) {
			if fail {
				return nil, errors.New("login expired")
			}
			n++
			return http.Header{"Authorization": {fmt.Sprintf("Bearer access-%d", n)}, "Chatgpt-Account-Id": {"acct"}}, nil
		}
	})
	for i := 1; i <= 2; i++ {
		resp, _ := do(p, "/v1/x", p.Token(), "{}")
		if resp == nil || resp.StatusCode != 200 {
			t.Fatalf("request %d: %v", i, resp)
		}
		h := (*seen)[i-1]
		if h.Get("Authorization") != fmt.Sprintf("Bearer access-%d", i) || h.Get("Chatgpt-Account-Id") != "acct" {
			t.Errorf("request %d upstream headers: %v", i, h)
		}
		if strings.Contains(h.Get("Authorization"), p.Token()) {
			t.Error("run token forwarded upstream")
		}
	}
	fail = true
	if resp, body := do(p, "/v1/x", p.Token(), "{}"); resp == nil || resp.StatusCode != http.StatusBadGateway || strings.Contains(body, "login expired") {
		t.Errorf("failing credential: %v %q", resp, body)
	}
	if len(*seen) != 2 {
		t.Errorf("a request without a credential reached upstream")
	}
}

func TestUnixSocketListener(t *testing.T) {
	dir, err := os.MkdirTemp("", "px") // short: Unix socket paths are limited
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := dir + "/m.sock"
	p, _, seen := setup(t, func(c *Config) { c.UnixSocket = sock })
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", sock)
	}}}
	req, _ := http.NewRequest("POST", "http://sandbox/v1/x", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+p.Token())
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("over the socket: %v %v", resp, err)
	}
	resp.Body.Close()
	if (*seen)[0].Get("x-api-key") != "REAL-PROVIDER-KEY" {
		t.Error("the credential is attached over the socket too")
	}
	req, _ = http.NewRequest("POST", "http://sandbox/v1/x", nil) // no token
	if resp, err := client.Do(req); err != nil || resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("the run token still guards the socket: %v %v", resp, err)
	}
	if fi, err := os.Stat(sock); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("socket mode: %v %v", fi, err)
	}
}

// Host-asserted headers replace whatever the sandbox sent under those names.
func TestHostHeadersReplaceClientOnes(t *testing.T) {
	p, _, seen := setup(t, func(c *Config) {
		c.Headers = http.Header{"agentbox-run-id": {"run-1"}}
	})
	req, _ := http.NewRequest("POST", p.BaseURL()+"/v1/messages", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+p.Token())
	req.Header.Add("Agentbox-Run-Id", "someone-elses-run")
	req.Header.Add("Agentbox-Run-Id", "another")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got := (*seen)[0].Values("Agentbox-Run-Id"); len(got) != 1 || got[0] != "run-1" {
		t.Errorf("upstream Agentbox-Run-Id = %q, want [run-1]", got)
	}

	// A name with no values is stripped, never passed on from the client.
	p2, _, seen2 := setup(t, func(c *Config) { c.Headers = http.Header{"Agentbox-Run-Id": nil} })
	req, _ = http.NewRequest("POST", p2.BaseURL()+"/v1/messages", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+p2.Token())
	req.Header.Set("Agentbox-Run-Id", "forged")
	if resp, err = http.DefaultClient.Do(req); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got := (*seen2)[0].Values("Agentbox-Run-Id"); len(got) != 0 {
		t.Errorf("stripped header reached upstream: %q", got)
	}
}
