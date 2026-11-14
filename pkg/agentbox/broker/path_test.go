package broker

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestUpstreamPath(t *testing.T) {
	for _, c := range []struct{ base, req, want string }{
		{"", "/v1/messages", "/v1/messages"},
		{"/", "/v1/messages", "/v1/messages"},
		{"/v1", "/chat/completions", "/v1/chat/completions"},
		{"/v1", "/v1/chat/completions", "/v1/chat/completions"}, // not /v1/v1/...
		{"/v1/", "/models", "/v1/models"},
		{"/v1", "/v1", "/v1"},
		{"/v1", "/v10/x", "/v1/v10/x"}, // a prefix of a segment is not the base
		{"/anthropic", "/v1/messages", "/anthropic/v1/messages"},
	} {
		if got := upstreamPath(c.base, c.req); got != c.want {
			t.Errorf("upstreamPath(%q, %q) = %q, want %q", c.base, c.req, got, c.want)
		}
	}
}

// Through the proxy: an upstream written with /v1 gets /v1 once, whichever
// form the client sent.
func TestProxyJoinsBasePathOnce(t *testing.T) {
	var got []string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.URL.Path)
		w.Write([]byte(`{}`))
	}))
	defer up.Close()
	u, _ := url.Parse(up.URL + "/v1")
	p, err := Start(Config{Upstream: u, AuthHeader: "Authorization", AuthValue: "Bearer upstream-key", PathPrefixes: []string{"/chat/completions", "/v1/chat/completions"}})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	for _, path := range []string{"/chat/completions", "/v1/chat/completions"} {
		req, _ := http.NewRequest("POST", p.BaseURL()+path, strings.NewReader("{}"))
		req.Header.Set("Authorization", "Bearer "+p.Token())
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("%s: HTTP %d", path, resp.StatusCode)
		}
	}
	if strings.Join(got, ",") != "/v1/chat/completions,/v1/chat/completions" {
		t.Errorf("upstream saw %v", got)
	}
}
