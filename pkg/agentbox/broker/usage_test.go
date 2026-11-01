package broker

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
)

// readUsage passes body through a usage reader in small, uneven reads and
// returns what it reported and the bytes the client got.
func readUsage(t *testing.T, format UsageFormat, status int, contentType, body string) (Usage, string) {
	t.Helper()
	var got []Usage
	b := newUsageBody(io.NopCloser(iotest.HalfReader(strings.NewReader(body))), status, contentType, format,
		func(u Usage) { got = append(got, u) })
	out, err := io.ReadAll(b)
	if err != nil {
		t.Fatal(err)
	}
	b.Close()
	if len(got) != 1 {
		t.Fatalf("reported %d times, want once", len(got))
	}
	return got[0], string(out)
}

func TestUsageAnthropicStream(t *testing.T) {
	body := "event: message_start\n" +
		`data: {"type":"message_start","message":{"model":"claude-x","usage":{"input_tokens":12,"cache_creation_input_tokens":300,"cache_read_input_tokens":4000,"output_tokens":1}}}` + "\n\n" +
		"event: content_block_delta\n" +
		`data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"` + strings.Repeat("x", 3000) + `"}}` + "\n\n" +
		"event: message_delta\n" +
		`data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":345}}` + "\n\n" +
		"event: message_stop\r\n" + `data: {"type":"message_stop"}` + "\r\n\r\n"
	u, out := readUsage(t, UsageAnthropic, 200, "text/event-stream; charset=utf-8", body)
	if out != body {
		t.Error("the stream reached the client altered")
	}
	want := Usage{Model: "claude-x", InputTokens: 12, OutputTokens: 345, CacheReadTokens: 4000, CacheWriteTokens: 300, Status: 200}
	if u != want {
		t.Errorf("usage %+v, want %+v", u, want)
	}
}

func TestUsageAnthropicJSON(t *testing.T) {
	u, _ := readUsage(t, UsageAnthropic, 200, "application/json",
		`{"id":"msg_1","model":"claude-x","content":[{"type":"text","text":"hi"}],"usage":{"input_tokens":7,"output_tokens":9,"cache_read_input_tokens":3}}`)
	if u != (Usage{Model: "claude-x", InputTokens: 7, OutputTokens: 9, CacheReadTokens: 3, Status: 200}) {
		t.Errorf("usage %+v", u)
	}
}

// OpenAI counts cached tokens inside the prompt; they come out of input.
func TestUsageOpenAI(t *testing.T) {
	chat, _ := readUsage(t, UsageOpenAI, 200, "application/json",
		`{"model":"gpt-x","choices":[],"usage":{"prompt_tokens":100,"completion_tokens":20,"prompt_tokens_details":{"cached_tokens":60}}}`)
	if chat != (Usage{Model: "gpt-x", InputTokens: 40, OutputTokens: 20, CacheReadTokens: 60, Status: 200}) {
		t.Errorf("chat completions %+v", chat)
	}
	stream := `data: {"object":"chat.completion.chunk","model":"deepseek-chat","choices":[{"delta":{"content":"a"}}],"usage":null}` + "\n\n" +
		`data: {"object":"chat.completion.chunk","model":"deepseek-chat","choices":[],"usage":{"prompt_tokens":50,"completion_tokens":5}}` + "\n\n" +
		"data: [DONE]\n\n"
	if u, _ := readUsage(t, UsageOpenAI, 200, "text/event-stream", stream); u != (Usage{Model: "deepseek-chat", InputTokens: 50, OutputTokens: 5, Status: 200}) {
		t.Errorf("chat stream %+v", u)
	}
	responses := "event: response.output_text.delta\n" + `data: {"type":"response.output_text.delta","delta":"hi"}` + "\n\n" +
		"event: response.completed\n" +
		`data: {"type":"response.completed","response":{"model":"gpt-5","usage":{"input_tokens":900,"input_tokens_details":{"cached_tokens":800},"output_tokens":30}}}` + "\n\n"
	if u, _ := readUsage(t, UsageOpenAI, 200, "text/event-stream", responses); u != (Usage{Model: "gpt-5", InputTokens: 100, OutputTokens: 30, CacheReadTokens: 800, Status: 200}) {
		t.Errorf("responses stream %+v", u)
	}
}

// A successful response that ends without its final usage report is
// truncated; an error response reports no usage and is not.
func TestUsageTruncatedAndErrors(t *testing.T) {
	cut := `data: {"type":"message_start","message":{"model":"claude-x","usage":{"input_tokens":12,"output_tokens":1}}}` + "\n\n" +
		`data: {"type":"content_block_delta"`
	if u, _ := readUsage(t, UsageAnthropic, 200, "text/event-stream", cut); !u.Truncated || u.InputTokens != 12 {
		t.Errorf("cut stream %+v", u)
	}
	noUsage := `data: {"object":"chat.completion.chunk","choices":[{"delta":{"content":"a"}}]}` + "\n\ndata: [DONE]\n\n"
	if u, _ := readUsage(t, UsageOpenAI, 200, "text/event-stream", noUsage); !u.Truncated {
		t.Errorf("chat stream without usage: %+v", u)
	}
	if u, _ := readUsage(t, UsageAnthropic, 429, "application/json", `{"type":"error","error":{"type":"rate_limit_error"}}`); u.Truncated || u.Status != 429 || u.InputTokens != 0 {
		t.Errorf("error response %+v", u)
	}
	// A body closed before its end is reported once, as truncated.
	var got []Usage
	b := newUsageBody(io.NopCloser(strings.NewReader(`{"usage":{"input_tokens":1}}`)), 200, "application/json", UsageAnthropic, func(u Usage) { got = append(got, u) })
	b.Read(make([]byte, 4))
	b.Close()
	b.Close()
	if len(got) != 1 || !got[0].Truncated {
		t.Errorf("early close: %+v", got)
	}
}

// Through the broker: every forwarded request gets an id, sent upstream in
// place of any the client forged, and one usage report under the same id,
// including a request whose upstream failed.
func TestBrokerReportsUsagePerRequest(t *testing.T) {
	var seen []string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Header.Get("Agentbox-Request-Id"))
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"model":"claude-x","usage":{"input_tokens":5,"output_tokens":6}}`)
	}))
	defer up.Close()
	u, _ := url.Parse(up.URL)
	var mu sync.Mutex
	var forwarded []string
	usage := map[string]Usage{}
	p, err := Start(Config{
		Upstream: u, AuthHeader: "x-api-key", AuthValue: "K", PathPrefixes: []string{"/v1/"},
		RequestIDHeader: "Agentbox-Request-Id", UsageFormat: UsageAnthropic,
		OnForward: func(id string) { mu.Lock(); forwarded = append(forwarded, id); mu.Unlock() },
		OnUsage:   func(id string, u Usage) { mu.Lock(); usage[id] = u; mu.Unlock() },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	req, _ := http.NewRequest("POST", p.BaseURL()+"/v1/messages", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+p.Token())
	req.Header.Set("Agentbox-Request-Id", "req_forged")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	up.Close() // the next request's upstream fails
	resp2, _ := do(p, "/v1/messages", p.Token(), "{}")

	mu.Lock()
	defer mu.Unlock()
	if len(forwarded) != 2 || !strings.HasPrefix(forwarded[0], "req_") || len(forwarded[0]) != 36 || forwarded[0] == forwarded[1] {
		t.Fatalf("forwarded ids %v", forwarded)
	}
	if len(seen) != 1 || seen[0] != forwarded[0] {
		t.Errorf("upstream got request id %v, want the broker's %s", seen, forwarded[0])
	}
	if got := usage[forwarded[0]]; got != (Usage{Model: "claude-x", InputTokens: 5, OutputTokens: 6, Status: 200}) {
		t.Errorf("usage %+v", got)
	}
	if resp2 == nil || resp2.StatusCode != 502 || usage[forwarded[1]] != (Usage{Status: 502}) {
		t.Errorf("failed upstream: %v, usage %+v", resp2, usage[forwarded[1]])
	}
}

// A client that accepts compression (as the claude CLI does) still gets its
// usage read: the broker drops its Accept-Encoding, and the transport
// decompresses what it asked for itself. The client gets the plain body.
func TestUsageReadThroughCompression(t *testing.T) {
	const body = `{"model":"claude-x","usage":{"input_tokens":5,"output_tokens":6}}`
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			w.Header().Set("Content-Encoding", "gzip")
			z := gzip.NewWriter(w)
			io.WriteString(z, body)
			z.Close()
			return
		}
		io.WriteString(w, body)
	}))
	defer up.Close()
	u, _ := url.Parse(up.URL)
	var got Usage
	p, err := Start(Config{Upstream: u, AuthHeader: "x-api-key", AuthValue: "K", PathPrefixes: []string{"/v1/"},
		UsageFormat: UsageAnthropic, OnUsage: func(_ string, u Usage) { got = u }})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	req, _ := http.NewRequest("POST", p.BaseURL()+"/v1/messages", strings.NewReader("{}"))
	req.Header.Set("x-api-key", p.Token())
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	resp, err := (&http.Client{Transport: &http.Transport{DisableCompression: true}}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(out) != body || resp.Header.Get("Content-Encoding") != "" {
		t.Errorf("client got %q (encoding %q), want the plain body", out, resp.Header.Get("Content-Encoding"))
	}
	if got != (Usage{Model: "claude-x", InputTokens: 5, OutputTokens: 6, Status: 200}) {
		t.Errorf("usage %+v", got)
	}
}

// Requests that ask for no output (a liveness check, count_tokens, the model
// list) are reported once, with no tokens and nothing missing.
func TestUsageOnlyExpectedFromGeneration(t *testing.T) {
	for _, c := range []struct {
		method, path string
		format       UsageFormat
		want         bool
	}{
		{"POST", "/v1/messages", UsageAnthropic, true},
		{"POST", "/v1/messages/count_tokens", UsageAnthropic, false},
		{"GET", "/api/hello", UsageAnthropic, false},
		{"POST", "/v1/chat/completions", UsageOpenAI, true},
		{"POST", "/chat/completions", UsageOpenAI, true},
		{"POST", "/backend-api/codex/responses", UsageOpenAI, true},
		{"GET", "/v1/models", UsageOpenAI, false},
	} {
		if got := generates(c.method, c.path, c.format); got != c.want {
			t.Errorf("generates(%s %s) = %v", c.method, c.path, got)
		}
	}
	if u, _ := readUsage(t, UsageNone, 200, "application/json", `{"input_tokens":42}`); u.Truncated || u.InputTokens != 0 {
		t.Errorf("count_tokens-like response: %+v", u)
	}
}
