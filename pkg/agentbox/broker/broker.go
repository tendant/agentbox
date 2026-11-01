// Package broker is the host-side model channel: the sandboxed agent talks to
// a per-run local endpoint with a per-run token, and the broker attaches the real
// provider credential and forwards. Provider keys never enter the sandbox, and
// the channel is an explicitly authorized, byte- and rate-limited exception to
// the sandbox's network policy.
//
// This package must not import an agentbox backend (gvisor, seatbelt).
package broker

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Config describes one run's model channel.
type Config struct {
	Upstream   *url.URL // provider base URL, e.g. https://api.anthropic.com
	ListenHost string   // address to listen on; "" = 127.0.0.1. A backend with its own network namespace (gVisor) needs one it can route to
	AuthHeader string   // header carrying the provider credential, e.g. "x-api-key" or "Authorization"
	AuthValue  string   // full header value (secret; never logged)
	// Credential, when set, replaces AuthHeader/AuthValue: it is called per
	// request for the headers to attach (a refreshing login, e.g. ChatGPT's
	// bearer token and account id). An error fails the request with 502.
	Credential func(context.Context) (http.Header, error)
	// Headers are set on every forwarded request, replacing any the client
	// sent under those names: what the host asserts about the run (its
	// run id, for a ledger upstream). A name with no values is only
	// removed. The sandbox cannot forge them.
	Headers       http.Header
	PathPrefixes  []string // allowed request path prefixes; empty = deny all
	MaxRequestB   int64    // per-request body cap (0 = 1 MiB default)
	MaxTotalB     int64    // total bytes (request+response) for the run; 0 = unlimited
	RatePerMinute int      // requests per minute; 0 = unlimited
	// UnixSocket, when set, is a path the proxy also listens on: the channel
	// for a sandbox without network (agentbox), mounted into it.
	UnixSocket string
	Transport  http.RoundTripper
	OnEvent    func(kind string) // "denied", "limit", "forwarded" (no payloads)
	// OnForward, when set, is called with each forwarded request's id as it
	// is sent: the broker's own name for the call ("req_" and 32 hex
	// digits), never the client's.
	OnForward func(requestID string)
	// RequestIDHeader, when set, carries that id upstream (to a ledger,
	// which records it), replacing any the client sent under that name.
	RequestIDHeader string
	// UsageFormat and OnUsage: read each response's token usage as it passes
	// (never holding a stream back, never keeping content) and report it
	// once per forwarded request, when its response ends or the upstream
	// fails. Both must be set.
	UsageFormat UsageFormat
	OnUsage     func(requestID string, u Usage)
}

// Proxy is a running per-run channel.
type Proxy struct {
	cfg   Config
	token string
	ln    net.Listener
	srv   *http.Server

	total atomic.Int64
	mu    sync.Mutex
	win   []time.Time
}

// Start listens on ListenHost (127.0.0.1 by default; ephemeral port) and
// returns the proxy.
func Start(cfg Config) (*Proxy, error) {
	if cfg.Upstream == nil || (cfg.Credential == nil && (cfg.AuthHeader == "" || cfg.AuthValue == "")) {
		return nil, errors.New("broker: upstream and credential required")
	}
	if cfg.MaxRequestB == 0 {
		cfg.MaxRequestB = 1 << 20
	}
	var tok [24]byte
	if _, err := rand.Read(tok[:]); err != nil {
		return nil, err
	}
	host := cfg.ListenHost
	if host == "" {
		host = "127.0.0.1"
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		return nil, err
	}
	p := &Proxy{cfg: cfg, token: hex.EncodeToString(tok[:]), ln: ln}
	rp := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(cfg.Upstream)
			r.Out.Host = cfg.Upstream.Host
			r.Out.Header.Del("Authorization")
			r.Out.Header.Del("X-Api-Key")
			if p.readsUsage() {
				// A compressed response cannot be read for usage. Without
				// the client's Accept-Encoding the transport asks for gzip
				// itself and hands back the body decompressed, to the
				// reader and the client alike (on loopback, where the size
				// does not matter).
				r.Out.Header.Del("Accept-Encoding")
			}
			if cfg.RequestIDHeader != "" {
				r.Out.Header.Del(cfg.RequestIDHeader)
				if id, _ := r.In.Context().Value(reqKey{}).(string); id != "" {
					r.Out.Header.Set(cfg.RequestIDHeader, id)
				}
			}
			for k, v := range cfg.Headers {
				if len(v) == 0 {
					r.Out.Header.Del(k)
				} else {
					r.Out.Header[http.CanonicalHeaderKey(k)] = slices.Clone(v)
				}
			}
			if h, ok := r.In.Context().Value(credKey{}).(http.Header); ok {
				for k, v := range h {
					r.Out.Header[k] = v
				}
				return
			}
			r.Out.Header.Set(cfg.AuthHeader, cfg.AuthValue)
		},
		Transport: cfg.Transport,
		ModifyResponse: func(resp *http.Response) error {
			resp.Body = &countingBody{ReadCloser: resp.Body, p: p}
			if p.readsUsage() {
				id, _ := resp.Request.Context().Value(reqKey{}).(string)
				format := cfg.UsageFormat
				if !generates(resp.Request.Method, resp.Request.URL.Path, format) {
					format = UsageNone // reported, with no tokens and nothing missing
				}
				resp.Body = newUsageBody(resp.Body, resp.StatusCode, resp.Header.Get("Content-Type"), format,
					func(u Usage) { cfg.OnUsage(id, u) })
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, _ error) {
			if p.readsUsage() {
				// No response to read: the call is still reported, once.
				id, _ := r.Context().Value(reqKey{}).(string)
				cfg.OnUsage(id, Usage{Status: http.StatusBadGateway})
			}
			http.Error(w, "upstream error", http.StatusBadGateway)
		},
	}
	p.srv = &http.Server{Handler: p.guard(rp), ReadHeaderTimeout: 10 * time.Second}
	if cfg.UnixSocket != "" {
		os.Remove(cfg.UnixSocket)
		ul, err := net.Listen("unix", cfg.UnixSocket)
		if err != nil {
			ln.Close()
			return nil, fmt.Errorf("broker: unix socket: %w", err)
		}
		// The sandbox reaches it as the runner's own user (rootless), and the
		// per-run token still guards it; owner-only keeps other users out.
		os.Chmod(cfg.UnixSocket, 0o600)
		go p.srv.Serve(ul)
	}
	go p.srv.Serve(ln)
	return p, nil
}

// BaseURL is what the agent is pointed at (e.g. via ANTHROPIC_BASE_URL).
func (p *Proxy) BaseURL() string { return "http://" + p.ln.Addr().String() }

// Addr is the proxy's listen address (host:port), for network policy.
func (p *Proxy) Addr() string { return p.ln.Addr().String() }

// Token is the per-run credential the sandbox receives instead of the provider key.
func (p *Proxy) Token() string { return p.token }

// Port is the loopback port, for network policy exposure.
func (p *Proxy) Port() int { return p.ln.Addr().(*net.TCPAddr).Port }

// Close stops the proxy.
func (p *Proxy) Close() error { return p.srv.Close() }

func (p *Proxy) event(k string) {
	if p.cfg.OnEvent != nil {
		p.cfg.OnEvent(k)
	}
}

func (p *Proxy) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !p.authorized(r) {
			p.event("denied")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if !p.pathAllowed(r.URL.Path) {
			p.event("denied")
			http.Error(w, "path not allowed", http.StatusForbidden)
			return
		}
		if !p.allowRate() {
			p.event("limit")
			http.Error(w, "rate limit", http.StatusTooManyRequests)
			return
		}
		if r.ContentLength > p.cfg.MaxRequestB {
			p.event("limit")
			http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, p.cfg.MaxRequestB)
		if max := p.cfg.MaxTotalB; max > 0 {
			if p.total.Load() >= max {
				p.event("limit")
				http.Error(w, "byte budget exhausted", http.StatusTooManyRequests)
				return
			}
			p.total.Add(max0(r.ContentLength))
		}
		if p.cfg.Credential != nil {
			h, err := p.cfg.Credential(r.Context())
			if err != nil {
				p.event("credential_error")
				http.Error(w, "model credential unavailable", http.StatusBadGateway)
				return
			}
			r = r.WithContext(context.WithValue(r.Context(), credKey{}, h))
		}
		id, err := newRequestID()
		if err != nil {
			http.Error(w, "broker error", http.StatusInternalServerError)
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), reqKey{}, id))
		p.event("forwarded")
		if p.cfg.OnForward != nil {
			p.cfg.OnForward(id)
		}
		next.ServeHTTP(w, r)
	})
}

// credKey carries a request's Credential headers from guard to Rewrite.
type credKey struct{}

// reqKey carries a forwarded request's id from guard to Rewrite and the
// response.
type reqKey struct{}

func newRequestID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "req_" + hex.EncodeToString(b[:]), nil
}

func (p *Proxy) readsUsage() bool { return p.cfg.OnUsage != nil && p.cfg.UsageFormat != UsageNone }

func max0(n int64) int64 {
	if n < 0 {
		return 0
	}
	return n
}

// authorized accepts the per-run token as a bearer token or x-api-key.
func (p *Proxy) authorized(r *http.Request) bool {
	got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if got == "" {
		got = r.Header.Get("X-Api-Key")
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(p.token)) == 1
}

func (p *Proxy) pathAllowed(path string) bool {
	if strings.Contains(path, "..") {
		return false
	}
	for _, pre := range p.cfg.PathPrefixes {
		if strings.HasPrefix(path, pre) {
			return true
		}
	}
	return false
}

func (p *Proxy) allowRate() bool {
	if p.cfg.RatePerMinute <= 0 {
		return true
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	cut := now.Add(-time.Minute)
	i := 0
	for i < len(p.win) && p.win[i].Before(cut) {
		i++
	}
	p.win = p.win[i:]
	if len(p.win) >= p.cfg.RatePerMinute {
		return false
	}
	p.win = append(p.win, now)
	return true
}

// countingBody charges response bytes to the run budget and cuts the stream
// when it is exhausted.
type countingBody struct {
	io.ReadCloser
	p *Proxy
}

var errBudget = fmt.Errorf("broker: byte budget exhausted")

func (c *countingBody) Read(b []byte) (int, error) {
	n, err := c.ReadCloser.Read(b)
	if max := c.p.cfg.MaxTotalB; max > 0 {
		if c.p.total.Add(int64(n)) > max {
			c.p.event("limit")
			return n, errBudget
		}
	}
	return n, err
}
