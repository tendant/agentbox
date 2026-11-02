// Package egress is the host-side egress gateway for "restricted" network
// policy. The sandbox has no direct network; it reaches the gateway (HTTP proxy
// with CONNECT) which enforces the grants and serves DNS itself, so a name is
// resolved once, validated, and dialled by IP (no rebinding, no sandbox-chosen
// resolver). Private/loopback/link-local/metadata destinations are refused
// unless an explicit CIDR/IP grant covers them.
//
// This package must not import an agentbox backend (gvisor, seatbelt).
package egress

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"
)

// Resolver is the controlled DNS: the only name resolution the sandbox gets.
type Resolver func(ctx context.Context, host string) ([]netip.Addr, error)

// Config configures a gateway for one run.
type Config struct {
	Allow   []string            // grants: hosts, *.wildcards, CIDRs/IPs, @sets
	Sets    map[string][]string // trusted sets, e.g. "@vcs"
	Resolve Resolver            // nil = system resolver
	Dial    func(ctx context.Context, network, addr string) (net.Conn, error)
	Ports   []int                   // allowed destination ports; nil = 443 and 80
	OnEvent func(kind, host string) // "allowed" | "denied" | "outside"; never payloads
	// ReportOnly connects to a host the allowlist does not grant instead of
	// refusing it, and reports it "outside": an allowlist tried before it is
	// enforced. Ports and internal addresses are refused all the same.
	ReportOnly bool
	// UnixSocket, when set, is where the gateway listens instead of
	// 127.0.0.1: a sandbox with no network reaches it mounted (agentbox).
	UnixSocket string
	// Inspect, when set, inspects HTTPS (port 443) to the hosts granted:
	// each request is read and reported (OnRequest), and forwarded over a
	// connection that verifies the host's real certificate. The sandbox must
	// trust Inspect's certificate. InspectExcept names hosts never inspected
	// (patterns as Allow's); a host whose client refuses the certificate
	// passes through for the rest of the run. Both are reported once per
	// host (OnInspection, InspectExcepted or InspectClientRefused).
	Inspect       *Inspector
	InspectExcept []string
	OnRequest     func(RequestInfo)
	OnInspection  func(host, reason string)
	// UpstreamRoots verifies inspected hosts' certificates; nil: the
	// system roots.
	UpstreamRoots *x509.CertPool
}

// Gateway is a running egress proxy.
type Gateway struct {
	cfg Config
	m   *HostMatcher
	ln  net.Listener
	srv *http.Server
	wg  sync.WaitGroup

	except      *HostMatcher // InspectExcept
	inspMu      sync.Mutex
	passThrough map[string]bool // hosts whose client refused inspection
	reported    map[string]bool // hosts reported not inspected
}

// Start listens on 127.0.0.1 and serves until Close.
func Start(cfg Config) (*Gateway, error) {
	m, err := NewHostMatcher(cfg.Allow, cfg.Sets)
	if err != nil {
		return nil, err
	}
	if cfg.Resolve == nil {
		cfg.Resolve = systemResolve
	}
	if cfg.Dial == nil {
		d := &net.Dialer{Timeout: 15 * time.Second}
		cfg.Dial = d.DialContext
	}
	if cfg.Ports == nil {
		cfg.Ports = []int{443, 80}
	}
	var ln net.Listener
	if cfg.UnixSocket != "" {
		os.Remove(cfg.UnixSocket)
		if ln, err = net.Listen("unix", cfg.UnixSocket); err != nil {
			return nil, err
		}
		os.Chmod(cfg.UnixSocket, 0o600) // the runner's user only (the sandbox is that user)
	} else if ln, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
		return nil, err
	}
	g := &Gateway{cfg: cfg, m: m, ln: ln, passThrough: map[string]bool{}, reported: map[string]bool{}}
	if len(cfg.InspectExcept) > 0 {
		if g.except, err = NewHostMatcher(cfg.InspectExcept, cfg.Sets); err != nil {
			ln.Close()
			return nil, fmt.Errorf("egress: inspect exceptions: %w", err)
		}
	}
	g.srv = &http.Server{Handler: g, ReadHeaderTimeout: 10 * time.Second}
	go g.srv.Serve(ln)
	return g, nil
}

// Addr is host:port for HTTP(S)_PROXY (the socket path with UnixSocket).
func (g *Gateway) Addr() string { return g.ln.Addr().String() }

// Close stops the gateway.
func (g *Gateway) Close() error { return g.srv.Close() }

func systemResolve(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

func (g *Gateway) event(kind, host string) {
	if g.cfg.OnEvent != nil {
		g.cfg.OnEvent(kind, host)
	}
}

var errDenied = errors.New("egress denied")

// dial validates host:port against policy, resolves, and dials the IP.
func (g *Gateway) dial(ctx context.Context, hostport string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil, errDenied
	}
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil || !g.portOK(port) {
		slog.Info("egress port check failed", "hostport", hostport, "host", host, "port", port, "allowed_ports", g.cfg.Ports, "parse_err", err)
		g.event("denied", host)
		return nil, errDenied
	}
	// outside: not granted, reached anyway (ReportOnly). The internal
	// address check below still applies: granted or not, a name never
	// reaches one without an explicit grant.
	outside := !g.m.Match(host)
	if outside && !g.cfg.ReportOnly {
		g.event("denied", host)
		return nil, errDenied
	}
	var addrs []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{ip.Unmap()}
	} else {
		if addrs, err = g.cfg.Resolve(ctx, host); err != nil || len(addrs) == 0 {
			// Not a policy decision (no such name, or the run ended
			// mid-lookup): no "denied" event, which would read as a refusal.
			return nil, errDenied
		}
	}
	var last error = errDenied
	for _, a := range addrs {
		a = a.Unmap()
		if sensitive(a) && !g.m.MatchIP(a) {
			// A granted NAME resolving to an internal address (rebinding,
			// metadata) needs an explicit CIDR grant for that address.
			slog.Info("egress deny sensitive IP", "host", host, "port", port, "ip", a.String())
			g.event("denied", host)
			last = errDenied
			continue
		}
		slog.Info("egress allow attempt", "host", host, "port", port, "ip", a.String())
		c, err := g.cfg.Dial(ctx, "tcp", net.JoinHostPort(a.String(), portStr))
		if err == nil {
			slog.Info("egress allow success", "host", host, "port", port, "ip", a.String(), "outside", outside)
			if outside {
				g.event("outside", host)
			} else {
				g.event("allowed", host)
			}
			return c, nil
		}
		last = err
	}
	return nil, last
}

func (g *Gateway) portOK(p int) bool {
	for _, x := range g.cfg.Ports {
		if x == p {
			return true
		}
	}
	return false
}

// sensitive reports addresses that are never reachable by name alone.
func sensitive(a netip.Addr) bool {
	return a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsMulticast() || a.IsUnspecified() || a.IsInterfaceLocalMulticast()
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		g.connect(w, r)
		return
	}
	if !r.URL.IsAbs() {
		http.Error(w, "proxy request required", http.StatusBadRequest)
		return
	}
	host := r.URL.Host
	if !strings.Contains(host, ":") {
		host = net.JoinHostPort(host, "80")
	}
	// Plain HTTP is readable as it is: reported when requests are.
	start := time.Now()
	info := RequestInfo{Host: r.URL.Hostname(), Method: r.Method, Path: cleanPath(r.URL.Path), Protocol: r.Proto}
	if g.cfg.OnRequest != nil {
		defer func() { info.Duration = time.Since(start); g.request(info) }()
	}
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return g.dial(ctx, host) }}
	defer tr.CloseIdleConnections()
	out := r.Clone(r.Context())
	out.RequestURI = ""
	out.Header.Del("Proxy-Authorization")
	body := &counter{r: io.NopCloser(strings.NewReader(""))}
	if r.Body != nil && r.Body != http.NoBody {
		body.r = r.Body
		out.Body = body
	}
	resp, err := tr.RoundTrip(out)
	info.RequestBytes = body.n.Load()
	if err != nil {
		code := http.StatusBadGateway
		if errors.Is(err, errDenied) {
			code = http.StatusForbidden
		}
		info.Status, info.Error = code, "upstream_failed"
		http.Error(w, "egress "+http.StatusText(code), code)
		return
	}
	defer resp.Body.Close()
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	info.Status = resp.StatusCode
	info.ResponseBytes, _ = io.Copy(w, resp.Body)
}

func (g *Gateway) connect(w http.ResponseWriter, r *http.Request) {
	up, err := g.dial(r.Context(), r.Host)
	if err != nil {
		code := http.StatusBadGateway
		if errors.Is(err, errDenied) {
			code = http.StatusForbidden
		}
		http.Error(w, "egress "+http.StatusText(code), code)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		up.Close()
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	raw, brw, err := hj.Hijack()
	if err != nil {
		up.Close()
		return
	}
	c := net.Conn(raw)
	if brw.Reader.Buffered() > 0 {
		c = bufConn{Conn: raw, r: brw.Reader}
	}
	io.WriteString(raw, "HTTP/1.1 200 Connection Established\r\n\r\n")
	if host, p, err := net.SplitHostPort(r.Host); err == nil {
		var port int
		fmt.Sscanf(p, "%d", &port)
		if g.inspects(host, port) {
			g.inspect(c, up, host, port)
			return
		}
	}
	go func() { io.Copy(up, c); up.Close() }()
	io.Copy(c, up)
	c.Close()
}
