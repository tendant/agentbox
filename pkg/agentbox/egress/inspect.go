package egress

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Inspector is a run's certificate authority for TLS inspection: the
// gateway answers an inspected connection with a certificate for its host
// issued by it, reads the requests, and forwards each to the host over its
// own TLS connection, which verifies the host's real certificate. The
// sandbox trusts the authority (CertPEM, mounted and named in its trust
// variables); its key never leaves the host, and lives as long as the run.
type Inspector struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	leafKey *ecdsa.PrivateKey
	pem     []byte
	mu      sync.Mutex
	leaves  map[string]*tls.Certificate
}

// inspectorLife bounds the authority's validity: longer than any run.
const inspectorLife = 7 * 24 * time.Hour

// NewInspector creates a run's certificate authority.
func NewInspector() (*Inspector, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "agentbox egress inspection (one run)", Organization: []string{"agentbox"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(inspectorLife),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &Inspector{cert: cert, key: key, leafKey: leafKey, leaves: map[string]*tls.Certificate{},
		pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}, nil
}

// CertPEM is the authority's certificate, for the sandbox to trust.
func (in *Inspector) CertPEM() []byte { return in.pem }

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	return n
}

// leaf is the certificate the gateway answers name with, issued once per
// run and name.
func (in *Inspector) leaf(name string) (*tls.Certificate, error) {
	in.mu.Lock()
	defer in.mu.Unlock()
	if c := in.leaves[name]; c != nil {
		return c, nil
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    in.cert.NotBefore,
		NotAfter:     in.cert.NotAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip, err := netip.ParseAddr(name); err == nil {
		tmpl.IPAddresses = []net.IP{ip.AsSlice()}
	} else {
		tmpl.DNSNames = []string{name}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, in.cert, &in.leafKey.PublicKey, in.key)
	if err != nil {
		return nil, err
	}
	c := &tls.Certificate{Certificate: [][]byte{der, in.cert.Raw}, PrivateKey: in.leafKey}
	in.leaves[name] = c
	return c, nil
}

// RequestInfo is one inspected request: what was asked and how it ended,
// never its headers, query string or body.
type RequestInfo struct {
	Host          string
	Method        string
	Path          string // printable, bounded, no query string
	Status        int    // 0 when no response came (Error says why)
	RequestBytes  int64
	ResponseBytes int64
	Duration      time.Duration
	Protocol      string // HTTP/1.1, HTTP/2.0
	Error         string // upstream_failed, client_gone
}

// Reasons a host is not inspected (OnInspection).
const (
	InspectClientRefused = "client_refused" // the client did not trust the run's certificate
	InspectExcepted      = "excepted"       // InspectExcept names it
)

// inspects reports whether a connection to host:port is inspected: HTTPS
// (443), and plain HTTP tunnelled (80; transparent egress hands it over as
// CONNECT). One not inspected for a reason (an exception) is reported once
// per host.
func (g *Gateway) inspects(host string, port int) bool {
	if g.cfg.Inspect == nil || port != 443 && port != 80 {
		return false
	}
	if g.except != nil && g.except.Match(host) {
		g.noInspect(host, InspectExcepted)
		return false
	}
	g.inspMu.Lock()
	defer g.inspMu.Unlock()
	return !g.passThrough[host]
}

// noInspect reports once per run and host why it is not inspected.
func (g *Gateway) noInspect(host, reason string) {
	g.inspMu.Lock()
	first := !g.reported[host]
	g.reported[host] = true
	g.inspMu.Unlock()
	if first && g.cfg.OnInspection != nil {
		g.cfg.OnInspection(host, reason)
	}
}

// inspect serves an inspected CONNECT tunnel to host:port: c is the
// client's side (after "200 Connection Established"), up the connection
// already dialled to the host, used for the first upstream request.
func (g *Gateway) inspect(c net.Conn, up net.Conn, host string, port int) {
	defer c.Close()
	if port == 80 {
		g.inspectPlain(c, up, host)
		return
	}
	cs := tls.Server(c, &tls.Config{
		NextProtos: []string{"h2", "http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := hello.ServerName
			if name == "" {
				name = host
			}
			return g.cfg.Inspect.leaf(strings.ToLower(name))
		},
	})
	hctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	err := cs.HandshakeContext(hctx)
	cancel()
	if err != nil {
		// The client refused the certificate (or gave up on it): this
		// request fails; the host passes through from now on.
		up.Close()
		g.inspMu.Lock()
		g.passThrough[host] = true
		g.inspMu.Unlock()
		g.noInspect(host, InspectClientRefused)
		return
	}
	hostport := net.JoinHostPort(host, fmt.Sprint(port))
	var first atomic.Pointer[net.Conn]
	first.Store(&up)
	tr := &http.Transport{
		ForceAttemptHTTP2:   true,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     90 * time.Second,
		TLSClientConfig:     g.upstreamTLS(host),
		DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			raw := net.Conn(nil)
			if p := first.Swap(nil); p != nil {
				raw = *p
			} else {
				var err error
				if raw, err = g.dial(ctx, hostport); err != nil {
					return nil, err
				}
			}
			tc := tls.Client(raw, g.upstreamTLS(host))
			if err := tc.HandshakeContext(ctx); err != nil {
				raw.Close()
				return nil, err
			}
			return tc, nil
		},
	}
	defer tr.CloseIdleConnections()
	// An upgrade (WebSocket) cannot go over HTTP/2: its own connections,
	// HTTP/1.1 only.
	h1 := g.upstreamTLS(host)
	h1.NextProtos = []string{"http/1.1"}
	trUp := &http.Transport{
		TLSClientConfig: h1,
		DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			raw, err := g.dial(ctx, hostport)
			if err != nil {
				return nil, err
			}
			tc := tls.Client(raw, h1)
			if err := tc.HandshakeContext(ctx); err != nil {
				raw.Close()
				return nil, err
			}
			return tc, nil
		},
	}
	defer trUp.CloseIdleConnections()
	if p := first.Load(); p != nil {
		defer func() {
			if p := first.Swap(nil); p != nil {
				(*p).Close()
			}
		}()
	}
	fwd := g.forward(host, hostport, port, tr, trUp)
	serveOne(cs, fwd)
}

// inspectPlain serves a tunnelled plain HTTP connection to host:80: its
// requests are readable as they are.
func (g *Gateway) inspectPlain(c net.Conn, up net.Conn, host string) {
	hostport := net.JoinHostPort(host, "80")
	var first atomic.Pointer[net.Conn]
	first.Store(&up)
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			if p := first.Swap(nil); p != nil {
				return *p, nil
			}
			return g.dial(ctx, hostport)
		},
	}
	defer tr.CloseIdleConnections()
	defer func() {
		if p := first.Swap(nil); p != nil {
			(*p).Close()
		}
	}()
	serveOne(c, g.forwardScheme("http", host, hostport, 80, tr, tr))
}

// serveOne serves the requests of one connection with h. Handlers still
// running when the server stops (an upgrade, which takes the connection
// over) are waited for before it returns.
func serveOne(c net.Conn, h http.Handler) {
	var running sync.WaitGroup
	srv := &http.Server{ReadHeaderTimeout: 60 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		running.Add(1)
		defer running.Done()
		h.ServeHTTP(w, r)
	})}
	ln := newOneConn(c)
	srv.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateClosed || s == http.StateHijacked {
			ln.Close()
		}
	}
	srv.Serve(ln)
	running.Wait()
}

// upstreamTLS verifies host's real certificate (its IP SANs, for an IP)
// against the system roots, or UpstreamRoots.
func (g *Gateway) upstreamTLS(host string) *tls.Config {
	return &tls.Config{NextProtos: []string{"h2", "http/1.1"}, RootCAs: g.cfg.UpstreamRoots, ServerName: host}
}

// hopHeaders are the connection's own, not forwarded either way.
var hopHeaders = []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer",
	"Transfer-Encoding"}

// forward forwards each request of an inspected connection to the host and
// reports it.
func (g *Gateway) forward(host, hostport string, port int, tr, trUp *http.Transport) http.Handler {
	return g.forwardScheme("https", host, hostport, port, tr, trUp)
}

// forwardScheme is forward for scheme (https, or http for a tunnelled
// plain connection on port 80).
func (g *Gateway) forwardScheme(scheme, host, hostport string, port int, tr, trUp *http.Transport) http.Handler {
	defaultPort := map[string]int{"https": 443, "http": 80}[scheme]
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		info := RequestInfo{Host: host, Method: r.Method, Path: cleanPath(r.URL.Path), Protocol: r.Proto}
		defer func() {
			info.Duration = time.Since(start)
			g.request(info)
		}()
		out := r.Clone(r.Context())
		out.RequestURI = ""
		out.URL.Scheme = scheme
		out.URL.Host = host
		if port != defaultPort {
			out.URL.Host = hostport
		}
		upgrade := strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
		for _, h := range hopHeaders {
			out.Header.Del(h)
		}
		if upgrade {
			out.Header.Set("Connection", "Upgrade")
			out.Header.Set("Upgrade", r.Header.Get("Upgrade"))
		}
		body := &counter{r: r.Body}
		if r.Body != nil && r.Body != http.NoBody {
			out.Body = body
		}
		rt := tr
		if upgrade {
			rt = trUp
		}
		resp, err := rt.RoundTrip(out)
		info.RequestBytes = body.n.Load()
		if err != nil {
			info.Error = "upstream_failed"
			http.Error(w, "egress: upstream failed", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		info.Status = resp.StatusCode
		if resp.StatusCode == http.StatusSwitchingProtocols {
			info.RequestBytes, info.ResponseBytes = g.switchProtocols(w, resp)
			return
		}
		for _, h := range hopHeaders {
			resp.Header.Del(h)
		}
		for k, vs := range resp.Header {
			w.Header()[k] = vs
		}
		for k := range resp.Trailer {
			w.Header().Add("Trailer", k)
		}
		w.WriteHeader(resp.StatusCode)
		n, err := copyFlushing(w, resp.Body)
		info.ResponseBytes = n
		if err != nil && !errors.Is(err, io.EOF) {
			info.Error = "client_gone"
		}
		for k, vs := range resp.Trailer {
			w.Header()[http.TrailerPrefix+k] = vs
		}
	})
}

// switchProtocols hands a 101 (WebSocket) over: the client's side is taken
// from the server, the upgraded upstream connection joined to it, until
// either ends. Bytes are counted both ways.
func (g *Gateway) switchProtocols(w http.ResponseWriter, resp *http.Response) (sent, received int64) {
	upc, ok := resp.Body.(io.ReadWriteCloser)
	if !ok {
		http.Error(w, "egress: upgrade failed", http.StatusBadGateway)
		return 0, 0
	}
	defer upc.Close()
	c, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return 0, 0
	}
	defer c.Close()
	resp.Body = nil
	if err := resp.Write(brw); err != nil {
		return 0, 0
	}
	brw.Flush()
	done := make(chan int64, 1)
	go func() {
		n, _ := io.Copy(upc, brw)
		upc.Close()
		done <- n
	}()
	received, _ = io.Copy(c, upc)
	c.Close()
	return <-done, received
}

func (g *Gateway) request(info RequestInfo) {
	if g.cfg.OnRequest != nil {
		g.cfg.OnRequest(info)
	}
}

// copyFlushing copies a response body, flushing after each read so a
// stream (server-sent events) reaches the client as it comes.
func copyFlushing(w http.ResponseWriter, r io.Reader) (int64, error) {
	rc := http.NewResponseController(w)
	buf := make([]byte, 32<<10)
	var n int64
	for {
		k, err := r.Read(buf)
		if k > 0 {
			if _, werr := w.Write(buf[:k]); werr != nil {
				return n, werr
			}
			n += int64(k)
			rc.Flush()
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return n, nil
			}
			return n, err
		}
	}
}

// counter counts what is read through it.
type counter struct {
	r io.ReadCloser
	n atomic.Int64
}

func (c *counter) Read(p []byte) (int, error) {
	k, err := c.r.Read(p)
	c.n.Add(int64(k))
	return k, err
}

func (c *counter) Close() error { return c.r.Close() }

// maxPath bounds a recorded path: the sandbox picks it.
const maxPath = 200

// cleanPath makes a sandbox-chosen URL path safe to record: printable
// ASCII, bounded. The query string is never part of it.
func cleanPath(path string) string {
	b := []byte(path)
	for i, c := range b {
		if c < 0x21 || c > 0x7e {
			b[i] = '?'
		}
	}
	if len(b) > maxPath {
		return string(b[:maxPath]) + "..."
	}
	return string(b)
}

// oneConn is a listener of one connection: the server serves it, and
// Accept then waits until the connection is done.
type oneConn struct {
	c    chan net.Conn
	done chan struct{}
	once sync.Once
	addr net.Addr
}

func newOneConn(c net.Conn) *oneConn {
	l := &oneConn{c: make(chan net.Conn, 1), done: make(chan struct{}), addr: c.LocalAddr()}
	l.c <- c
	return l
}

func (l *oneConn) Accept() (net.Conn, error) {
	select {
	case c := <-l.c:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *oneConn) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *oneConn) Addr() net.Addr { return l.addr }

// bufConn is a hijacked connection whose reader may hold bytes already.
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (b bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }
