package egress

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// InjectRule sets a header on every inspected HTTPS request to a host: a
// credential the runner holds, so the sandbox never has it. The value is
// never reported; Name is what the record calls it (the secret's name).
type InjectRule struct {
	Host   string // a host or *.wildcard, as Allow's
	Header string // e.g. Authorization
	Value  string // e.g. "Bearer <token>"
	Name   string // e.g. GITHUB_TOKEN
	// Plain also sets the header on plain HTTP requests to the host, but
	// only when the address actually dialled is one the credential cannot
	// leave in the clear over: this machine (loopback) or a Tailscale
	// address, whose traffic WireGuard encrypts (TrustedPlain). To any
	// other address it is withheld, and the record says so. Without Plain a
	// rule is for HTTPS only: a credential never goes out in the clear.
	Plain bool
}

// Tailscale's address ranges: its IPv4 addresses (in the shared 100.64/10
// space) and its IPv6 ULA prefix.
var (
	tailnet4 = netip.MustParsePrefix("100.64.0.0/10")
	tailnet6 = netip.MustParsePrefix("fd7a:115c:a1e0::/48")
)

// TrustedPlain reports whether a plain-HTTP credential may go to a: the
// machine itself, or a Tailscale address. The address is the one dialled,
// not what a name says, so a renamed or rebound host cannot receive it.
func TrustedPlain(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsLoopback() || tailnet4.Contains(a) || tailnet6.Contains(a)
}

// remoteAddr is a connection's peer address, or the zero Addr.
func remoteAddr(c net.Conn) netip.Addr {
	if c == nil {
		return netip.Addr{}
	}
	ap, err := netip.ParseAddrPort(c.RemoteAddr().String())
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr()
}

// injector applies Config.Inject.
type injector struct {
	rules []injectRule
}

type injectRule struct {
	InjectRule
	m *HostMatcher
}

// Headers a rule may not set: the connection's own, and what routes the
// request.
var notInjectable = map[string]bool{"Host": true, "Content-Length": true, "Upgrade": true}

func newInjector(rules []InjectRule) (*injector, error) {
	if len(rules) == 0 {
		return nil, nil
	}
	in := &injector{}
	for _, r := range rules {
		m, err := NewHostMatcher([]string{r.Host}, nil)
		if err != nil || r.Host == "" || r.Host == "*" || strings.HasPrefix(r.Host, "@") || strings.ContainsAny(r.Host, "/:") {
			return nil, fmt.Errorf("egress: inject: host %q: want a host or *.wildcard", r.Host)
		}
		h := http.CanonicalHeaderKey(r.Header)
		if !validHeaderName(h) || notInjectable[h] || isHop(h) {
			return nil, fmt.Errorf("egress: inject: header %q cannot be set", r.Header)
		}
		if r.Value == "" || !validHeaderValue(r.Value) {
			return nil, fmt.Errorf("egress: inject: %s for %s: empty or not a valid header value", r.Name, r.Host)
		}
		if r.Name == "" {
			return nil, errors.New("egress: inject: a rule needs a name for the record")
		}
		r.Header = h
		in.rules = append(in.rules, injectRule{InjectRule: r, m: m})
	}
	return in, nil
}

func isHop(h string) bool {
	for _, x := range hopHeaders {
		if strings.EqualFold(x, h) {
			return true
		}
	}
	return false
}

// hosts are the rules' host patterns.
func (in *injector) hosts() []string {
	var out []string
	for _, r := range in.rules {
		out = append(out, r.Host)
	}
	return out
}

// apply sets the matching rules' headers on h, over whatever the client
// sent, and returns their names: an HTTPS request.
func (in *injector) apply(host string, h http.Header) []string {
	if in == nil {
		return nil
	}
	var names []string
	for _, r := range in.rules {
		if r.m.Match(host) {
			h.Set(r.Header, r.Value)
			names = append(names, r.Name)
		}
	}
	return names
}

// coversPlain reports whether a Plain rule matches host: its plain HTTP
// requests then go over a connection checked before they are sent.
func (in *injector) coversPlain(host string) bool {
	if in == nil {
		return false
	}
	for _, r := range in.rules {
		if r.Plain && r.m.Match(host) {
			return true
		}
	}
	return false
}

// applyPlain is apply for a plain HTTP request sent over a connection to
// addr: the Plain rules matching host set their headers when addr is
// trusted (TrustedPlain); otherwise none is set and their names come back
// as withheld.
func (in *injector) applyPlain(host string, addr netip.Addr, h http.Header) (names, withheld []string) {
	if in == nil {
		return nil, nil
	}
	ok := addr.IsValid() && TrustedPlain(addr)
	for _, r := range in.rules {
		if !r.Plain || !r.m.Match(host) {
			continue
		}
		if ok {
			h.Set(r.Header, r.Value)
			names = append(names, r.Name)
		} else {
			withheld = append(withheld, r.Name)
		}
	}
	return names, withheld
}

// validHeaderName: an RFC 9110 token.
func validHeaderName(h string) bool {
	if h == "" {
		return false
	}
	for _, c := range h {
		if c > 0x7e || c <= ' ' || strings.ContainsRune("\"(),/:;<=>?@[\\]{}", c) {
			return false
		}
	}
	return true
}

// validHeaderValue: printable, no line breaks or control characters (tab
// allowed).
func validHeaderValue(v string) bool {
	for _, c := range v {
		if c < ' ' && c != '\t' || c == 0x7f {
			return false
		}
	}
	return true
}
