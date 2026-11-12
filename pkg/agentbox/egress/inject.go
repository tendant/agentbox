package egress

import (
	"errors"
	"fmt"
	"net/http"
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
// sent, and returns their names.
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
