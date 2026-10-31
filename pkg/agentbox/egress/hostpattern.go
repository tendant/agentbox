package egress

import (
	"fmt"
	"net/netip"
	"strings"
)

type hostKind int

const (
	hostExact hostKind = iota
	hostWildcard
	hostPrefix // CIDR or single IP
	hostSet    // @name trusted set, opaque
	// hostAny ("*") is any public host or IP. It never grants a sensitive
	// address (private, loopback, link-local, metadata): MatchIP ignores it,
	// so only an explicit CIDR/IP grant reaches those.
	hostAny
)

type hostPattern struct {
	kind   hostKind
	name   string // exact host, wildcard suffix ("github.com" for *.github.com), or set name
	prefix netip.Prefix
}

// parseHostPattern parses an egress grant: exact host, single-label wildcard
// (*.example.com), IP/CIDR, or trusted set (@vcs).
func parseHostPattern(s string) (hostPattern, error) {
	s = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
	switch {
	case s == "":
		return hostPattern{}, fmt.Errorf("empty host pattern")
	case s == "*":
		return hostPattern{kind: hostAny}, nil
	case strings.HasPrefix(s, "@"):
		if len(s) == 1 || strings.ContainsAny(s[1:], "@*/ ") {
			return hostPattern{}, fmt.Errorf("bad set %q", s)
		}
		return hostPattern{kind: hostSet, name: s}, nil
	case strings.Contains(s, "/"):
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return hostPattern{}, fmt.Errorf("bad CIDR %q", s)
		}
		return hostPattern{kind: hostPrefix, prefix: p.Masked()}, nil
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return hostPattern{kind: hostPrefix, prefix: netip.PrefixFrom(a, a.BitLen())}, nil
	}
	if strings.HasPrefix(s, "*.") {
		rest := s[2:]
		if rest == "" || strings.Contains(rest, "*") || !strings.Contains(rest, ".") {
			return hostPattern{}, fmt.Errorf("bad wildcard %q (only single leading *. over a domain)", s)
		}
		return hostPattern{kind: hostWildcard, name: rest}, nil
	}
	if strings.ContainsAny(s, "*: ") {
		return hostPattern{}, fmt.Errorf("bad host %q", s)
	}
	return hostPattern{kind: hostExact, name: s}, nil
}

// subsetOf reports whether every destination matched by c is matched by p.
func (c hostPattern) subsetOf(p hostPattern) bool {
	switch p.kind {
	case hostSet:
		return c.kind == hostSet && c.name == p.name
	case hostPrefix:
		return c.kind == hostPrefix && c.prefix.Bits() >= p.prefix.Bits() &&
			c.prefix.Addr().BitLen() == p.prefix.Addr().BitLen() && p.prefix.Contains(c.prefix.Addr())
	case hostExact:
		return c.kind == hostExact && c.name == p.name
	case hostWildcard:
		switch c.kind {
		case hostWildcard:
			return c.name == p.name
		case hostExact:
			label, ok := strings.CutSuffix(c.name, "."+p.name)
			return ok && label != "" && !strings.Contains(label, ".")
		}
	}
	return false
}

// ValidateHostPattern checks one egress grant: exact host, single-label
// wildcard (*.example.com), IP/CIDR, "*", or trusted set (@vcs).
func ValidateHostPattern(s string) error {
	_, err := parseHostPattern(s)
	return err
}

// HostsSubset reports whether every pattern in child is covered by some
// parent pattern; if not, it also returns the first one that is not.
func HostsSubset(child, parent []string) (bool, string) {
	var ps []hostPattern
	for _, s := range parent {
		p, err := parseHostPattern(s)
		if err != nil {
			return false, s
		}
		ps = append(ps, p)
	}
	for _, s := range child {
		c, err := parseHostPattern(s)
		if err != nil {
			return false, s
		}
		ok := false
		for _, p := range ps {
			if c.subsetOf(p) {
				ok = true
				break
			}
		}
		if !ok {
			return false, s
		}
	}
	return true, ""
}

// HostMatcher decides whether a destination (host name or IP literal) is
// granted by a list of egress patterns, with @set expansion.
type HostMatcher struct {
	pats []hostPattern
	sets map[string]*HostMatcher
}

// NewHostMatcher parses patterns. sets maps "@name" to its member patterns
// (members may not themselves be sets, which keeps expansion finite).
func NewHostMatcher(patterns []string, sets map[string][]string) (*HostMatcher, error) {
	m := &HostMatcher{sets: map[string]*HostMatcher{}}
	for name, members := range sets {
		sub, err := NewHostMatcher(members, nil)
		if err != nil {
			return nil, fmt.Errorf("set %s: %w", name, err)
		}
		m.sets[strings.ToLower(name)] = sub
	}
	for _, s := range patterns {
		p, err := parseHostPattern(s)
		if err != nil {
			return nil, err
		}
		if p.kind == hostSet && m.sets[p.name] == nil {
			return nil, fmt.Errorf("unknown set %s", p.name)
		}
		m.pats = append(m.pats, p)
	}
	return m, nil
}

// Match reports whether host (a name or IP literal, no port) is granted.
func (m *HostMatcher) Match(host string) bool { return m.match(host, true) }

// MatchIP reports whether ip is granted explicitly (a CIDR/IP grant, possibly
// in a set): what a sensitive address needs. "*" does not count.
func (m *HostMatcher) MatchIP(ip netip.Addr) bool { return m.match(ip.Unmap().String(), false) }

func (m *HostMatcher) match(host string, any bool) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	addr, err := netip.ParseAddr(host)
	isIP := err == nil
	for _, p := range m.pats {
		switch p.kind {
		case hostAny:
			if any {
				return true
			}
		case hostSet:
			if m.sets[p.name].match(host, any) {
				return true
			}
		case hostPrefix:
			if isIP && p.prefix.Contains(addr.Unmap()) {
				return true
			}
		case hostExact:
			if !isIP && host == p.name {
				return true
			}
		case hostWildcard:
			if !isIP {
				if label, ok := strings.CutSuffix(host, "."+p.name); ok && label != "" && !strings.Contains(label, ".") {
					return true
				}
			}
		}
	}
	return false
}
