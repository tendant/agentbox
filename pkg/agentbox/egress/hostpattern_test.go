package egress

import "testing"

func TestHostMatcher(t *testing.T) {
	m, err := NewHostMatcher([]string{"*.github.com", "10.0.0.0/8", "@vcs"}, map[string][]string{"@vcs": {"gitlab.com"}})
	if err != nil {
		t.Fatal(err)
	}
	for h, want := range map[string]bool{"api.github.com": true, "a.b.github.com": false, "github.com": false, "10.2.3.4": true,
		"11.0.0.1": false, "gitlab.com": true, "evil.com": false, "API.GITHUB.COM.": true} {
		if m.Match(h) != want {
			t.Errorf("%s: want %v", h, want)
		}
	}
}

func TestHostsSubset(t *testing.T) {
	cases := []struct {
		c, p string
		want bool
	}{
		{"10.1.0.0/16", "10.0.0.0/8", true},
		{"10.0.0.0/8", "10.1.0.0/16", false},
		{"10.2.3.4", "10.0.0.0/8", true},
		{"::1", "10.0.0.0/8", false},
		{"api.github.com", "*.github.com", true},
		{"a.b.github.com", "*.github.com", false}, // single label only
		{"github.com", "*.github.com", false},
		{"*.github.com", "*.github.com", true},
		{"*.api.github.com", "*.github.com", false},
		{"API.GitHub.com.", "*.github.com", true},
		{"evilgithub.com", "*.github.com", false},
		{"@vcs", "@vcs", true},
		{"github.com", "@vcs", false},
		{"@vcs", "github.com", false},
	}
	for _, c := range cases {
		got, _ := HostsSubset([]string{c.c}, []string{c.p})
		if got != c.want {
			t.Errorf("%s ⊆ %s = %v, want %v", c.c, c.p, got, c.want)
		}
	}
}

func TestValidateHostPattern(t *testing.T) {
	for _, ok := range []string{"*", "github.com", "*.github.com", "10.0.0.0/8", "::1", "@vcs"} {
		if err := ValidateHostPattern(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "*.*.com", "*.com", "a b", "host:443", "@", "10.0.0.0/33"} {
		if ValidateHostPattern(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
