package pricing

import "testing"

func TestDefaultParses(t *testing.T) {
	d := Default()
	if d.Version == "" || len(d.Prices) == 0 {
		t.Fatalf("default table: %+v", d)
	}
	seen := map[string]bool{}
	for _, p := range d.Prices {
		k := p.Provider + "/" + p.Model
		if seen[k] {
			t.Errorf("duplicate %s", k)
		}
		seen[k] = true
	}
}

func TestLookup(t *testing.T) {
	d := Default()
	for _, c := range []struct {
		provider, model, want string
	}{
		{"anthropic", "claude-opus-5-5", "claude-opus-5-5"},
		{"anthropic", "claude-opus-5", "claude-opus-5"},
		{"anthropic", "claude-haiku-4-5-20251001", "claude-haiku-4-5"},
		{"deepseek", "deepseek-chat", "deepseek-chat"},
	} {
		p, ok := d.Lookup(c.provider, c.model)
		if !ok || p.Model != c.want {
			t.Errorf("%s/%s: %+v %v", c.provider, c.model, p, ok)
		}
	}
	for _, c := range [][2]string{
		{"anthropic", "claude-opus-5-7"},  // not a snapshot of claude-opus-5
		{"anthropic", "claude-opus-5-5x"}, // not a name in the table
		{"openai", "claude-opus-5-5"},     // another provider's
		{"anthropic", ""},
	} {
		if p, ok := d.Lookup(c[0], c[1]); ok {
			t.Errorf("%v priced as %s", c, p.Model)
		}
	}
}

func TestMicros(t *testing.T) {
	p := Price{Input: 4, Output: 20, CacheRead: 0.2, CacheWrite: 5}
	// 1M input = $4, 100K output = $2, 1M cache read = $0.20, 10K write = $0.05.
	got := p.Micros(Tokens{Input: 1_000_000, Output: 100_000, CacheRead: 1_000_000, CacheWrite: 10_000})
	if got != 6_250_000 {
		t.Errorf("micros %d", got)
	}
	// A fraction of a millionth is charged, not dropped.
	if got := (Price{CacheRead: 0.0028}).Micros(Tokens{CacheRead: 1}); got != 1 {
		t.Errorf("rounding %d", got)
	}
}

func TestCeiling(t *testing.T) {
	c, ok := Default().Ceiling("anthropic")
	if !ok || c.Input != 10 || c.Output != 50 || c.CacheWrite != 12.5 {
		t.Errorf("ceiling %+v %v", c, ok)
	}
	if _, ok := Default().Ceiling("nobody"); ok {
		t.Error("ceiling for a provider with no prices")
	}
}

func TestParseRejects(t *testing.T) {
	for _, b := range []string{`{}`, `{"version":"v","prices":[{"provider":"a"}]}`, `{"version":"v","prices":[{"provider":"a","model":"m","input":-1}]}`} {
		if _, err := Parse([]byte(b)); err == nil {
			t.Errorf("accepted %s", b)
		}
	}
}
