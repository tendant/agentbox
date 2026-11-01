// Package pricing is the model price table: list prices per provider and
// model, versioned, so a cost estimated from broker-read token counts can
// name the prices it used and be checked later. The runner prices a run's
// calls against its model budget with it; a reader (agent-gate) prices the
// same counts for its reports. One table, so the two agree.
//
// An estimate is not a bill: it is tokens times list price, with no
// discounts, and for a subscription channel a value, not a cost.
package pricing

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"math"
	"strings"
)

//go:embed prices.json
var embedded []byte

// Price is one model's list price, USD per million tokens.
type Price struct {
	Provider   string  `json:"provider"`
	Model      string  `json:"model"`
	Input      float64 `json:"input"`
	Output     float64 `json:"output"`
	CacheRead  float64 `json:"cache_read"`
	CacheWrite float64 `json:"cache_write"`
}

// Tokens are one call's counts, as the broker reads them: Input excludes
// the cached tokens, which are counted apart.
type Tokens struct {
	Input, Output, CacheRead, CacheWrite int64
}

// Micros is what t costs at p, in USD millionths, rounded up.
func (p Price) Micros(t Tokens) int64 {
	// USD per million tokens is USD millionths per token.
	c := float64(t.Input)*p.Input + float64(t.Output)*p.Output +
		float64(t.CacheRead)*p.CacheRead + float64(t.CacheWrite)*p.CacheWrite
	return int64(math.Ceil(c))
}

// Table is a set of prices under one version.
type Table struct {
	Version string  `json:"version"`
	Prices  []Price `json:"prices"`
}

var def = func() *Table {
	t, err := Parse(embedded)
	if err != nil {
		panic(err)
	}
	return t
}()

// Default is the table this release of agentbox carries.
func Default() *Table { return def }

// Parse reads a table (the format of prices.json).
func Parse(b []byte) (*Table, error) {
	var t Table
	if err := json.Unmarshal(b, &t); err != nil {
		return nil, fmt.Errorf("pricing: %w", err)
	}
	if t.Version == "" {
		return nil, fmt.Errorf("pricing: table has no version")
	}
	for _, p := range t.Prices {
		if p.Provider == "" || p.Model == "" || p.Input < 0 || p.Output < 0 || p.CacheRead < 0 || p.CacheWrite < 0 {
			return nil, fmt.Errorf("pricing: bad entry %+v", p)
		}
	}
	return &t, nil
}

// Lookup finds model's price under provider: the entry of that name, or one
// of which model is a dated snapshot (claude-haiku-4-5-20251001). A model
// the table does not name has no price; it is never guessed from a
// neighbour.
func (t *Table) Lookup(provider, model string) (Price, bool) {
	for _, p := range t.Prices {
		if p.Provider != provider {
			continue
		}
		if model == p.Model {
			return p, true
		}
		if rest, ok := strings.CutPrefix(model, p.Model+"-"); ok && isDate(rest) {
			return p, true
		}
	}
	return Price{}, false
}

// Ceiling is the highest of provider's rates, each taken apart: what a
// budget charges a call to a model the table does not price, so an
// unknown model cannot slip past it. False when the table has no price
// for the provider.
func (t *Table) Ceiling(provider string) (Price, bool) {
	c := Price{Provider: provider}
	found := false
	for _, p := range t.Prices {
		if p.Provider != provider {
			continue
		}
		found = true
		c.Input = max(c.Input, p.Input)
		c.Output = max(c.Output, p.Output)
		c.CacheRead = max(c.CacheRead, p.CacheRead)
		c.CacheWrite = max(c.CacheWrite, p.CacheWrite)
	}
	return c, found
}

// isDate: eight digits, a snapshot's YYYYMMDD.
func isDate(s string) bool {
	if len(s) != 8 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
