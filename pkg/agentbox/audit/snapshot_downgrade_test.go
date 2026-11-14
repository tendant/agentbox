package audit

import (
	"encoding/json"
	"strings"
	"testing"
)

// Snapshots recorded before ModelDowngrade existed must keep their bytes, and
// so their digests: an absent list is omitted, not written as null or [].
func TestModelDowngradeOmittedWhenEmpty(t *testing.T) {
	s := PolicySnapshot{Backend: "gvisor", Spec: json.RawMessage(`{}`), Check: json.RawMessage(`{}`)}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "model_downgrade") {
		t.Fatalf("empty ModelDowngrade serialized: %s", b)
	}
	s.ModelDowngrade = []string{"openai"}
	b, _ = json.Marshal(s)
	if !strings.Contains(string(b), `"model_downgrade":["openai"]`) {
		t.Fatalf("ModelDowngrade missing: %s", b)
	}
}
