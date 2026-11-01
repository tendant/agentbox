package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// PolicySnapshot is what one run was allowed and what its backend actually
// enforced, recorded once when the run starts. Rules judge a run against it;
// silence in the event stream is never taken as compliance.
type PolicySnapshot struct {
	Backend string `json:"backend"`
	// Mode is how gaps were treated (off, permissive, strict).
	Mode string `json:"mode,omitempty"`
	// CapabilityRegistry is the version of the capability definitions the
	// check was made against.
	CapabilityRegistry int `json:"capability_registry,omitempty"`
	// Spec is the resolved policy the run asked for; Check is the backend's
	// answer (enforced capabilities, gaps, caveats). Both are stored as the
	// caller's JSON so this package needs neither type.
	Spec  json.RawMessage `json:"spec"`
	Check json.RawMessage `json:"check"`
	// Metering is how each model provider's calls are metered in this run
	// (provider -> MeteringLedger, MeteringBroker or MeteringNone), declared
	// before it starts. A reader judges each model_forwarded against it.
	// Absent from snapshots that predate it, so their digests are unchanged.
	Metering map[string]string `json:"metering,omitempty"`
}

// NewPolicySnapshot encodes spec and check into a snapshot.
func NewPolicySnapshot(backend, mode string, registry int, spec, check any) (PolicySnapshot, error) {
	s := PolicySnapshot{Backend: backend, Mode: mode, CapabilityRegistry: registry}
	var err error
	if s.Spec, err = json.Marshal(spec); err != nil {
		return s, fmt.Errorf("audit: policy spec: %w", err)
	}
	if s.Check, err = json.Marshal(check); err != nil {
		return s, fmt.Errorf("audit: policy check: %w", err)
	}
	return s, nil
}

// PolicyDigest is "sha256:" and the hex SHA-256 of detail with insignificant
// whitespace removed, so a reader can recompute it from a stored
// policy_snapshot event's detail.
func PolicyDigest(detail []byte) (string, error) {
	var b bytes.Buffer
	if err := json.Compact(&b, detail); err != nil {
		return "", fmt.Errorf("audit: policy digest: %w", err)
	}
	sum := sha256.Sum256(b.Bytes())
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
