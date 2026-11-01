// Package audit is the security event record of agentbox runs: one schema
// shared by the hosts that write events and by agent-gate, which ingests
// them. Events say what a run was allowed (its policy snapshot) and what the
// host-side controls decided; they never carry environment values,
// credentials or payloads.
//
// This package must not import an agentbox backend (gvisor, seatbelt).
package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// SchemaVersion is written into every event. Readers accept any 1.x.
const SchemaVersion = "1.0"

// MaxEventBytes caps one encoded event (one JSONL line, newline excluded).
const MaxEventBytes = 64 << 10

// Event types. Readers must keep events of types they do not know.
const (
	TypeSandboxCreated     = "sandbox_created"
	TypeSandboxClosed      = "sandbox_closed"
	TypeSandboxRejected    = "sandbox_rejected"
	TypePolicySnapshot     = "policy_snapshot"
	TypeEnforcementLost    = "enforcement_lost"
	TypeNetworkAllowed     = "network_allowed"
	TypeNetworkBlocked     = "network_blocked"
	TypeResourceLimitHit   = "resource_limit_hit"
	TypeCredentialInjected = "credential_injected"
	TypeModelForwarded     = "model_forwarded"
	TypeModelDenied        = "model_denied"
	TypeModelLimitHit      = "model_limit_hit"
	// TypeModelUsage reports what one forwarded call used (UsageDetail),
	// for calls metered by the broker: written when the response ends.
	TypeModelUsage = "model_usage"
	// TypeEventsDropped marks a run whose events the record could not
	// keep (DroppedDetail): written once per run, at its first loss.
	TypeEventsDropped = "events_dropped"
)

// Event is one line of the record.
type Event struct {
	SchemaVersion string `json:"schema_version"`
	// EventID is "evt_" and a ULID: unique, and ordered by creation time
	// within one source. Readers deduplicate on it.
	EventID string `json:"event_id"`
	// RunID is the run the event belongs to: one sandbox's life, from
	// creation to close. The runner that owns the sandbox assigns it
	// (agent-runner's run ID), never the sandbox.
	RunID string `json:"run_id"`
	// SourceID names the writer (one per host and record file).
	// SourceSequence counts its events from 1 with no gaps, so a reader can
	// tell a lost event from one never written.
	SourceID       string    `json:"source_id"`
	SourceSequence uint64    `json:"source_sequence"`
	Type           string    `json:"event_type"`
	OccurredAt     time.Time `json:"occurred_at"`
	ObservedAt     time.Time `json:"observed_at"`
	// PolicyID is the digest of the run's policy snapshot ("sha256:..."),
	// on the snapshot event itself and on events decided under it.
	PolicyID string `json:"policy_id,omitempty"`
	// Detail is a JSON object; its shape depends on Type (the *Detail
	// types below for the known ones).
	Detail json.RawMessage `json:"detail,omitempty"`
}

// Validate reports whether e is a well-formed event of this schema.
func (e Event) Validate() error {
	if e.SchemaVersion != "1" && !strings.HasPrefix(e.SchemaVersion, "1.") {
		return fmt.Errorf("audit: schema version %q not supported", e.SchemaVersion)
	}
	if !validEventID(e.EventID) {
		return fmt.Errorf("audit: bad event id %q", e.EventID)
	}
	switch {
	case e.RunID == "":
		return errors.New("audit: no run id")
	case e.SourceID == "":
		return errors.New("audit: no source id")
	case e.SourceSequence == 0:
		return errors.New("audit: source sequence starts at 1")
	case e.Type == "":
		return errors.New("audit: no event type")
	case e.OccurredAt.IsZero() || e.ObservedAt.IsZero():
		return errors.New("audit: missing timestamp")
	}
	if e.PolicyID != "" && !strings.HasPrefix(e.PolicyID, "sha256:") {
		return fmt.Errorf("audit: policy id %q is not a sha256 digest", e.PolicyID)
	}
	if len(e.Detail) > 0 {
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(e.Detail, &obj); err != nil || obj == nil {
			return errors.New("audit: detail is not a JSON object")
		}
	}
	return nil
}

// LifecycleDetail goes with sandbox_created, sandbox_closed,
// sandbox_rejected and enforcement_lost.
type LifecycleDetail struct {
	Backend  string `json:"backend,omitempty"`
	ThreadID string `json:"thread_id,omitempty"`
	// Agent and Project say whose run it is, on sandbox_created and
	// sandbox_rejected: the agent (a runner deployment's name) and the
	// project it worked on, when it had one.
	Agent   string `json:"agent,omitempty"`
	Project string `json:"project,omitempty"`
	// ExitCode, on sandbox_closed, is how the agent's command ended.
	ExitCode *int   `json:"exit_code,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

// NetworkDetail goes with network_allowed and network_blocked. Destination
// is the name (or address) the sandbox asked for.
type NetworkDetail struct {
	Destination string `json:"destination"`
	Port        int    `json:"port,omitempty"`
	Protocol    string `json:"protocol,omitempty"`
	Reason      string `json:"reason,omitempty"`
}

// ReasonOutsideAllowlist, on a network_allowed, marks a connection the run's
// allowlist does not grant, let through because the allowlist was only being
// reported on (egress.Config.ReportOnly): what enforcing it would refuse.
const ReasonOutsideAllowlist = "outside_allowlist"

// ResourceDetail goes with resource_limit_hit.
type ResourceDetail struct {
	Resource string `json:"resource"` // memory, cpu, pids, disk, output_bytes, timeout
	Limit    int64  `json:"limit,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

// ModelDetail goes with credential_injected and the model_* types except
// model_usage. It names the provider route, never the credential.
type ModelDetail struct {
	Provider string `json:"provider"`
	Reason   string `json:"reason,omitempty"`
	// Metering, on model_forwarded, is how the call's use is recorded
	// (MeteringLedger, MeteringBroker, MeteringNone): the evidence a reader
	// should expect for it. Empty on events from writers that predate it.
	Metering string `json:"metering,omitempty"`
	// RequestID, on model_forwarded, names the call: the broker's own id,
	// also sent to a ledger upstream and repeated on its model_usage, so
	// each call can be matched rather than counted.
	RequestID string `json:"request_id,omitempty"`
	// Path, on model_denied and model_limit_hit, is the URL path the
	// refused request asked for (no query string; broker.OnRefuse), and
	// Reason why it was refused (broker.Refuse* values).
	Path string `json:"path,omitempty"`
}

// Metering modes: where a forwarded model call's use is recorded.
const (
	// MeteringLedger: by ledger-gate, which the call went through; a
	// ledger row carries the run (and request) id.
	MeteringLedger = "ledger"
	// MeteringBroker: by the broker, which read the usage from the
	// response and wrote a model_usage event.
	MeteringBroker = "broker"
	// MeteringNone: nowhere. The call is on record, its use is not; the
	// run's policy said so before it started.
	MeteringNone = "none"
)

// ValidMetering reports whether m is a metering mode.
func ValidMetering(m string) bool {
	return m == MeteringLedger || m == MeteringBroker || m == MeteringNone
}

// UsageDetail goes with model_usage: what one call used, as the response
// reported it. Token counts only, never content.
type UsageDetail struct {
	RequestID string `json:"request_id"`
	Provider  string `json:"provider"`
	Model     string `json:"model,omitempty"`
	// InputTokens excludes the cache counts, as the providers report it.
	InputTokens      int64 `json:"input_tokens"`
	OutputTokens     int64 `json:"output_tokens"`
	CacheReadTokens  int64 `json:"cache_read_tokens,omitempty"`
	CacheWriteTokens int64 `json:"cache_write_tokens,omitempty"`
	// Billing is how the channel is paid for: BillingAPI (per token) or
	// BillingSubscription (flat rate; the tokens have no marginal cost).
	Billing string `json:"billing"`
	// Truncated: the response ended before its final usage report (a
	// stream cut short); the counts are what was seen.
	Truncated bool `json:"truncated,omitempty"`
}

// Billing of a model channel.
const (
	BillingAPI          = "api"
	BillingSubscription = "subscription"
)

// DroppedDetail goes with events_dropped. From FirstSequence on, the run's
// events may be missing: the numbers they used are gaps in the source's
// sequence.
type DroppedDetail struct {
	FirstSequence uint64 `json:"first_sequence"`
	Reason        string `json:"reason"`
	LimitBytes    int64  `json:"limit_bytes,omitempty"`
}
