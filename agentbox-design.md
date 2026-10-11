# Agentbox — Design

**Status:** Draft 0.1  
**Language:** Go  
**Repository:** `github.com/tendant/agentbox`

## 1. Purpose

Agentbox is a reusable, server-side sandbox execution service for untrusted AI-agent commands and generated code. It is independent of `agent-runner` and can support other workloads.

**Core invariant:** The caller decides what is authorized; Agentbox enforces the requested restrictions within worker-side maximum permissions. Backends advertise capabilities, and any unsupported restriction fails closed.

## 2. Goals and non-goals

**Goals**
- Isolate filesystem, processes, network, credentials, and resources.
- Create a sandbox once and execute multiple commands within it.
- Support leases, cancellation, reliable cleanup, and crash recovery.
- Expose a small Go client and gRPC API; use a Unix socket initially.
- Verify security behavior with backend-independent conformance tests.
- Start with gVisor on Linux; keep room for a future microVM backend.

**Non-goals (v1)**
- Agent orchestration, LLM calls, or agent-specific authorization decisions.
- Arbitrary host mounts, unrestricted networking, or Docker socket access.
- Multi-host scheduling, Kubernetes operators, or Windows/macOS support.
- Claiming VM-grade isolation from a container sandbox.

## 3. Architecture

```text
agent-runner (policy decisions, agent lifecycle)
       |
       | Agentbox Go client / gRPC (Unix socket initially)
       v
agentboxd (authentication, admission, leases, audit)
       |
       +-- policy validation + capability negotiation
       +-- filesystem / network / resource preparation
       +-- sandbox lifecycle manager
       |       |
       |       +-- gVisor backend (v1; runsc/containerd integration)
       |       +-- microVM backend (future)
       +-- conformance suite (CI and deployment qualification)
       |
       v
isolated sandbox (persistent for one agent execution)
```

The worker runs on dedicated Linux hosts. `agent-runner` does not need runtime privileges. Any privileged host setup is restricted to the worker deployment. Rootless operation is a **validation target**, not an assumed property: user namespaces, cgroup delegation, networking, and gVisor configuration must be tested together.

## 4. Trust boundaries

1. **Agent-runner → Agentbox:** Authenticated caller; worker applies its own admission limits. The caller cannot grant itself arbitrary host access.
2. **Agentbox → sandbox:** Untrusted code cannot access host files, credentials, sockets, or sibling sandboxes.
3. **Sandbox → network:** Default deny. Permitted traffic traverses an enforcement point that cannot be bypassed with raw IP, alternate DNS, or IPv6.
4. **Sandbox → model/tool APIs:** Secrets remain outside the sandbox; a credential-aware proxy mediates authorized requests.

Do not expose container runtime sockets, host PID namespaces, host `/proc`, cloud metadata, or ambient service-account credentials.

## 5. Policy contract

The runner resolves agent-level permissions into a concrete `SandboxSpec`. Agentbox validates the spec against its own ceiling and backend capabilities, then compiles it into enforcement configuration.

```go
type SandboxSpec struct {
    ID        string
    Image     string // pinned immutable image/digest
    ReadOnly  []MountGrant
    Writable  []MountGrant
    Network   NetworkPolicy
    Resources ResourceLimits
    LeaseTTL  time.Duration
}

type MountGrant struct {
    Source string // worker-managed approved source; never arbitrary host path
    Target string
}

type NetworkPolicy struct {
    Egress       bool
    AllowedHosts []string
    AllowedCIDRs []string
    Listen       bool
}

type ResourceLimits struct {
    MemoryBytes int64
    CPUQuota    float64
    MaxPIDs     int
    DiskBytes   int64
    ExecTimeout time.Duration
}
```

**Policy rules**
- Deny by default; no implicit widening when a field is omitted.
- Reject unsupported capabilities instead of silently ignoring them.
- A child grant must be a **semantic subset** of the parent grant (e.g. `10.1.0.0/16` is within `10.0.0.0/8`). Define wildcard hostname semantics explicitly.
- Filesystem paths must be canonicalized and checked against symlink and mount escape; only approved worker-managed sources may be mounted.
- Validate effective runtime configuration, not merely requested flags.
- Version the API and capability schema; reject incompatible major versions.

## 6. API and lifecycle

Minimal RPC surface:

```protobuf
service Agentbox {
  rpc Create(CreateRequest) returns (CreateResponse);
  rpc Exec(ExecRequest) returns (stream ExecEvent);
  rpc RenewLease(RenewLeaseRequest) returns (RenewLeaseResponse);
  rpc Inspect(InspectRequest) returns (InspectResponse);
  rpc Destroy(DestroyRequest) returns (DestroyResponse);
}
```

Lifecycle: `Creating → Ready → Running ↔ Ready → Stopping → Destroyed` (or `Failed`). `Create` and `Destroy` must be idempotent by request/sandbox ID. `Exec` streams stdout, stderr, exit status, and bounded diagnostics; cancellation terminates the process tree. An expired lease destroys the sandbox. On daemon restart, reconcile runtime state and clean orphaned resources.

Each sandbox belongs to one execution/tenant context; never recycle a live sandbox across tenants. Multiple commands may share its workspace until destruction.

## 7. Enforcement design

| Boundary | Mechanism | Acceptance condition |
|---|---|---|
| Host kernel | gVisor (`runsc`) | No direct host kernel access beyond supported runtime boundary |
| Filesystem | Immutable rootfs, explicit mounts, writable workspace/tmp | No unauthorized read/write or symlink escape |
| Network | Isolated networking + forced egress proxy/firewall | No direct-IP, DNS, IPv6, or metadata bypass |
| Credentials | Host-side broker/model proxy | No raw secrets in sandbox environment or filesystem |
| CPU, memory, PIDs | cgroup v2 with verified delegation | Hard limits enforced; fail closed if unavailable |
| Disk | Quota/size-limited writable storage | Disk-fill contained |
| Lifetime | Lease, deadline, kill/reap, reconciliation | No persistent child process after destroy |

A hostname-only CONNECT allowlist is insufficient: resolve and validate destinations at the proxy, including private/link-local ranges, and prevent rebinding and direct egress.

## 8. Backend contract

```go
type Backend interface {
    Name() string
    Capabilities(ctx context.Context) (Capabilities, error)
    Create(ctx context.Context, spec SandboxSpec) (Sandbox, error)
}

type Sandbox interface {
    Exec(ctx context.Context, cmd Command) (ResultStream, error)
    Inspect(ctx context.Context) (Status, error)
    Destroy(ctx context.Context) error
}
```

`Capabilities` reports *verified enforceable* features and constraints. A backend may be admitted only after passing applicable conformance tests on the target host configuration. Start with one gVisor backend; do not pre-build Firecracker abstractions beyond this narrow interface.

## 9. Repository layout

```text
agentbox/
├── cmd/
│   ├── agentboxd/         # worker daemon
│   └── agentbox/          # local CLI / diagnostics
├── api/proto/             # versioned wire contract
├── pkg/client/            # public Go client
├── pkg/policy/            # public spec types + validation helpers
├── internal/
│   ├── server/            # auth, admission, RPC
│   ├── manager/           # lifecycle, leases, reconciliation
│   ├── backend/gvisor/    # first runtime adapter
│   ├── filesystem/
│   ├── network/
│   └── resources/
├── conformance/           # black-box security tests
├── examples/
└── docs/
```

## 10. Conformance and acceptance

Required negative tests: read `~/.ssh/id_rsa`; symlink escape; write outside workspace; access IPv4/IPv6 metadata addresses; non-allowlisted hostname; raw-IP egress; alternate DNS/DNS exfiltration; fork bomb; memory/disk exhaustion; unauthorized listener; sibling-process `ptrace`; host `/proc/*/environ`; daemon persistence after lease expiry. Include positive tests for explicitly permitted operations and nested policy narrowing.

A test passes only if the **actual operation is blocked or bounded** and cleanup is verified. CI must exercise real runtime instances, not only policy mocks. Record kernel, runtime, and host configuration for reproducibility.

## 11. Implementation plan

**M1 — Runtime proof of concept**
- Implement `Create`, `Exec`, `Destroy` against gVisor with a fixed image and network disabled.
- Stream output, support multiple execs, verify process cleanup.
- Decide direct `runsc` vs containerd based on rootless feasibility and lifecycle complexity.

**M2 — Enforcement**
- Implement policy validation and capability checks.
- Add controlled mounts, quotas/cgroups, leases, network default-deny and approved egress.
- Keep credentials in a host-side broker.

**M3 — Integration**
- Add `agentboxd` Unix-socket gRPC, Go client, authenticated admission, and structured audit logs.
- Integrate with `agent-runner`; preserve runner-side authorization.
- Add crash recovery, idempotency, and concurrency limits.

**M4 — Qualification**
- Run full conformance suite on target Linux hosts.
- Measure cold start, warm exec latency, CPU/memory overhead, and concurrency.
- Document deployment privileges and residual risks; release only after required controls pass.

## 12. Open decisions

1. **Runtime:** Direct `runsc` or containerd + gVisor? Prototype both before locking in.
2. **Privilege model:** Is a tightly controlled privileged worker acceptable, or must the entire worker be rootless?
3. **Network:** Which proxy/firewall design can prove no bypass on the deployment host?
4. **Persistence:** Is a sandbox scoped to a single agent execution or a longer-lived thread?
5. **Deployment:** Single worker host first, then dedicated worker pool as demand grows.

**Recommended v1:** Linux-only, gVisor, one sandbox per agent execution, default-deny networking, Unix-socket API, runner-owned authorization, worker-owned enforcement, and mandatory conformance gates.
