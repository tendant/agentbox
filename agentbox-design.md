# Agentbox — Technical Design

**Status:** Proposed v1  
**Language:** Go  
**Repository:** `github.com/tendant/agentbox`
**Primary backend:** Direct gVisor (`runsc`)  
**Future backend:** Firecracker

## 1. Purpose

Agentbox is a small, reusable execution library for running untrusted agent-generated commands in isolated sandboxes on Linux. It is independent of agent orchestration and does not require Docker, Podman, or containerd.

**Core invariant:** The caller decides the requested permissions; Agentbox validates and enforces them. Unsupported or unverifiable requirements **fail closed**. The host/operator also sets non-overridable maximum permissions.

## 2. Scope

### v1
- Linux production; macOS development through a Linux VM.
- Direct `runsc` lifecycle: create, start, exec, stop, delete.
- Persistent sandbox for multiple commands during one agent execution.
- Immutable base rootfs, explicit read-only mounts, writable workspace and temporary storage
  (rootfs source: see §6 Filesystem).
- Default-deny network; no networking required for initial MVP, **except the model channel**
  (§6 Network): an agent CLI cannot work without reaching its model.
- CPU, memory, PID, disk and time limits where enforcement is verified.
- Leases, cancellation, orphan cleanup and structured logs.
- Backend capability checks and real conformance tests.

### Non-goals
- Writing a container runtime, Linux namespace manager, or VM hypervisor.
- Kubernetes scheduling, distributed orchestration, snapshots, UI, or Windows support.
- Firecracker implementation in v1.
- Claiming that rootless execution works without host-specific verification.

## 3. Architecture

```text
agent-runner (policy decision, agent lifecycle, credential broker)
      |
      | Go API: immutable sandbox spec
      v
agentbox (policy validation, capability checks, leases)
      |
      v
backend/gvisor (OCI bundle, runsc lifecycle, host setup)
      |
      v
gVisor sandbox (agent commands, isolated filesystem/processes)

Future: backend/firecracker -> microVM + guest exec agent
```

Agentbox runs as a Go library initially. A separate `agentboxd` worker and authenticated remote API can be added if deployment or privilege separation demands it. **A separate repository is not itself a security boundary.**

## 4. Public API

```go
type Backend interface {
    Capabilities(ctx context.Context) (Capabilities, error)
    Create(ctx context.Context, spec Spec) (Sandbox, error)
}

type Sandbox interface {
    ID() string
    Exec(ctx context.Context, cmd Command) (Result, error)
    Close(ctx context.Context) error
}
```

`Spec` contains: sandbox ID, pinned rootfs/image reference, workspace, explicit filesystem grants, network policy, CPU/memory/PID/disk limits, execution deadline and lease. The caller cannot inject arbitrary `runsc` flags, host paths, OCI configuration, or environment secrets.

`Exec` must support bounded stdout/stderr, exit status, cancellation and timeout. Concurrent exec semantics must be defined explicitly (v1 may serialize commands).

## 5. Direct gVisor backend

1. Validate and normalize the requested policy against the worker maximum.
2. Check runtime/host capabilities; reject unsupported restrictions.
3. Prepare a trusted rootfs, workspace and approved mount sources.
4. Generate a restrictive OCI bundle (`config.json`, rootfs) with explicit namespaces, mounts, process identity and security settings.
5. Invoke `runsc` to create/start the sandbox, then `runsc exec` for subsequent commands.
   Rootless `runsc` refuses `create` and stops a `run --detach` sandbox at once (Phase 0):
   agentbox keeps a foreground `runsc run` alive for the sandbox's lifetime (a small monitor,
   like Podman's `conmon`) and `exec`s into it; the monitor also owns cleanup.
6. Enforce resource and network controls using verified host/runtime mechanisms.
7. On close/expiry/crash recovery, terminate processes, delete runtime state and clean owned resources.

Do not assume `runsc` alone provisions networking, delegated cgroups, image extraction, disk quotas or rootless mounts. Those are host integration tasks.

## 6. Security model

### Filesystem
- Read-only root filesystem; writable `/workspace` and size-limited `/tmp`.
- Explicit allowlisted host mounts only; reject traversal and symlink-based escapes.
- No Docker/containerd sockets, SSH keys, host `/proc` or `/sys`, cloud credentials, or service-account tokens.
- Validate mount source paths safely at creation time; guard against path substitution races.
- **Rootfs source** (open decision 4): either (a) a built, pinned image containing the toolchain
  agents need (node, the agent CLIs, git, compilers), or (b) read-only binds of the host's system
  paths (`/usr`, `/etc`, `/lib*`, `/opt`), as isobox does. (b) needs no image pipeline but must:
  - recreate the host's top-level symlinks in the view (`/bin -> usr/bin`, `/sbin`, `/lib64` on
    usrmerge distributions). *Lesson:* isobox's scoped gVisor view lost `/bin`, so every
    `#!/bin/sh` and `#!/bin/bash` script failed to start (fixed in the tendant/isobox fork,
    `2145756`);
  - grant agent CLIs installed under a home directory (npm prefix, nvm, `~/.local`) explicitly,
    never the home directory itself.
- **System secrets stay unreadable:** `/etc/shadow`, `/etc/gshadow`, sudoers, SSH host keys. A
  sandbox whose identity maps to host root reads root-owned files; denying them is a backstop
  even when §6 Identity keeps the agent non-root.

### Identity and privileges
- Run agent commands as a non-root identity with no unnecessary capabilities.
- **Files the agent writes must belong to the caller** (the runner commits, pushes and deletes
  them). With rootless `runsc` this holds by itself: the sandbox's root is the caller on the host,
  and the gofer runs as the caller, so root-owned host files stay unreadable by ordinary
  permissions (Phase 0). Run commands as uid 0 inside and declare no user namespace in the OCI
  spec; mapping a non-zero uid made the gofer fail (`fork/exec /proc/self/exe: EPERM`).
  *Lesson:* isobox runs gVisor sandboxes as uid 0, so workspace files come out owned by root,
  and a non-root runner cannot clean them up. With rootless `runsc`, an unmapped non-root uid lands
  in a subordinate uid range instead, owned by neither the runner nor root.
- A directory the agent must reach is reachable only if every parent is traversable for that
  identity. *Lesson:* a 0750 home hid the runner's data dir from a uid-0, capability-less gVisor
  sandbox; agent-runner now rejects such runs naming the directory.
- Disallow privilege escalation and host namespace sharing.
- Verify unprivileged user namespace availability and selected gVisor platform support.
- Rootless is a **deployment qualification**, not a blanket promise. A privileged worker, if introduced, must be isolated from the agent orchestration process.

### Network
- **v1 default:** no network access, except the model channel:
  - the host-side model proxy (credential broker) listens on a Unix socket bind-mounted into the
    sandbox, and a small forwarder inside gives the CLIs the `http://127.0.0.1:<port>` base URL
    they expect (claude: `ANTHROPIC_BASE_URL`; codex: a custom provider; pi: `models.json`);
  - candidate mechanism: `runsc --host-uds=open` for connecting to a mounted host socket.
    **Phase 0 must verify** it works with rootless `runsc` and network `none`;
  - the proxy attaches the real credential per request (an API key, a `claude setup-token`, or a
    refreshing codex ChatGPT login) and the sandbox gets only a per-run token. agent-runner already
    implements and tests this over TCP (`internal/sandbox/proxy`, `internal/sandbox/codexlogin`).
- Without network, `git push`, `npm install`, `pip install` and web lookups fail inside the
  sandbox: v1 suits tasks that don't need them, or the runner does those steps outside.
- Future restricted egress: proxy-only path with enforceable prevention of direct-IP, DNS, IPv6 and metadata-service bypass.
- Define hostname wildcard and CIDR containment semantics. Authorization is evaluated on actual destination resolution/connect behavior, not just the requested hostname.
- Keep LLM/API credentials outside the sandbox via a host-side broker.

### Resources and lifecycle
- Use cgroup v2 for CPU, memory and PID limits when controllers are available/delegated.
  - Rootless `runsc` is expected to run without managing cgroups itself (`--ignore-cgroups`).
    Candidate: start it inside a delegated systemd user scope
    (`systemd-run --user --scope -p MemoryMax=… -p TasksMax=… -p CPUQuota=…`), so the scope's
    limits contain the whole sandbox. **Phase 0 must verify** both, or creation must be rejected
    (per the next rules) whenever limits are required.
  - *Lesson:* isobox's `--pids` set `pids.max` on the cgroup holding runsc's own host threads:
    small values stopped runsc from starting, and a fork bomb crashed runsc instead of failing
    `fork()`. `RLIMIT_NPROC` inside gVisor did contain a fork bomb (EAGAIN, sandbox alive).
    A scope's `TasksMax` counts runsc's threads too, so test the actual limiter against a fork
    bomb, not just its configuration.
- Enforce disk usage through a real quota/size-limited filesystem, not a config field alone.
- Apply execution deadlines and leases; terminate the entire sandbox on expiry.
- Reject creation when required resource controls cannot be proven active.

## 7. Backend capability contract

Capabilities describe **verified enforceable behavior**, not only supported configuration syntax. Policy narrowing uses semantic containment (for example, `10.1.0.0/16` is within `10.0.0.0/8`). No silent fallback to weaker isolation. Report the effective enforcement configuration for audit/debugging without exposing secrets.

## 8. Conformance suite

Run real instances against each supported host/runtime combination:

| Category | Required checks |
|---|---|
| Filesystem | Read SSH keys, write outside workspace, symlink/mount escape |
| Network | Metadata IP, unauthorized host/IP, DNS exfiltration, IPv6 bypass |
| Process | Inspect sibling processes, `/proc/*/environ`, ptrace, listener creation |
| Resources | Fork bomb, excessive memory, disk exhaustion, CPU throttling |
| Lifecycle | Cancellation, timeout, orphan/daemon cleanup, repeated exec |
| Policy | Unsupported controls rejected; child permissions semantically contained |

Also required, from problems found with isobox:

| Category | Check |
|---|---|
| Filesystem | `/etc/shadow` and SSH host keys unreadable; host home and another project invisible (not merely unreadable) |
| Filesystem | a `#!/bin/sh` script and a home-installed npm CLI start under the scoped rootfs |
| Identity | a file the agent creates in the workspace is owned by the caller's uid |
| Resources | fork bomb against the real limiter: `fork()` fails, the sandbox and host survive, cleanup completes |
| Model channel | the CLI reaches the model through the proxy; the real credential never appears in the sandbox's env or files |

**Seed suite:** port agent-runner's existing probes
(`internal/sandbox/conformance`, `scripts/sandbox-smoke`): SSH key, symlink escape, write outside
the workspace, read scope, metadata IP, loopback, raw IP, listeners, daemon cleanup, cross-run
signals, timeout, memory and pids caps, both fork bombs, and codex on a ChatGPT login through the
proxy against a fake backend.

Mark network-specific tests as **not applicable only when networking is entirely disabled and that denial is verified**. Do not treat a skipped required capability as a pass.

## 9. Repository layout

```text
agentbox/
├── cmd/agentbox/             # Local CLI / smoke testing
├── pkg/agentbox/             # Public Go API
├── internal/
│   ├── policy/               # Validation, narrowing, capabilities
│   ├── backend/
│   │   ├── backend.go
│   │   └── gvisor/            # OCI preparation and runsc lifecycle
│   ├── filesystem/
│   ├── resources/
│   ├── network/
│   ├── lease/
│   └── conformance/
├── testdata/
├── docs/
└── go.mod
```

Keep agent-specific policy decisions in `agent-runner`; keep enforcement contracts and conformance in Agentbox.

## 10. Implementation plan

### Phase 0 — Host feasibility (1–3 days)
- Validate `runsc` on the actual Linux host as an unprivileged user.
- Check user namespaces, filesystem mounts, cgroup delegation, runtime platform and cleanup.
- Specifically: the uid mapping (§6 Identity), limits through a systemd user scope (§6 Resources),
  the model channel over a mounted Unix socket (§6 Network), and a fork bomb against the limiter.
- An early signal is possible on macOS: rootless `runsc` in a Linux container as a non-root user
  with user namespaces allowed. It does not replace the check on the production host.
- **Go/no-go:** create, exec and delete a rootless, network-disabled sandbox reliably.

### Phase 1 — Execution MVP (3–7 days)
- Create Go API, OCI bundle generator, `runsc` backend.
- Support persistent create/exec/close, read-only rootfs, writable workspace, output and cancellation.
- Integrate one command path from `agent-runner`.

### Phase 2 — Enforcement and conformance (1–2 weeks)
- Add validated mount policy, identity restrictions, resource controls, leases and orphan cleanup.
- Port existing conformance tests; fail closed for unmet requirements.
- Validate Linux production and macOS VM development workflows.

### Phase 3 — Restricted networking (1–2+ weeks)
- Design proxy-only networking and host/CIDR policy semantics.
- Verify DNS, IPv4/IPv6, direct-IP and metadata bypass prevention.
- Keep networking disabled until all relevant tests pass.

### Phase 4 — Production qualification (1–2+ weeks)
- Stress tests, crash recovery, runtime upgrade tests, metrics, log limits and threat-model review.
- Decide whether a dedicated sandbox worker/service is required.

### Phase 0 results so far (2026-10-11)

`scripts/phase0.sh` runs every check as a normal user; `scripts/phase0-docker.sh` runs it in an
Ubuntu 24.04 container on a Mac (runsc `20261005.0`, arm64, seccomp/AppArmor unconfined, not
privileged). All pass there:

- unprivileged user namespaces, cgroup v2, `runsc --rootless do`;
- a persistent sandbox through a held `runsc run` with repeated `exec`, then delete with no
  processes left (`create` is not supported rootless; `run --detach` stops at once);
- a rootfs of read-only host binds with the usrmerge symlinks recreated: `#!/bin/sh` starts;
- workspace files owned by the caller; `/etc/shadow` unreadable; no network;
- a fork bomb contained by `process.rlimits` `RLIMIT_NPROC`, the sandbox alive;
- the model channel: a host Unix socket mounted in, reached with `--host-uds=open`.

Not testable in a container: limits through a systemd user scope.

**Production host — GO (2026-10-11).** Ubuntu 24.04.3, kernel 6.8.0-142, x86_64, as `ubuntu`
(1000), with `scripts/install-runsc.sh` (runsc in `/usr/local/bin` and the `agentbox-runsc`
AppArmor profile that Ubuntu's `apparmor_restrict_unprivileged_userns=1` requires). Every check
above passes there too, and the scope checks:

- a sandbox runs inside `systemd-run --user --scope` (MemoryMax=1G, TasksMax=512);
- memory past `MemoryMax=512M` ends the sandbox (exit 137), nothing left behind;
- a fork bomb with `TasksMax=256` as the **only** limiter ends the sandbox (exit 2) instead of
  failing `fork()`: the cap counts runsc's own threads, as isobox's `--pids` did.

**Limiter decision:** `RLIMIT_NPROC` in the OCI spec is the per-sandbox process limit (graceful:
`fork()` fails, the sandbox survives); the scope's `MemoryMax` and `CPUQuota` cap memory and CPU;
`TasksMax` stays a generous host backstop (thousands), never the policy limit.

**Transparent egress — GO (2026-10-11).** For programs that ignore `HTTPS_PROXY`:
`scripts/phase0-transparent.sh` makes a private user + network namespace as the runner's user,
redirects all TCP (nftables `redirect`) to a local catcher and UDP 53 to a local DNS responder,
and runs `runsc --rootless --network=host` inside it. On the production host, with the namespace
made by `agentbox-unshare` (a root-owned copy of `unshare` with its own AppArmor profile, installed
by `scripts/install-runsc.sh`), and in the container, all pass:

- TCP to any address from inside gVisor is caught, with its original destination
  (`SO_ORIGINAL_DST`) recovered;
- the TLS server name is read from the ClientHello, so host allowlists apply to HTTPS;
- DNS queries are answered by the local responder;
- the catcher reaches the gateway's Unix socket outside the namespace.

`runsc` without `--rootless` (root in the user namespace) fails to set up host networking there;
agentbox does not use it.

**Rough estimate:** 1–2 weeks for a no-network internal MVP after host feasibility; 4–8+ weeks for a hardened single-host deployment with controlled egress. These are planning estimates, not security certification.

## 11. Firecracker future backend

Firecracker can be integrated directly through its API socket, but needs kernel/rootfs artifacts, host KVM/TAP setup, a guest agent for repeated `exec`, workspace transfer/sharing, and VM cleanup. It is **not** a drop-in `runsc` replacement. Add only after the gVisor backend contract and conformance suite stabilize, or if the threat model requires a VM boundary sooner.

## 12. Open decisions

1. Can the production host satisfy direct **rootless `runsc`** requirements, including cgroups and mounts?
2. What is the trust model: one tenant per host, or mutually untrusted tenants sharing a host?
3. Is no-network execution (plus the model channel) sufficient for v1, or is restricted egress
   mandatory? Agents that `git push` or install packages need egress or a runner-side step.
4. How will trusted rootfs images and workspace disk quotas be provisioned?
5. When does a separate sandbox worker become necessary for privilege separation?

**Decision:** Prototype direct gVisor first. Do not add Podman/containerd unless host integration cost or reliability justifies them; do not build Firecracker support before a concrete need.
