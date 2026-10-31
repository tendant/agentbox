// Package capability is the shared vocabulary for what a sandbox enforces:
// versioned capability IDs, their definitions, and the result of checking a
// policy against a backend. Backends report against it, runners admit runs
// with it, and agent-gate's rules judge recorded runs by it.
//
// This package must not import an agentbox backend (gvisor, seatbelt).
package capability

import "slices"

// ID names one enforceable property in the versioned registry.
type ID string

const (
	FSDeny                   ID = "fs.deny"
	FSWriteScope             ID = "fs.write_scope"
	FSReadScope              ID = "fs.read_scope"
	FSPathVirtualization     ID = "fs.path_virtualization"
	EnvScrub                 ID = "env.scrub"
	ProcessContainment       ID = "process.containment"
	ProcessCrossRunIsolation ID = "process.cross_run_isolation"
	NetworkDirectNone        ID = "network.direct_none"
	NetworkOutbound          ID = "network.outbound"
	NetworkNoListen          ID = "network.no_listen"
	NetworkRestrictedEgress  ID = "network.restricted_egress"
	NetworkControlledDNS     ID = "network.controlled_dns"
	ResourceCPU              ID = "resource.cpu"
	ResourceMemory           ID = "resource.memory"
	ResourcePIDs             ID = "resource.pids"
	ResourceDisk             ID = "resource.disk"
	ResourceOutput           ID = "resource.output_bytes"
	ResourceTimeout          ID = "resource.timeout"
	DeadlineSurvivesRunner   ID = "resource.deadline_survives_runner"
	OrphanRecovery           ID = "runtime.orphan_recovery"
	KernelIsolation          ID = "kernel.isolation"
)

// RegistryVersion bumps whenever a capability's definition changes.
const RegistryVersion = 1

// Def is a precise definition. A backend may claim the capability only if
// every named conformance test passes.
type Def struct {
	ID          ID
	Description string
	Tests       []string
}

func def(id ID, desc string, tests ...string) Def {
	return Def{ID: id, Description: desc, Tests: tests}
}

// Registry is the one source of capability definitions.
var Registry = func() map[ID]Def {
	m := map[ID]Def{}
	for _, d := range []Def{
		def(FSDeny, "denied paths are unreadable and unwritable, including via symlinks", "fs.ssh_unreadable", "fs.symlink_escape"),
		def(FSWriteScope, "writes succeed only under granted writable paths", "fs.no_write_outside_workspace"),
		def(FSReadScope, "reads succeed only under granted paths and the system paths programs need", "fs.read_scope"),
		def(FSPathVirtualization, "sandbox sees logical roots (/workspace) rather than host paths", "fs.virtual_paths"),
		def(EnvScrub, "inherited env is allowlisted; credentials are not passed", "env.no_credentials"),
		def(ProcessContainment, "all descendants die at teardown, including daemonized children", "proc.daemon_killed"),
		def(ProcessCrossRunIsolation, "one run cannot signal another run's processes", "proc.cross_run_signal"),
		def(NetworkDirectNone, "no direct network, including loopback to host services, raw IPs and metadata endpoints", "net.none_loopback", "net.none_raw_ip", "net.none_metadata"),
		def(NetworkOutbound, "outbound connections allowed", "net.outbound_connect"),
		def(NetworkNoListen, "nothing outside the sandbox can connect to a listener in it", "net.no_listen"),
		def(NetworkRestrictedEgress, "egress limited to granted hosts/CIDRs via a gateway behind default-deny networking", "net.restricted_allow", "net.restricted_deny"),
		def(NetworkControlledDNS, "name resolution is served by the runner and honours egress policy", "net.controlled_dns"),
		def(ResourceCPU, "CPU capped", "res.cpu"),
		def(ResourceMemory, "memory capped and OOM reported", "res.memory"),
		def(ResourcePIDs, "process count capped", "res.pids"),
		def(ResourceDisk, "writable disk usage capped", "res.disk"),
		def(ResourceOutput, "captured output capped", "res.output"),
		def(ResourceTimeout, "wall timeout: TERM, grace, KILL", "res.timeout"),
		def(DeadlineSurvivesRunner, "deadline is enforced even if the runner dies", "res.deadline_runner_crash"),
		def(OrphanRecovery, "sandboxes orphaned by a crash are reaped without touching live runners", "rt.orphan_recovery"),
		def(KernelIsolation, "syscalls served by a user-space kernel", "kernel.isolation"),
	} {
		m[d.ID] = d
	}
	return m
}()

// IDs returns all registered IDs, sorted.
func IDs() []ID {
	out := make([]ID, 0, len(Registry))
	for id := range Registry {
		out = append(out, id)
	}
	slices.Sort(out)
	return out
}

// Gap is a required capability the backend cannot enforce.
type Gap struct {
	Capability ID     `json:"capability"`
	Reason     string `json:"reason,omitempty"`
}

// CheckResult is what a backend enforces for one policy: the capabilities
// it enforces, the required ones it does not (Gaps), and caveats.
type CheckResult struct {
	Backend  string   `json:"backend"`
	Enforced []ID     `json:"enforced"`
	Gaps     []Gap    `json:"gaps,omitempty"`
	Caveats  []string `json:"caveats,omitempty"`
}

// Evaluate computes required minus enforced. Enforced comes back sorted and
// deduplicated; gaps follow the order of required.
func Evaluate(backend string, required, enforced []ID, caveats []string) CheckResult {
	have := map[ID]bool{}
	for _, c := range enforced {
		have[c] = true
	}
	res := CheckResult{Backend: backend, Caveats: caveats}
	for c := range have {
		res.Enforced = append(res.Enforced, c)
	}
	slices.Sort(res.Enforced)
	for _, c := range required {
		if !have[c] {
			res.Gaps = append(res.Gaps, Gap{Capability: c, Reason: "not enforced by backend"})
		}
	}
	return res
}
