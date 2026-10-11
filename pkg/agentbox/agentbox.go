// Package agentbox runs untrusted agent-generated commands in isolated
// sandboxes on Linux. The caller decides what a sandbox may do (Spec);
// agentbox validates the request and enforces it, and fails closed when it
// cannot.
package agentbox

import (
	"context"
	"io"
	"os/exec"
	"time"
)

// Backend creates sandboxes. Capabilities reports what this host can
// actually enforce; Create rejects a Spec needing anything else.
type Backend interface {
	Capabilities(ctx context.Context) (Capabilities, error)
	Create(ctx context.Context, spec Spec) (Sandbox, error)
}

// Sandbox is one isolated environment that runs commands until Close.
// Commands share its filesystem; v1 runs them one at a time.
type Sandbox interface {
	ID() string
	Exec(ctx context.Context, cmd Command) (Result, error)
	Close(ctx context.Context) error
}

// Commander is implemented by sandboxes that can hand back an unstarted
// command, for callers that manage its stdio and lifetime themselves
// (streaming an agent CLI's output). cleanup must be called once the command
// has ended or been abandoned: it kills what is left of it inside the
// sandbox (its process group), which killing the returned process alone
// does not.
type Commander interface {
	Cmd(ctx context.Context, cmd Command) (c *exec.Cmd, cleanup func(), err error)
}

// Spec is what the caller asks for. Paths are host paths; everything not
// granted is absent from the sandbox.
type Spec struct {
	// ID names the sandbox: [a-zA-Z0-9_.-], unique among live sandboxes.
	ID string
	// Workspace is a host directory mounted read-write at /workspace and used
	// as the default working directory.
	Workspace string
	// ReadOnly and Writable mount more host paths. A Target defaults to the
	// Source path.
	ReadOnly []Mount
	Writable []Mount
	// Env is the base environment for every command (KEY=VALUE).
	Env []string
	// Network is "none" in v1.
	Network NetworkPolicy
	// ModelSocket, when set, is a host Unix socket the sandbox may connect to
	// at /run/agentbox/<its file name>: the credential broker's channel.
	ModelSocket string
	Limits      Limits
	// Lifetime ends the sandbox when exceeded (0: until Close).
	Lifetime time.Duration
}

// Mount maps a host path into the sandbox.
type Mount struct {
	Source string
	Target string
}

// NetworkPolicy selects the sandbox's network. v1 supports "none".
type NetworkPolicy struct {
	Mode string
}

// NetworkNone is the only v1 network mode.
const NetworkNone = "none"

// Limits are hard caps; a zero field means "not requested".
type Limits struct {
	MemoryBytes int64   // the whole sandbox (systemd scope MemoryMax)
	CPUs        float64 // CPU time, in cores (scope CPUQuota)
	PIDs        int64   // processes and threads inside (RLIMIT_NPROC)
}

// Command is one process to run in a sandbox.
type Command struct {
	Args    []string
	Env     []string // added to Spec.Env; later entries win
	Dir     string   // default /workspace
	Stdin   io.Reader
	Stdout  io.Writer
	Stderr  io.Writer
	Timeout time.Duration // 0: until ctx ends
}

// Result is how a command ended.
type Result struct {
	ExitCode int
	TimedOut bool
}

// Capabilities are what a backend verified on this host.
type Capabilities struct {
	Backend     string
	Rootless    bool
	NetworkNone bool
	ModelSocket bool
	MemoryLimit bool
	CPULimit    bool
	PIDLimit    bool
	Persistent  bool // several Execs per sandbox
	Notes       []string
}
