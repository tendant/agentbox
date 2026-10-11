// Package seatbelt is agentbox's macOS backend: every command runs under
// sandbox-exec with a profile built from the Spec. It is weaker than gVisor,
// and says so in its Capabilities:
//
//   - commands run on the host's kernel (no KernelIsolation);
//   - the sandbox shares the host's network stack: Network "none" denies all
//     sockets except HostPorts on the loopback; no NetworkGateway, no
//     ModelSockets;
//   - mounts cannot move paths: a mount's Target must be its Source, and
//     /workspace is not a path inside (Command.Dir defaults to Workspace);
//   - no limits: macOS has no per-sandbox memory, CPU or process cap
//     (RLIMIT_NPROC counts all of the user's processes);
//   - containment: a timeout or cleanup kills the command's process group;
//     Close also kills every process of the user still running under this
//     sandbox's profile, daemons that left the group (setsid) included
//     (sandbox_check, with cgo; without, the process groups only).
//
// Reads are an allowlist (system paths, the workspace and mounts), writes
// are the workspace, writable mounts and a private TMPDIR, Deny wins over
// both, Mach lookups are limited to a few services (no keychain, no DNS),
// and signals cannot leave the sandbox.
package seatbelt

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/tendant/agentbox/pkg/agentbox"
)

// Config configures the backend.
type Config struct {
	// StateDir holds each sandbox's profile and TMPDIR; private to the
	// caller (default: os.TempDir()/agentbox).
	StateDir string
	// SandboxExec is the sandbox-exec binary (default /usr/bin/sandbox-exec).
	SandboxExec string
	// MachAllow are Mach services allowed besides agentbox's own short list.
	MachAllow []string
}

// Backend creates Seatbelt sandboxes.
type Backend struct{ cfg Config }

// New returns a backend.
func New(cfg Config) *Backend {
	if cfg.StateDir == "" {
		cfg.StateDir = filepath.Join(os.TempDir(), "agentbox")
	}
	if cfg.SandboxExec == "" {
		cfg.SandboxExec = "/usr/bin/sandbox-exec"
	}
	return &Backend{cfg: cfg}
}

// Capabilities checks that sandbox-exec works here.
func (b *Backend) Capabilities(ctx context.Context) (agentbox.Capabilities, error) {
	c := agentbox.Capabilities{Backend: "seatbelt"}
	if runtime.GOOS != "darwin" {
		c.Notes = append(c.Notes, "Seatbelt runs on macOS only")
		return c, nil
	}
	if out, err := exec.CommandContext(ctx, b.cfg.SandboxExec, "-p", "(version 1)(allow default)", "/usr/bin/true").CombinedOutput(); err != nil {
		c.Notes = append(c.Notes, "sandbox-exec does not work: "+strings.TrimSpace(string(out)))
		return c, nil
	}
	c.Rootless, c.NetworkNone, c.HostPorts, c.Persistent = true, true, true, true
	c.Notes = append(c.Notes, "Seatbelt: the host's kernel and network stack, no memory/CPU/process limits")
	if !membersByProfile {
		c.Notes = append(c.Notes, "built without cgo: a process that leaves its process group (setsid) outlives Close")
	}
	return c, nil
}

// sandbox is a profile and a TMPDIR; each command is its own sandbox-exec.
type sandbox struct {
	b       *Backend
	spec    agentbox.Spec
	dir     string
	tmp     string
	profile string
	mu      sync.Mutex
	closed  bool
	running map[*exec.Cmd]bool
	once    sync.Once
	timer   *time.Timer
}

// Create validates spec and writes the sandbox's profile.
func (b *Backend) Create(ctx context.Context, spec agentbox.Spec) (agentbox.Sandbox, error) {
	if runtime.GOOS != "darwin" {
		return nil, errors.New("agentbox: the seatbelt backend runs on macOS only")
	}
	spec, err := spec.Normalize()
	if err != nil {
		return nil, err
	}
	for _, m := range append(slices.Clone(spec.ReadOnly), spec.Writable...) {
		if t, _ := filepath.EvalSymlinks(m.Target); m.Target != m.Source && t != m.Source {
			return nil, fmt.Errorf("agentbox: seatbelt cannot mount %s at %s: paths stay where they are", m.Source, m.Target)
		}
	}
	switch {
	case spec.Network.Mode != agentbox.NetworkNone:
		return nil, errors.New("agentbox: seatbelt has no gateway network (the host's stack is shared): use HostPorts")
	case len(spec.ModelSockets) > 0:
		return nil, errors.New("agentbox: seatbelt does not mount sockets: use HostPorts")
	case spec.Limits != (agentbox.Limits{}):
		return nil, errors.New("agentbox: seatbelt has no memory, CPU or process limits (fail closed)")
	}
	if err := os.MkdirAll(filepath.Join(b.cfg.StateDir, "sandboxes"), 0o700); err != nil {
		return nil, err
	}
	dir := filepath.Join(b.cfg.StateDir, "sandboxes", spec.ID)
	if err := os.Mkdir(dir, 0o700); err != nil {
		if os.IsExist(err) {
			return nil, fmt.Errorf("agentbox: sandbox %q already exists", spec.ID)
		}
		return nil, err
	}
	dir, _ = filepath.EvalSymlinks(dir) // Seatbelt matches resolved paths (/var -> /private/var)
	tmp := filepath.Join(dir, "tmp")
	if err := os.Mkdir(tmp, 0o700); err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	var sys []string
	for _, p := range systemReadable {
		if r, err := filepath.EvalSymlinks(p); err == nil {
			sys = append(sys, r)
		}
	}
	prof := filepath.Join(dir, "profile.sb")
	if err := os.WriteFile(prof, []byte(profile(spec, sys, tmp, b.cfg.MachAllow)), 0o600); err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	s := &sandbox{b: b, spec: spec, dir: dir, tmp: tmp, profile: prof, running: map[*exec.Cmd]bool{}}
	if spec.Lifetime > 0 {
		s.timer = time.AfterFunc(spec.Lifetime, func() { s.Close(context.Background()) })
	}
	return s, nil
}

func (s *sandbox) ID() string { return s.spec.ID }

// env is the command's environment: the spec's, the command's (later wins),
// a TMPDIR inside the sandbox and a PATH if none was given.
func (s *sandbox) env(extra []string) []string {
	m := map[string]string{}
	var keys []string
	for _, e := range append(append(slices.Clone(s.spec.Env), extra...), "TMPDIR="+s.tmp+"/") {
		k, v, _ := strings.Cut(e, "=")
		if k == "TMPDIR" && m[k] != "" {
			continue // the caller's own TMPDIR wins
		}
		if _, ok := m[k]; !ok {
			keys = append(keys, k)
		}
		m[k] = v
	}
	if _, ok := m["PATH"]; !ok {
		keys, m["PATH"] = append(keys, "PATH"), "/usr/bin:/bin:/usr/sbin:/sbin"
	}
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k+"="+m[k])
	}
	return out
}

// Cmd returns an unstarted command under sandbox-exec (agentbox.Commander).
// cleanup kills its process group; it may be called more than once.
func (s *sandbox) Cmd(ctx context.Context, cmd agentbox.Command) (*exec.Cmd, func(), error) {
	if len(cmd.Args) == 0 {
		return nil, nil, errors.New("agentbox: empty command")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, nil, errors.New("agentbox: sandbox is closed")
	}
	dir := cmd.Dir
	switch {
	case dir == "" || dir == "/workspace":
		dir = s.spec.Workspace
	case strings.HasPrefix(dir, "/workspace/"):
		dir = filepath.Join(s.spec.Workspace, strings.TrimPrefix(dir, "/workspace/"))
	}
	c := exec.CommandContext(ctx, s.b.cfg.SandboxExec, append([]string{"-f", s.profile}, cmd.Args...)...)
	c.Dir, c.Env = dir, s.env(cmd.Env)
	c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	c.Cancel = func() error { return syscall.Kill(-c.Process.Pid, syscall.SIGKILL) }
	c.WaitDelay = 5 * time.Second // a background child holding the pipes must not hang Wait
	s.running[c] = true
	var once sync.Once
	cleanup := func() {
		once.Do(func() {
			if c.Process != nil {
				syscall.Kill(-c.Process.Pid, syscall.SIGKILL)
			}
			s.mu.Lock()
			delete(s.running, c)
			s.mu.Unlock()
		})
	}
	return c, cleanup, nil
}

// Exec runs cmd. A timeout or a cancelled ctx kills its process group.
func (s *sandbox) Exec(ctx context.Context, cmd agentbox.Command) (agentbox.Result, error) {
	if cmd.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cmd.Timeout)
		defer cancel()
	}
	c, cleanup, err := s.Cmd(ctx, cmd)
	if err != nil {
		return agentbox.Result{}, err
	}
	defer cleanup()
	c.Stdin, c.Stdout, c.Stderr = cmd.Stdin, cmd.Stdout, cmd.Stderr
	err = c.Run()
	var res agentbox.Result
	if ctx.Err() != nil {
		if cmd.Timeout > 0 && errors.Is(ctx.Err(), context.DeadlineExceeded) {
			res.TimedOut = true
			return res, nil
		}
		return res, ctx.Err()
	}
	var ee *exec.ExitError
	switch {
	case err == nil, errors.Is(err, exec.ErrWaitDelay):
	case errors.As(err, &ee):
		res.ExitCode = ee.ExitCode()
	default:
		return res, err
	}
	return res, nil
}

// Close kills every running command's process group and removes the
// sandbox's files. Safe to call more than once.
func (s *sandbox) Close(context.Context) error {
	var err error
	s.once.Do(func() {
		if s.timer != nil {
			s.timer.Stop()
		}
		s.mu.Lock()
		s.closed = true
		for c := range s.running {
			if c.Process != nil {
				syscall.Kill(-c.Process.Pid, syscall.SIGKILL)
			}
		}
		s.mu.Unlock()
		s.killMembers()
		err = os.RemoveAll(s.dir)
	})
	return err
}

// killMembers kills the user's processes that belong to this sandbox: those
// running under a Seatbelt profile that lets them write its TMPDIR, which
// only this sandbox's profile does (members.go). A few rounds, in case one
// forks while dying.
func (s *sandbox) killMembers() {
	for range 3 {
		out, err := exec.Command("/bin/ps", "-U", strconv.Itoa(os.Getuid()), "-o", "pid=").Output()
		if err != nil {
			return
		}
		found := false
		for _, f := range strings.Fields(string(out)) {
			pid, err := strconv.Atoi(f)
			if err != nil || pid == os.Getpid() || !member(pid, s.tmp) {
				continue
			}
			syscall.Kill(pid, syscall.SIGKILL)
			found = true
		}
		if !found {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}
