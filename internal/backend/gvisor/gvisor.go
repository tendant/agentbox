// Package gvisor is agentbox's backend on gVisor: rootless runsc, driven
// directly (no Docker, Podman or containerd).
//
// Rootless runsc has no create/start (Phase 0): a sandbox is a foreground
// "runsc run" that agentbox holds for its lifetime (a monitor, like Podman's
// conmon), and commands are "runsc exec"s into it. Memory and CPU limits put
// that run in a systemd user scope; the process limit is RLIMIT_NPROC.
package gvisor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/tendant/agentbox/pkg/agentbox"
)

// Config configures the backend.
type Config struct {
	// Runsc is the runsc binary (default: /usr/local/bin/runsc if present,
	// else runsc on PATH). Install it with scripts/install-runsc.sh.
	Runsc string
	// StateDir holds runsc's state and the bundles; it must be private to
	// the caller (default: $XDG_RUNTIME_DIR/agentbox, else os.TempDir()).
	StateDir string
	// Scope: "auto" (default) uses a systemd user scope when limits need
	// one and it works; "off" never does (then memory/CPU limits fail
	// closed); "on" requires it.
	Scope string
	// TasksMax is the scope's host backstop on tasks, not the policy limit
	// (default 8192): a task cap counts runsc's own threads.
	TasksMax int64
	// StartTimeout bounds sandbox startup (default 30s).
	StartTimeout time.Duration
}

// Backend creates gVisor sandboxes.
type Backend struct {
	cfg  Config
	host hostLayout
}

// New returns a backend; Capabilities says what this host can enforce.
func New(cfg Config) *Backend {
	if cfg.Runsc == "" {
		cfg.Runsc = "runsc"
		if _, err := os.Stat("/usr/local/bin/runsc"); err == nil {
			cfg.Runsc = "/usr/local/bin/runsc"
		}
	}
	if cfg.StateDir == "" {
		base := os.Getenv("XDG_RUNTIME_DIR")
		if base == "" {
			base = os.TempDir()
		}
		cfg.StateDir = filepath.Join(base, "agentbox")
	}
	if cfg.Scope == "" {
		cfg.Scope = "auto"
	}
	if cfg.TasksMax == 0 {
		cfg.TasksMax = 8192
	}
	if cfg.StartTimeout == 0 {
		cfg.StartTimeout = 30 * time.Second
	}
	return &Backend{cfg: cfg, host: probeHost("/")}
}

func (b *Backend) runscRoot() string { return filepath.Join(b.cfg.StateDir, "runsc") }

// globalFlags are runsc's flags for one sandbox; every call to it uses them.
func (b *Backend) globalFlags(spec agentbox.Spec) []string {
	f := []string{"--root", b.runscRoot(), "--rootless", "--network=none", "--ignore-cgroups"}
	if spec.ModelSocket != "" {
		f = append(f, "--host-uds=open")
	}
	return f
}

// scopeArgv wraps a command in a transient systemd user scope with the
// spec's memory and CPU limits and the tasks backstop.
func (b *Backend) scopeArgv(l agentbox.Limits) []string {
	a := []string{"systemd-run", "--user", "--scope", "--quiet", "--collect"}
	if l.MemoryBytes > 0 {
		a = append(a, "-p", "MemoryMax="+strconv.FormatInt(l.MemoryBytes, 10), "-p", "MemorySwapMax=0")
	}
	if l.CPUs > 0 {
		a = append(a, "-p", "CPUQuota="+strconv.FormatFloat(l.CPUs*100, 'f', 0, 64)+"%")
	}
	a = append(a, "-p", "TasksMax="+strconv.FormatInt(b.cfg.TasksMax, 10), "--")
	return a
}

func needsScope(l agentbox.Limits) bool { return l.MemoryBytes > 0 || l.CPUs > 0 }

// scopeWorks reports whether a systemd user scope can be created here.
func scopeWorks(ctx context.Context) bool {
	if _, err := exec.LookPath("systemd-run"); err != nil {
		return false
	}
	return exec.CommandContext(ctx, "systemd-run", "--user", "--scope", "--quiet", "--collect", "true").Run() == nil
}

// Capabilities tries each mechanism on this host rather than assuming it.
func (b *Backend) Capabilities(ctx context.Context) (agentbox.Capabilities, error) {
	c := agentbox.Capabilities{Backend: "gvisor"}
	if runtime.GOOS != "linux" {
		c.Notes = append(c.Notes, "gVisor runs on Linux only")
		return c, nil
	}
	if err := os.MkdirAll(b.cfg.StateDir, 0o700); err != nil {
		return c, err
	}
	tmp, err := os.MkdirTemp(b.cfg.StateDir, "probe-")
	if err != nil {
		return c, err
	}
	defer os.RemoveAll(tmp)
	out, err := exec.CommandContext(ctx, b.cfg.Runsc, "--root", tmp, "--rootless", "--network=none", "--ignore-cgroups",
		"do", "--", "/bin/true").CombinedOutput()
	if err != nil {
		c.Notes = append(c.Notes, "rootless runsc does not work: "+tail(out, 300)+
			" (on Ubuntu 23.10+ install it with scripts/install-runsc.sh, which adds its AppArmor profile)")
		return c, nil
	}
	c.Rootless, c.NetworkNone, c.ModelSocket, c.PIDLimit, c.Persistent = true, true, true, true, true
	if b.cfg.Scope != "off" && scopeWorks(ctx) {
		c.MemoryLimit, c.CPULimit = true, true
	} else {
		c.Notes = append(c.Notes, "no systemd user scope: memory and CPU limits are unavailable")
	}
	return c, nil
}

// initArgs is the sandbox's first process. It holds the sandbox open for
// Execs and reaps orphans: a command's children whose parent died are
// re-parented to it (a plain "sleep infinity" left them as zombies). dash's
// wait collects any child, adopted ones included.
var initArgs = []string{"/bin/sh", "-c", "trap 'exit 0' TERM; while :; do sleep 3600 & wait; done"}

// sandbox is one held "runsc run".
type sandbox struct {
	b      *Backend
	spec   agentbox.Spec
	dir    string
	flags  []string
	run    *exec.Cmd
	done   chan struct{} // closed when the held run exits
	runErr error
	execMu sync.Mutex
	once   sync.Once
	closed error
	timer  *time.Timer
}

// Create validates spec, writes its bundle and starts the sandbox.
func (b *Backend) Create(ctx context.Context, spec agentbox.Spec) (agentbox.Sandbox, error) {
	if runtime.GOOS != "linux" {
		return nil, errors.New("agentbox: the gvisor backend runs on Linux only")
	}
	spec, err := spec.Normalize()
	if err != nil {
		return nil, err
	}
	scope := false
	if needsScope(spec.Limits) || b.cfg.Scope == "on" {
		if b.cfg.Scope == "off" || !scopeWorks(ctx) {
			return nil, errors.New("agentbox: memory/CPU limits need a systemd user scope, which is unavailable here (fail closed)")
		}
		scope = true
	}
	if err := os.MkdirAll(b.cfg.StateDir, 0o700); err != nil {
		return nil, err
	}
	dir := filepath.Join(b.cfg.StateDir, "sandboxes", spec.ID)
	if err := os.Mkdir(filepath.Dir(dir), 0o700); err != nil && !os.IsExist(err) {
		return nil, err
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		if os.IsExist(err) {
			return nil, fmt.Errorf("agentbox: sandbox %q already exists", spec.ID)
		}
		return nil, err
	}
	s := &sandbox{b: b, spec: spec, dir: dir, flags: b.globalFlags(spec), done: make(chan struct{})}
	fail := func(err error) (agentbox.Sandbox, error) {
		s.teardown()
		return nil, err
	}
	if err := writeBundle(dir, spec, b.host, initArgs); err != nil {
		return fail(fmt.Errorf("agentbox: bundle: %w", err))
	}

	argv := append(append([]string{b.cfg.Runsc}, s.flags...), "run", "--bundle", dir, spec.ID)
	if scope {
		argv = append(b.scopeArgv(spec.Limits), argv...)
	}
	log, err := os.Create(filepath.Join(dir, "run.log"))
	if err != nil {
		return fail(err)
	}
	s.run = exec.Command(argv[0], argv[1:]...)
	s.run.Stdout, s.run.Stderr = log, log
	s.run.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := s.run.Start(); err != nil {
		log.Close()
		return fail(fmt.Errorf("agentbox: start: %w", err))
	}
	go func() {
		s.runErr = s.run.Wait()
		log.Close()
		close(s.done)
	}()

	deadline := time.Now().Add(b.cfg.StartTimeout)
	for {
		if st, _ := s.state(ctx); st == "running" {
			break
		}
		select {
		case <-s.done:
			out, _ := os.ReadFile(filepath.Join(dir, "run.log"))
			return fail(fmt.Errorf("agentbox: sandbox exited while starting: %s", tail(out, 400)))
		case <-ctx.Done():
			return fail(ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			return fail(errors.New("agentbox: sandbox did not start in time"))
		}
	}
	if spec.Lifetime > 0 {
		s.timer = time.AfterFunc(spec.Lifetime, func() { s.Close(context.Background()) })
	}
	return s, nil
}

func (s *sandbox) ID() string { return s.spec.ID }

// runsc runs one runsc subcommand for this sandbox.
func (s *sandbox) runsc(ctx context.Context, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, s.b.cfg.Runsc, append(append([]string{}, s.flags...), args...)...).CombinedOutput()
}

func (s *sandbox) state(ctx context.Context) (string, error) {
	out, err := s.runsc(ctx, "state", s.spec.ID)
	if err != nil {
		return "", err
	}
	var st struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(out, &st); err != nil {
		return "", err
	}
	return st.Status, nil
}

// Exec runs cmd in the sandbox. A timeout or a cancelled ctx kills the
// command inside the sandbox, not only its runsc client.
func (s *sandbox) Exec(ctx context.Context, cmd agentbox.Command) (agentbox.Result, error) {
	s.execMu.Lock()
	defer s.execMu.Unlock()
	c, cleanup, err := s.Cmd(ctx, cmd)
	if err != nil {
		return agentbox.Result{}, err
	}
	defer cleanup()
	c.Stdin, c.Stdout, c.Stderr = cmd.Stdin, cmd.Stdout, cmd.Stderr
	if err := c.Start(); err != nil {
		return agentbox.Result{}, err
	}
	waited := make(chan error, 1)
	go func() { waited <- c.Wait() }()

	var timeout <-chan time.Time
	if cmd.Timeout > 0 {
		t := time.NewTimer(cmd.Timeout)
		defer t.Stop()
		timeout = t.C
	}
	var res agentbox.Result
	select {
	case err = <-waited:
	case <-timeout:
		res.TimedOut = true
		cleanup()
		err = <-waited
	case <-ctx.Done():
		cleanup()
		<-waited
		return agentbox.Result{}, ctx.Err()
	}
	var ee *exec.ExitError
	switch {
	case err == nil, errors.Is(err, exec.ErrWaitDelay):
		// ErrWaitDelay: the command exited 0 but a background child held its
		// output open; cleanup kills that child.
	case errors.As(err, &ee):
		res.ExitCode = ee.ExitCode()
	default:
		return res, err
	}
	return res, nil
}

// Cmd returns an unstarted "runsc exec" for cmd (agentbox.Commander). The
// caller sets its stdio, starts and waits for it; cleanup kills what is left
// of the command inside the sandbox and removes its files, and may be called
// more than once. cmd.Timeout and the stdio fields are the caller's to apply.
func (s *sandbox) Cmd(ctx context.Context, cmd agentbox.Command) (*exec.Cmd, func(), error) {
	if len(cmd.Args) == 0 {
		return nil, nil, errors.New("agentbox: empty command")
	}
	select {
	case <-s.done:
		return nil, nil, errors.New("agentbox: sandbox is closed")
	default:
	}
	proc := process(s.spec, cmd.Args, cmd.Env, cmd.Dir)
	pf, err := os.CreateTemp(s.dir, "exec-*.json")
	if err != nil {
		return nil, nil, err
	}
	if err := json.NewEncoder(pf).Encode(proc); err != nil {
		pf.Close()
		os.Remove(pf.Name())
		return nil, nil, err
	}
	pf.Close()
	pidFile := strings.TrimSuffix(pf.Name(), ".json") + ".pid"
	c := exec.Command(s.b.cfg.Runsc, append(append([]string{}, s.flags...),
		"exec", "--process", pf.Name(), "--internal-pid-file", pidFile, s.spec.ID)...)
	// A background child the command leaves running inherits its stdout and
	// stderr: without a WaitDelay, Wait blocks on those pipes until the child
	// exits (an agent that starts a server would hang its caller). cleanup
	// then kills the child.
	c.WaitDelay = 5 * time.Second
	var once sync.Once
	cleanup := func() {
		once.Do(func() {
			s.killExec(pidFile)
			os.Remove(pf.Name())
			os.Remove(pidFile)
		})
	}
	return c, cleanup, nil
}

// killExec kills the exec'd command inside the sandbox: its process group
// (a shell's children too: killing the pid alone left "sh -c 'sleep 600'"'s
// sleep running), then the pid itself.
func (s *sandbox) killExec(pidFile string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	b, err := os.ReadFile(pidFile)
	pid := strings.TrimSpace(string(b))
	if err != nil || pid == "" {
		return
	}
	s.runsc(ctx, "exec", s.spec.ID, "/bin/kill", "-KILL", "--", "-"+pid)
	s.runsc(ctx, "kill", "--pid", pid, s.spec.ID, "KILL")
}

// Close kills every process in the sandbox, ends the held run, deletes the
// sandbox and removes its bundle. Safe to call more than once.
func (s *sandbox) Close(ctx context.Context) error {
	s.once.Do(func() {
		if s.timer != nil {
			s.timer.Stop()
		}
		s.closed = s.teardown()
	})
	return s.closed
}

func (s *sandbox) teardown() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if s.run != nil && s.run.Process != nil {
		s.runsc(ctx, "kill", "--all", s.spec.ID, "KILL")
		select {
		case <-s.done:
		case <-time.After(10 * time.Second):
			syscall.Kill(-s.run.Process.Pid, syscall.SIGKILL) // the whole process group
			<-s.done
		}
	}
	var errs []error
	if out, err := s.runsc(ctx, "delete", "--force", s.spec.ID); err != nil && !bytes.Contains(out, []byte("does not exist")) &&
		!bytes.Contains(out, []byte("not found")) {
		errs = append(errs, fmt.Errorf("runsc delete: %s", tail(out, 200)))
	}
	if err := os.RemoveAll(s.dir); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func tail(b []byte, n int) string {
	s := strings.TrimSpace(string(b))
	if len(s) > n {
		s = "…" + s[len(s)-n:]
	}
	return s
}
