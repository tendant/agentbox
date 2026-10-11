//go:build linux

package gvisor

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/tendant/agentbox/pkg/agentbox"
)

// Real rootless runsc, as the user running the tests (never root).
// Opt-in: AGENTBOX_INTEGRATION=1; scripts/test-linux.sh runs them in a
// container.
func integration(t *testing.T) *Backend {
	t.Helper()
	if os.Getenv("AGENTBOX_INTEGRATION") == "" {
		t.Skip("set AGENTBOX_INTEGRATION=1 (needs runsc; see scripts/test-linux.sh)")
	}
	if os.Geteuid() == 0 {
		t.Fatal("run as a normal user: agentbox is rootless")
	}
	return New(Config{StateDir: t.TempDir()})
}

func run(t *testing.T, sb agentbox.Sandbox, script string) (string, agentbox.Result) {
	t.Helper()
	var out bytes.Buffer
	res, err := sb.Exec(context.Background(), agentbox.Command{Args: []string{"/bin/sh", "-c", script}, Stdout: &out, Stderr: &out})
	if err != nil {
		t.Fatalf("exec %q: %v", script, err)
	}
	return out.String(), res
}

func TestSandboxLifecycle(t *testing.T) {
	b := integration(t)
	ctx := context.Background()
	if c, err := b.Capabilities(ctx); err != nil || !c.Rootless {
		t.Fatalf("capabilities %+v %v", c, err)
	}
	ws := t.TempDir()
	os.WriteFile(filepath.Join(ws, "script.sh"), []byte("#!/bin/sh\necho SCRIPT_OK\n"), 0o755)
	sb, err := b.Create(ctx, agentbox.Spec{ID: "life", Workspace: ws, Env: []string{"GREETING=hi"}, Limits: agentbox.Limits{PIDs: 128}})
	if err != nil {
		t.Fatal(err)
	}

	// Several commands share the sandbox; files belong to the caller.
	if out, res := run(t, sb, "echo $GREETING > /workspace/made && echo FIRST"); res.ExitCode != 0 || !strings.Contains(out, "FIRST") {
		t.Fatalf("first exec: %d %q", res.ExitCode, out)
	}
	if out, _ := run(t, sb, "cat /workspace/made"); strings.TrimSpace(out) != "hi" {
		t.Errorf("second exec saw %q", out)
	}
	if st, err := os.Stat(filepath.Join(ws, "made")); err != nil || st.Sys().(*syscall.Stat_t).Uid != uint32(os.Getuid()) {
		t.Errorf("workspace file: %v, want owner %d", err, os.Getuid())
	}
	if out, _ := run(t, sb, "/workspace/script.sh"); !strings.Contains(out, "SCRIPT_OK") {
		t.Errorf("#!/bin/sh script: %q", out)
	}
	if out, _ := run(t, sb, "cat /etc/shadow 2>&1 | head -c 200"); strings.Contains(out, "root:") {
		t.Error("/etc/shadow readable")
	}
	if out, _ := run(t, sb, "ls /home /root 2>&1"); strings.Contains(out, os.Getenv("USER")+"\n") {
		t.Errorf("host home visible: %q", out)
	}
	if out, _ := run(t, sb, "python3 -c 'import socket; socket.create_connection((\"1.1.1.1\", 80), 3)' 2>&1 || echo NO_NET"); !strings.Contains(out, "NO_NET") {
		t.Errorf("network reachable: %q", out)
	}
	if _, res := run(t, sb, "exit 7"); res.ExitCode != 7 {
		t.Errorf("exit code %d, want 7", res.ExitCode)
	}

	// A timeout kills the command inside the sandbox, not just its client.
	start := time.Now()
	res, err := sb.Exec(ctx, agentbox.Command{Args: []string{"/bin/sh", "-c", "sleep 600"}, Timeout: time.Second})
	if err != nil || !res.TimedOut || time.Since(start) > 20*time.Second {
		t.Errorf("timeout: %+v %v after %v", res, err, time.Since(start))
	}
	time.Sleep(500 * time.Millisecond) // let init reap
	if out, _ := run(t, sb, "ps -eo stat,args 2>/dev/null | grep -c -e '[s]leep 600' -e '^Z' || true"); strings.TrimSpace(out) != "0" {
		// The timed-out sleep is gone, and nothing is left as a zombie.
		tree, _ := run(t, sb, "ps -eo pid,ppid,pgid,sid,comm,args")
		t.Errorf("sleeps left in the sandbox: %q\n%s", out, tree)
	}

	// A fork bomb hits RLIMIT_NPROC; the sandbox survives.
	if out, _ := run(t, sb, "b() { b | b & }; b; sleep 2; echo ALIVE"); !strings.Contains(out, "ALIVE") {
		t.Errorf("fork bomb: %q", out)
	}
	if out, _ := run(t, sb, "echo STILL_THERE"); !strings.Contains(out, "STILL_THERE") {
		t.Errorf("after the bomb: %q", out)
	}

	if err := sb.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := sb.Exec(ctx, agentbox.Command{Args: []string{"true"}}); err == nil {
		t.Error("exec after close must fail")
	}
	if out, _ := exec.Command("pgrep", "-u", strings.TrimSpace(func() string { o, _ := exec.Command("id", "-u").Output(); return string(o) }()), "-f", "runsc.*life").Output(); len(bytes.TrimSpace(out)) > 0 {
		t.Errorf("runsc processes left: %s", out)
	}
	if _, err := os.Stat(filepath.Join(b.cfg.StateDir, "sandboxes", "life")); !os.IsNotExist(err) {
		t.Errorf("bundle left: %v", err)
	}
	// The ID is free again.
	sb2, err := b.Create(ctx, agentbox.Spec{ID: "life", Workspace: ws})
	if err != nil {
		t.Fatalf("reuse id: %v", err)
	}
	if _, err := b.Create(ctx, agentbox.Spec{ID: "life", Workspace: ws}); err == nil {
		t.Error("a live id must not be reused")
	}
	sb2.Close(ctx)
}

func TestModelSocket(t *testing.T) {
	b := integration(t)
	ctx := context.Background()
	dir, err := os.MkdirTemp("", "abx") // short: Unix socket paths are limited
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "model.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Write([]byte("MODEL_OK\n"))
			c.Close()
		}
	}()
	sb, err := b.Create(ctx, agentbox.Spec{ID: "model", Workspace: t.TempDir(), ModelSocket: sock})
	if err != nil {
		t.Fatal(err)
	}
	defer sb.Close(ctx)
	out, _ := run(t, sb, `python3 -c 'import socket; s=socket.socket(socket.AF_UNIX); s.connect("/run/agentbox/model.sock"); print(s.recv(100).decode())'`)
	if !strings.Contains(out, "MODEL_OK") {
		t.Errorf("model socket: %q", out)
	}
	if out, _ := run(t, sb, "ls /run/agentbox"); strings.TrimSpace(out) != "model.sock" {
		t.Errorf("only the socket is mounted, not its directory: %q", out)
	}
}

func TestMemoryLimit(t *testing.T) {
	b := integration(t)
	ctx := context.Background()
	if c, _ := b.Capabilities(ctx); !c.MemoryLimit {
		if _, err := b.Create(ctx, agentbox.Spec{ID: "mem", Workspace: t.TempDir(), Limits: agentbox.Limits{MemoryBytes: 512 << 20}}); err == nil {
			t.Fatal("a memory limit without a scope must fail closed")
		}
		t.Skip("no systemd user scope here: checked that a memory limit fails closed")
	}
	sb, err := b.Create(ctx, agentbox.Spec{ID: "mem", Workspace: t.TempDir(), Limits: agentbox.Limits{MemoryBytes: 512 << 20}})
	if err != nil {
		t.Fatal(err)
	}
	defer sb.Close(ctx)
	out, _ := run(t, sb, "echo SMALL_OK")
	if !strings.Contains(out, "SMALL_OK") {
		t.Fatalf("small command: %q", out)
	}
	// Past the cap the sandbox is killed: the exec fails or exits non-zero.
	res, err := sb.Exec(ctx, agentbox.Command{Args: []string{"python3", "-c", "b=[]\nwhile True: b.append(bytearray(64<<20))"}})
	if err == nil && res.ExitCode == 0 {
		t.Errorf("allocation past MemoryMax succeeded: %+v", res)
	}
}

// agent-runner's path: roots mounted at their own host paths (under /tmp in
// tests), commands as unstarted exec.Cmds whose output the caller streams.
func TestCmdAndPathPreservingMounts(t *testing.T) {
	b := integration(t)
	ctx := context.Background()
	ws, home, ro := t.TempDir(), t.TempDir(), t.TempDir() // all under /tmp
	os.WriteFile(filepath.Join(ro, "memo"), []byte("MEMO"), 0o644)
	sb, err := b.Create(ctx, agentbox.Spec{ID: "cmd", Workspace: ws,
		Writable: []agentbox.Mount{{Source: ws}, {Source: home}},
		ReadOnly: []agentbox.Mount{{Source: ro}}})
	if err != nil {
		t.Fatal(err)
	}
	defer sb.Close(ctx)
	cmdr, ok := sb.(agentbox.Commander)
	if !ok {
		t.Fatal("the gvisor sandbox must implement agentbox.Commander")
	}
	c, cleanup, err := cmdr.Cmd(ctx, agentbox.Command{Dir: ws, Env: []string{"HOME=" + home},
		Args: []string{"/bin/sh", "-c", "pwd; cat " + ro + "/memo; echo x > $HOME/h; echo y > " + ro + "/w 2>&1 || echo RO_OK; (sleep 600 &) ; echo DONE"}})
	if err != nil {
		t.Fatal(err)
	}
	c.Cancel = func() error { return c.Process.Signal(syscall.SIGTERM) } // what agent-runner's executor does
	var out bytes.Buffer
	c.Stdout, c.Stderr = &out, &out
	// ErrWaitDelay: the command exited but its background child still held
	// the pipes (by design here); WaitDelay keeps that from hanging the caller.
	if err := c.Run(); err != nil && !errors.Is(err, exec.ErrWaitDelay) {
		t.Fatalf("%v: %s", err, out.String())
	}
	cleanup()
	for _, want := range []string{ws, "MEMO", "RO_OK", "DONE"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in %q", want, out.String())
		}
	}
	if _, err := os.Stat(filepath.Join(home, "h")); err != nil {
		t.Errorf("write through the path-preserving home mount: %v", err)
	}
	// cleanup killed the command's background child too.
	time.Sleep(500 * time.Millisecond)
	if left, _ := run(t, sb, "ps -eo args | grep -c '[s]leep 600' || true"); strings.TrimSpace(left) != "0" {
		t.Errorf("background child survived cleanup: %q", left)
	}
}

// A denied path inside a mount is covered, wherever the mount is visible.
func TestDenyInsideMounts(t *testing.T) {
	b := integration(t)
	ctx := context.Background()
	ws, home := t.TempDir(), t.TempDir()
	os.MkdirAll(filepath.Join(home, ".ssh"), 0o700)
	os.WriteFile(filepath.Join(home, ".ssh", "id_rsa"), []byte("SECRET-KEY"), 0o600)
	os.WriteFile(filepath.Join(ws, ".env"), []byte("SECRET-ENV"), 0o600)
	sb, err := b.Create(ctx, agentbox.Spec{ID: "deny", Workspace: ws,
		Writable: []agentbox.Mount{{Source: ws}, {Source: home}},
		Deny:     []string{filepath.Join(home, ".ssh"), filepath.Join(ws, ".env")}})
	if err != nil {
		t.Fatal(err)
	}
	defer sb.Close(ctx)
	out, _ := run(t, sb, "cat "+home+"/.ssh/id_rsa /workspace/.env "+ws+"/.env 2>&1; ls -a "+home+"/.ssh; ln -s "+home+"/.ssh/id_rsa /workspace/l 2>/dev/null; cat /workspace/l 2>&1; echo END")
	if strings.Contains(out, "SECRET") {
		t.Errorf("a denied path was readable: %q", out)
	}
	if !strings.Contains(out, "END") {
		t.Errorf("probe did not run: %q", out)
	}
}
