package seatbelt

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/tendant/agentbox/pkg/agentbox"
)

func TestProfile(t *testing.T) {
	spec := agentbox.Spec{Workspace: "/w", ReadOnly: []agentbox.Mount{{Source: "/ro", Target: "/ro"}},
		Writable: []agentbox.Mount{{Source: "/rw", Target: "/rw"}}, Deny: []string{"/w/.env"}, HostPorts: []int{4801}}
	p := profile(spec, []string{"/usr"}, "/t", nil)
	for _, want := range []string{
		`(deny network*)`, `(allow network-outbound (remote ip "localhost:4801"))`,
		`(deny mach-lookup)`, `(global-name "com.apple.cfprefsd.daemon")`,
		`(allow file-read* (subpath "/w") (subpath "/t") (subpath "/rw") (subpath "/ro"))`,
		`(allow file-write* (subpath "/dev/fd") (subpath "/w") (subpath "/t") (subpath "/rw"))`,
	} {
		if !strings.Contains(p, want) {
			t.Errorf("missing %s in\n%s", want, p)
		}
	}
	if strings.Contains(p, "SecurityServer") || strings.Contains(p, "mDNSResponder") {
		t.Error("the keychain and DNS services must stay denied")
	}
	// Denies come last: they win.
	if !strings.HasSuffix(p, "(deny file-read* file-write* (subpath \"/w/.env\"))\n") {
		t.Errorf("deny is not last:\n%s", p)
	}
}

// Real sandbox-exec, on macOS.
func testBackend(t *testing.T) *Backend {
	t.Helper()
	if runtime.GOOS != "darwin" {
		t.Skip("Seatbelt is macOS only")
	}
	return New(Config{StateDir: t.TempDir()})
}

func sh(t *testing.T, sb agentbox.Sandbox, script string, env ...string) (string, int) {
	t.Helper()
	var out bytes.Buffer
	res, err := sb.Exec(context.Background(), agentbox.Command{Args: []string{"/bin/sh", "-c", script}, Env: env, Stdout: &out, Stderr: &out})
	if err != nil {
		t.Fatalf("exec %q: %v", script, err)
	}
	return out.String(), res.ExitCode
}

func TestSandbox(t *testing.T) {
	b := testBackend(t)
	ctx := context.Background()
	if c, err := b.Capabilities(ctx); err != nil || !c.Rootless || !c.HostPorts || c.KernelIsolation || c.Gateway {
		t.Fatalf("capabilities %+v %v", c, err)
	}
	home := t.TempDir() // stands in for the user's home: none of it is granted
	ws, ro, rw := t.TempDir(), t.TempDir(), t.TempDir()
	os.WriteFile(filepath.Join(home, "secret"), []byte("HOME-SECRET"), 0o600)
	os.WriteFile(filepath.Join(ro, "memo"), []byte("MEMO"), 0o644)
	os.WriteFile(filepath.Join(ws, ".env"), []byte("WS-SECRET"), 0o600)

	// A host service the sandbox may reach, and one it may not.
	allowed, _ := net.Listen("tcp", "127.0.0.1:0")
	other, _ := net.Listen("tcp", "127.0.0.1:0")
	defer allowed.Close()
	defer other.Close()
	for _, l := range []net.Listener{allowed, other} {
		go func(l net.Listener) {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				c.Write([]byte("HOST_SERVICE\n"))
				c.Close()
			}
		}(l)
	}
	port := allowed.Addr().(*net.TCPAddr).Port
	otherPort := other.Addr().(*net.TCPAddr).Port

	sb, err := b.Create(ctx, agentbox.Spec{ID: "t1", Workspace: ws, ReadOnly: []agentbox.Mount{{Source: ro}},
		Writable: []agentbox.Mount{{Source: rw}}, Deny: []string{filepath.Join(ws, ".env")},
		Env: []string{"GREETING=hi"}, HostPorts: []int{port}})
	if err != nil {
		t.Fatal(err)
	}
	defer sb.Close(ctx)

	out, code := sh(t, sb, `pwd; echo $GREETING; echo x > made && cat made; cat `+ro+`/memo; echo w > `+rw+`/w && echo RW_OK
		echo t > "$TMPDIR/t" && echo TMP_OK; git --version >/dev/null && echo GIT_OK; /usr/bin/python3 -c 'print("PY_OK")' 2>/dev/null; echo END`)
	ws, _ = filepath.EvalSymlinks(ws)
	for _, want := range []string{ws, "hi", "x", "MEMO", "RW_OK", "TMP_OK", "GIT_OK", "END"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q (exit %d):\n%s", want, code, out)
		}
	}
	if _, code := sh(t, sb, "exit 7"); code != 7 {
		t.Errorf("exit code %d", code)
	}

	// What it must not do.
	checks := map[string]string{
		"read home":        "cat " + home + "/secret",
		"list home":        "ls " + home,
		"read denied":      "cat " + ws + "/.env",
		"write read-only":  "echo x > " + ro + "/x",
		"write outside":    "echo x > " + home + "/x",
		"write /tmp":       "echo x > /private/tmp/agentbox-escape-" + fmt.Sprint(os.Getpid()),
		"read data volume": "ls /System/Volumes/Data" + home,
		"other host port":  fmt.Sprintf("nc -w 3 127.0.0.1 %d", otherPort),
		"internet":         "curl -sS -m 5 -o /dev/null http://1.1.1.1/",
		"dns":              "/usr/bin/python3 -c 'import socket; socket.getaddrinfo(\"example.com\", 80)'",
		"listen":           "/usr/bin/python3 -c 'import socket; s=socket.socket(); s.bind((\"127.0.0.1\", 0)); s.listen()'",
		"signal host":      fmt.Sprintf("kill -0 %d", os.Getpid()),
		"keychain":         "/usr/bin/security show-keychain-info login.keychain", // succeeds outside
	}
	for name, cmd := range checks {
		out, code := sh(t, sb, cmd+" 2>&1")
		if code == 0 || strings.Contains(out, "SECRET") || strings.Contains(out, "HOST_SERVICE") {
			t.Errorf("%s: allowed (exit %d): %s", name, code, out)
		}
	}
	if out, _ := sh(t, sb, fmt.Sprintf("nc -w 3 127.0.0.1 %d", port)); !strings.Contains(out, "HOST_SERVICE") {
		t.Errorf("host port: %q", out)
	}
	if _, err := os.Stat(filepath.Join(home, "x")); err == nil {
		t.Error("wrote outside")
	}

	// A timeout kills the command's process group.
	start := time.Now()
	res, err := sb.Exec(ctx, agentbox.Command{Args: []string{"/bin/sh", "-c", "sleep 600 & sleep 600"}, Timeout: time.Second})
	if err != nil || !res.TimedOut || time.Since(start) > 15*time.Second {
		t.Errorf("timeout: %+v %v after %v", res, err, time.Since(start))
	}
	time.Sleep(300 * time.Millisecond)
	if left, _ := exec.Command("pgrep", "-f", "sleep 600").Output(); len(bytes.TrimSpace(left)) > 0 {
		t.Errorf("sleeps left: %s", left)
	}

	// Close kills what is still running, a daemon that left the process
	// group too; the sandbox is gone.
	sh(t, sb, `/usr/bin/python3 -c "
import os
if os.fork() == 0:
    os.setsid(); os.execvp('sleep', ['sleep', '602'])" </dev/null >/dev/null 2>&1`)
	time.Sleep(300 * time.Millisecond)
	if out, _ := exec.Command("pgrep", "-f", "sleep 602").Output(); len(bytes.TrimSpace(out)) == 0 {
		t.Fatal("the daemon did not start")
	}
	c, cleanup, err := sb.(agentbox.Commander).Cmd(ctx, agentbox.Command{Args: []string{"/bin/sh", "-c", "sleep 601"}})
	if err != nil || c.Start() != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if err := sb.Close(ctx); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- c.Wait() }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Error("Close did not kill a running command")
	}
	if _, err := sb.Exec(ctx, agentbox.Command{Args: []string{"true"}}); err == nil {
		t.Error("exec after close must fail")
	}
	time.Sleep(200 * time.Millisecond)
	if out, _ := exec.Command("pgrep", "-f", "sleep 602").Output(); len(bytes.TrimSpace(out)) > 0 {
		exec.Command("pkill", "-f", "sleep 602").Run()
		t.Errorf("a daemon outlived Close: %s", out)
	}
}

func TestRefusals(t *testing.T) {
	b := testBackend(t)
	ws, other := t.TempDir(), t.TempDir()
	for name, spec := range map[string]agentbox.Spec{
		"moved mount": {Workspace: ws, ReadOnly: []agentbox.Mount{{Source: other, Target: "/data"}}},
		"gateway":     {Workspace: ws, Network: agentbox.NetworkPolicy{Mode: agentbox.NetworkGateway, Gateway: ws}},
		"limits":      {Workspace: ws, Limits: agentbox.Limits{PIDs: 100}},
	} {
		spec.ID = "r"
		if sb, err := b.Create(context.Background(), spec); err == nil {
			sb.Close(context.Background())
			t.Errorf("%s: want an error", name)
		}
	}
}
