package gvisor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/tendant/agentbox/pkg/agentbox"
)

// fakeHost is a usrmerge host: /usr and /etc real, /bin and /lib links.
func fakeHost(t *testing.T) hostLayout {
	root := t.TempDir()
	for _, d := range []string{"usr/bin", "usr/lib", "etc"} {
		os.MkdirAll(filepath.Join(root, d), 0o755)
	}
	os.Symlink("usr/bin", filepath.Join(root, "bin"))
	os.Symlink("usr/lib", filepath.Join(root, "lib"))
	return probeHost(root)
}

func TestProbeHost(t *testing.T) {
	h := fakeHost(t)
	if !slices.Equal(h.binds, []string{"/usr", "/etc"}) {
		t.Errorf("binds %v", h.binds)
	}
	if h.symlinks["/bin"] != "usr/bin" || h.symlinks["/lib"] != "usr/lib" {
		t.Errorf("symlinks %v", h.symlinks)
	}
}

func TestWriteBundle(t *testing.T) {
	h := fakeHost(t)
	ws, data, home := t.TempDir(), t.TempDir(), t.TempDir()
	os.WriteFile(filepath.Join(data, "f"), []byte("x"), 0o644)
	spec, err := agentbox.Spec{
		ID: "b1", Workspace: ws,
		ReadOnly: []agentbox.Mount{{Source: data, Target: "/data"}, {Source: filepath.Join(data, "f"), Target: "/files/f"}},
		Writable: []agentbox.Mount{{Source: home, Target: "/home/agent"}},
		Env:      []string{"HOME=/home/agent"},
		Limits:   agentbox.Limits{PIDs: 256},
	}.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := writeBundle(dir, spec, h, []string{"/bin/sleep", "infinity"}); err != nil {
		t.Fatal(err)
	}
	var s ociSpec
	b, _ := os.ReadFile(filepath.Join(dir, "config.json"))
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	rootfs := filepath.Join(dir, "rootfs")

	if !s.Root.Readonly || s.Root.Path != rootfs {
		t.Errorf("root %+v", s.Root)
	}
	if s.Process.User.UID != 0 || !s.Process.NoNewPrivileges || s.Process.Cwd != "/workspace" {
		t.Errorf("process %+v", s.Process)
	}
	if len(s.Process.Rlimits) != 1 || s.Process.Rlimits[0].Type != "RLIMIT_NPROC" || s.Process.Rlimits[0].Hard != 256 {
		t.Errorf("rlimits %+v", s.Process.Rlimits)
	}
	if !slices.Contains(s.Process.Env, "HOME=/home/agent") || !strings.HasPrefix(envOf(s.Process.Env, "PATH"), "/usr/local/sbin") {
		t.Errorf("env %v", s.Process.Env)
	}
	for _, ns := range s.Linux.Namespaces {
		if ns.Type == "user" {
			t.Error("no user namespace in the spec: rootless runsc maps the sandbox's root to the caller")
		}
	}

	byDest := map[string]ociMount{}
	for _, m := range s.Mounts {
		byDest[m.Destination] = m
	}
	want := map[string]string{"/usr": "ro", "/etc": "ro", "/workspace": "rw", "/data": "ro", "/files/f": "ro", "/home/agent": "rw"}
	for d, mode := range want {
		m, ok := byDest[d]
		if !ok || m.Type != "bind" || !slices.Contains(m.Options, mode) {
			t.Errorf("%s: %+v, want a %s bind", d, m, mode)
		}
	}
	if _, ok := byDest["/bin"]; ok {
		t.Error("/bin is a symlink on this host: recreate it, don't bind it")
	}
	if l, err := os.Readlink(filepath.Join(rootfs, "bin")); err != nil || l != "usr/bin" {
		t.Errorf("rootfs/bin: %q %v", l, err)
	}
	// Mount points exist in the read-only root: directories, and a file for a file.
	for _, d := range []string{"proc", "dev", "tmp", "usr", "etc", "workspace", "data", "home/agent"} {
		if fi, err := os.Stat(filepath.Join(rootfs, d)); err != nil || !fi.IsDir() {
			t.Errorf("mount point %s: %v", d, err)
		}
	}
	if fi, err := os.Stat(filepath.Join(rootfs, "files/f")); err != nil || fi.IsDir() {
		t.Errorf("file mount point: %v", err)
	}
	if byDest["/proc"].Type != "proc" || byDest["/tmp"].Type != "bind" || byDest["/tmp"].Source != filepath.Join(dir, "tmp") {
		t.Errorf("proc/tmp: %+v %+v", byDest["/proc"], byDest["/tmp"])
	}

	// A mount inside a system directory cannot work: rejected.
	bad := spec
	bad.ReadOnly = []agentbox.Mount{{Source: data, Target: "/usr/local/data"}}
	if err := writeBundle(t.TempDir(), bad, h, []string{"/bin/true"}); err == nil {
		t.Error("a target under /usr must be rejected")
	}
}

func envOf(env []string, k string) string {
	for _, e := range env {
		if v, ok := strings.CutPrefix(e, k+"="); ok {
			return v
		}
	}
	return ""
}

func TestMergeEnv(t *testing.T) {
	got := mergeEnv([]string{"A=1", "PATH=/x"}, []string{"A=2", "B=3"})
	if !slices.Equal(got, []string{"A=2", "B=3", "PATH=/x"}) {
		t.Errorf("%v", got)
	}
}

func TestScopeArgv(t *testing.T) {
	b := New(Config{TasksMax: 4096})
	got := strings.Join(b.scopeArgv(agentbox.Limits{MemoryBytes: 1 << 30, CPUs: 1.5}), " ")
	for _, want := range []string{"systemd-run --user --scope", "MemoryMax=1073741824", "MemorySwapMax=0", "CPUQuota=150%", "TasksMax=4096", " --"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %s", want, got)
		}
	}
	if needsScope(agentbox.Limits{PIDs: 100}) {
		t.Error("a process limit alone needs no scope: it is RLIMIT_NPROC")
	}
}

// Without XDG_RUNTIME_DIR (a system service, env -i), the scope still finds
// the user's manager where it is; nothing is invented when it is not there.
func TestUserSessionEnv(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "")
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "")
	env := strings.Join(userSessionEnv(), "\n")
	dir := "/run/user/" + strconv.Itoa(os.Getuid())
	if _, err := os.Stat(dir); err == nil {
		if !strings.Contains(env, "XDG_RUNTIME_DIR="+dir) {
			t.Errorf("XDG_RUNTIME_DIR not derived:\n%s", env)
		}
	} else if strings.Contains(env, "XDG_RUNTIME_DIR=/run/user") {
		t.Errorf("invented a runtime dir that does not exist:\n%s", env)
	}
	t.Setenv("XDG_RUNTIME_DIR", "/custom")
	if strings.Contains(strings.Join(userSessionEnv(), "\n"), "XDG_RUNTIME_DIR=/run/user") {
		t.Error("a set XDG_RUNTIME_DIR must be kept")
	}
}

// A read-only mount of a system path at its own place (agent-runner asks
// for a CLI's install dir, which may be /usr/local) is already visible:
// skipped, not refused. Writing or moving something into a system
// directory is still refused.
func TestMountInsideSystemDir(t *testing.T) {
	h := fakeHost(t)
	ws := t.TempDir()
	spec := agentbox.Spec{ID: "sys", Workspace: ws, ReadOnly: []agentbox.Mount{{Source: "/usr/local", Target: "/usr/local"}}}
	dir := t.TempDir()
	if err := writeBundle(dir, spec, h, initArgs); err != nil {
		t.Fatalf("redundant read-only system mount: %v", err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "config.json"))
	if strings.Contains(string(b), `"/usr/local"`) {
		t.Error("the redundant mount was added")
	}
	for name, s := range map[string]agentbox.Spec{
		"writable": {ID: "w", Workspace: ws, Writable: []agentbox.Mount{{Source: "/usr/local", Target: "/usr/local"}}},
		"moved":    {ID: "m", Workspace: ws, ReadOnly: []agentbox.Mount{{Source: ws, Target: "/usr/local/x"}}},
	} {
		if err := writeBundle(t.TempDir(), s, h, initArgs); err == nil || !strings.Contains(err.Error(), "system directory") {
			t.Errorf("%s: want a refusal, got %v", name, err)
		}
	}
}
