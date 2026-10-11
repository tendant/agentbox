package gvisor

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/tendant/agentbox/pkg/agentbox"
)

// Where the sandbox sees agentbox-owned things.
const (
	workspaceDir = "/workspace"
	modelDir     = "/run/agentbox"
)

// systemDirs are bound read-only from the host into every sandbox: the
// binaries, libraries and configuration programs need (design §6
// Filesystem, option b). Top-level symlinks among them are recreated as
// symlinks instead (usrmerge: /bin -> usr/bin).
var systemDirs = []string{"/usr", "/etc", "/opt", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32"}

// hostLayout describes the host's system directories. root is "/" except in
// tests.
type hostLayout struct {
	root     string
	binds    []string          // real directories, bound read-only
	symlinks map[string]string // top-level symlinks, recreated: "/bin" -> "usr/bin"
}

func probeHost(root string) hostLayout {
	h := hostLayout{root: root, symlinks: map[string]string{}}
	for _, d := range systemDirs {
		p := filepath.Join(root, d)
		fi, err := os.Lstat(p)
		switch {
		case err != nil:
		case fi.Mode()&os.ModeSymlink != 0:
			if t, err := os.Readlink(p); err == nil {
				h.symlinks[d] = t
			}
		case fi.IsDir():
			h.binds = append(h.binds, d)
		}
	}
	return h
}

// underSystem reports whether a sandbox path lies inside a system bind: a
// mount there would need its target to exist in the host's directory.
func (h hostLayout) underSystem(t string) bool {
	for _, d := range systemDirs {
		if t == d || strings.HasPrefix(t, d+"/") {
			return true
		}
	}
	return false
}

// ociSpec is the part of the OCI runtime spec agentbox writes.
type ociSpec struct {
	OCIVersion string     `json:"ociVersion"`
	Process    ociProcess `json:"process"`
	Root       struct {
		Path     string `json:"path"`
		Readonly bool   `json:"readonly"`
	} `json:"root"`
	Hostname string     `json:"hostname"`
	Mounts   []ociMount `json:"mounts"`
	Linux    struct {
		Namespaces []struct {
			Type string `json:"type"`
		} `json:"namespaces"`
	} `json:"linux"`
}

type ociProcess struct {
	User struct {
		UID int `json:"uid"`
		GID int `json:"gid"`
	} `json:"user"`
	Args            []string    `json:"args"`
	Env             []string    `json:"env"`
	Cwd             string      `json:"cwd"`
	Rlimits         []ociRlimit `json:"rlimits,omitempty"`
	NoNewPrivileges bool        `json:"noNewPrivileges"`
}

type ociRlimit struct {
	Type string `json:"type"`
	Hard uint64 `json:"hard"`
	Soft uint64 `json:"soft"`
}

type ociMount struct {
	Destination string   `json:"destination"`
	Type        string   `json:"type"`
	Source      string   `json:"source"`
	Options     []string `json:"options,omitempty"`
}

// process builds an OCI process: uid 0 inside, which rootless runsc maps to
// the caller on the host, so files written in the workspace belong to the
// caller (Phase 0); no user namespace is declared in the spec.
func process(spec agentbox.Spec, args, env []string, dir string) ociProcess {
	var p ociProcess
	p.Args = args
	p.Env = mergeEnv(spec.Env, env)
	p.Cwd = dir
	if p.Cwd == "" {
		p.Cwd = workspaceDir
	}
	p.NoNewPrivileges = true
	if n := spec.Limits.PIDs; n > 0 {
		// The per-sandbox process limit: fork() fails, the sandbox survives.
		// A cgroup task cap instead counts runsc's own threads and ends the
		// sandbox (Phase 0).
		p.Rlimits = []ociRlimit{{Type: "RLIMIT_NPROC", Hard: uint64(n), Soft: uint64(n)}}
	}
	return p
}

// mergeEnv returns base overridden by extra, keyed by name, in a stable
// order, with a PATH default.
func mergeEnv(base, extra []string) []string {
	m := map[string]string{"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
	for _, e := range append(append([]string{}, base...), extra...) {
		if k, v, ok := strings.Cut(e, "="); ok {
			m[k] = v
		}
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k+"="+m[k])
	}
	return out
}

// writeBundle lays out a bundle in dir: rootfs/ (an empty root holding only
// mount points and the recreated top-level symlinks; the spec makes it
// read-only) and config.json. init runs as the sandbox's first process and
// holds it open for Execs.
func writeBundle(dir string, spec agentbox.Spec, h hostLayout, init []string) error {
	rootfs := filepath.Join(dir, "rootfs")
	if err := os.MkdirAll(rootfs, 0o755); err != nil {
		return err
	}
	var s ociSpec
	s.OCIVersion = "1.0.2"
	s.Process = process(spec, init, nil, workspaceDir)
	s.Root.Path = rootfs
	s.Root.Readonly = true
	s.Hostname = "agentbox"
	for _, t := range []string{"pid", "ipc", "uts", "mount", "network"} {
		s.Linux.Namespaces = append(s.Linux.Namespaces, struct {
			Type string `json:"type"`
		}{t})
	}

	// mountPoint creates target inside rootfs: a directory, or an empty file
	// when the source is not one.
	mountPoint := func(target string, file bool) error {
		p := filepath.Join(rootfs, strings.TrimPrefix(target, "/"))
		if !file {
			return os.MkdirAll(p, 0o755)
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		return f.Close()
	}
	add := func(m ociMount, file bool) error {
		if err := mountPoint(m.Destination, file); err != nil {
			return fmt.Errorf("mount point %s: %w", m.Destination, err)
		}
		s.Mounts = append(s.Mounts, m)
		return nil
	}
	bind := func(src, dst string, rw bool) error {
		opt := "ro"
		if rw {
			opt = "rw"
		}
		fi, err := os.Stat(src)
		if err != nil {
			return err
		}
		return add(ociMount{Destination: dst, Type: "bind", Source: src, Options: []string{"rbind", opt}}, !fi.IsDir())
	}

	for link, target := range h.symlinks {
		if err := os.Symlink(target, filepath.Join(rootfs, strings.TrimPrefix(link, "/"))); err != nil && !os.IsExist(err) {
			return err
		}
	}
	for _, m := range []ociMount{
		{Destination: "/proc", Type: "proc", Source: "proc"},
		{Destination: "/dev", Type: "tmpfs", Source: "tmpfs", Options: []string{"nosuid", "mode=755"}},
		{Destination: "/tmp", Type: "tmpfs", Source: "tmpfs", Options: []string{"nosuid", "nodev", "mode=1777"}},
	} {
		if err := add(m, false); err != nil {
			return err
		}
	}
	for _, d := range h.binds {
		if err := bind(filepath.Join(h.root, d), d, false); err != nil {
			return err
		}
	}
	if err := bind(spec.Workspace, workspaceDir, true); err != nil {
		return err
	}
	for _, ms := range []struct {
		list []agentbox.Mount
		rw   bool
	}{{spec.ReadOnly, false}, {spec.Writable, true}} {
		for _, m := range ms.list {
			if h.underSystem(m.Target) {
				return fmt.Errorf("mount target %q is inside a system directory", m.Target)
			}
			if err := bind(m.Source, m.Target, ms.rw); err != nil {
				return err
			}
		}
	}
	if spec.ModelSocket != "" {
		// The socket alone, not its directory. Connecting needs write access.
		if err := bind(spec.ModelSocket, modelDir+"/"+filepath.Base(spec.ModelSocket), true); err != nil {
			return err
		}
	}

	b, err := json.MarshalIndent(s, "", " ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "config.json"), b, 0o600)
}
