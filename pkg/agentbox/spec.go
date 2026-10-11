package agentbox

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var idPattern = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,64}$`)

// reservedTargets are sandbox paths agentbox owns.
// /tmp is not reserved: it is a host directory agentbox owns, so mounts
// under it get their mount points there.
var reservedTargets = []string{"/proc", "/dev", "/run/agentbox", "/workspace"}

// Normalize checks a Spec and returns it with host paths resolved (symlinks
// followed, made absolute) and targets defaulted. Anything it cannot verify
// is an error: agentbox never widens a request to make it work.
func (s Spec) Normalize() (Spec, error) {
	if !idPattern.MatchString(s.ID) {
		return s, fmt.Errorf("agentbox: bad sandbox id %q", s.ID)
	}
	ws, err := hostDir(s.Workspace)
	if err != nil {
		return s, fmt.Errorf("agentbox: workspace: %w", err)
	}
	s.Workspace = ws
	seen := map[string]bool{"/workspace": true}
	norm := func(ms []Mount) ([]Mount, error) {
		out := make([]Mount, 0, len(ms))
		for _, m := range ms {
			src, err := hostPath(m.Source)
			if err != nil {
				return nil, fmt.Errorf("agentbox: mount %q: %w", m.Source, err)
			}
			t := m.Target
			if t == "" {
				t = filepath.Clean(m.Source)
			}
			if !filepath.IsAbs(t) || t != filepath.Clean(t) || t == "/" {
				return nil, fmt.Errorf("agentbox: mount target %q must be a clean absolute path", t)
			}
			if t == "/tmp" {
				return nil, fmt.Errorf("agentbox: mount target %q is reserved", t)
			}
			for _, r := range reservedTargets {
				if t == r || strings.HasPrefix(t, r+"/") {
					return nil, fmt.Errorf("agentbox: mount target %q is reserved", t)
				}
			}
			if seen[t] {
				return nil, fmt.Errorf("agentbox: mount target %q used twice", t)
			}
			seen[t] = true
			out = append(out, Mount{Source: src, Target: t})
		}
		return out, nil
	}
	if s.ReadOnly, err = norm(s.ReadOnly); err != nil {
		return s, err
	}
	if s.Writable, err = norm(s.Writable); err != nil {
		return s, err
	}
	var deny []string
	for _, d := range s.Deny {
		if d == "" || !filepath.IsAbs(d) {
			return s, fmt.Errorf("agentbox: deny %q is not an absolute path", d)
		}
		r, err := filepath.EvalSymlinks(d)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return s, fmt.Errorf("agentbox: deny %q: %w", d, err)
		}
		deny = append(deny, r)
	}
	s.Deny = deny
	switch s.Network.Mode {
	case "", NetworkNone:
		if s.Network.Gateway != "" {
			return s, errors.New("agentbox: a gateway needs network mode \"gateway\"")
		}
		s.Network.Mode = NetworkNone
	case NetworkGateway:
		p, err := hostPath(s.Network.Gateway)
		if err != nil {
			return s, fmt.Errorf("agentbox: gateway: %w", err)
		}
		if fi, err := os.Stat(p); err != nil || fi.Mode()&os.ModeSocket == 0 {
			return s, fmt.Errorf("agentbox: gateway %q is not a Unix socket", p)
		}
		s.Network.Gateway = p
	default:
		return s, fmt.Errorf("agentbox: network %q not supported (none, gateway)", s.Network.Mode)
	}
	// ModelSocket is shorthand for one ModelSockets entry.
	socks := s.ModelSockets
	if s.ModelSocket != "" {
		socks = append([]string{s.ModelSocket}, socks...)
	}
	s.ModelSocket, s.ModelSockets = "", nil
	names := map[string]bool{}
	for _, sock := range socks {
		p, err := hostPath(sock)
		if err != nil {
			return s, fmt.Errorf("agentbox: model socket: %w", err)
		}
		fi, err := os.Stat(p)
		if err != nil || fi.Mode()&os.ModeSocket == 0 {
			return s, fmt.Errorf("agentbox: model socket %q is not a Unix socket", p)
		}
		if names[filepath.Base(p)] {
			return s, fmt.Errorf("agentbox: two model sockets named %q", filepath.Base(p))
		}
		names[filepath.Base(p)] = true
		s.ModelSockets = append(s.ModelSockets, p)
	}
	for _, p := range s.HostPorts {
		if p < 1 || p > 65535 {
			return s, fmt.Errorf("agentbox: host port %d out of range", p)
		}
	}
	if s.Limits.MemoryBytes < 0 || s.Limits.CPUs < 0 || s.Limits.PIDs < 0 {
		return s, errors.New("agentbox: negative limit")
	}
	for _, e := range s.Env {
		if !strings.Contains(e, "=") {
			return s, fmt.Errorf("agentbox: env entry %q is not KEY=VALUE", e)
		}
	}
	return s, nil
}

// hostPath resolves p to an existing absolute path with no symlinks, so the
// mount source cannot be swapped through a link later. "/" is refused.
func hostPath(p string) (string, error) {
	if p == "" || !filepath.IsAbs(p) {
		return "", fmt.Errorf("%q is not an absolute path", p)
	}
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		return "", err
	}
	if r == "/" {
		return "", errors.New("the host root cannot be mounted")
	}
	return r, nil
}

func hostDir(p string) (string, error) {
	r, err := hostPath(p)
	if err != nil {
		return "", err
	}
	if fi, err := os.Stat(r); err != nil || !fi.IsDir() {
		return "", fmt.Errorf("%q is not a directory", p)
	}
	return r, nil
}
