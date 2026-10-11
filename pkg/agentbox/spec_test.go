package agentbox

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNormalize(t *testing.T) {
	ws := t.TempDir()
	data := t.TempDir()
	link := filepath.Join(t.TempDir(), "link")
	os.Symlink(data, link)
	real, _ := filepath.EvalSymlinks(data)

	s, err := Spec{ID: "s1", Workspace: ws, ReadOnly: []Mount{{Source: link, Target: "/data"}}}.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	if s.ReadOnly[0].Source != real {
		t.Errorf("a symlinked source must resolve: %q, want %q", s.ReadOnly[0].Source, real)
	}
	if s.Network.Mode != NetworkNone {
		t.Errorf("network defaults to none, got %q", s.Network.Mode)
	}
	// The target defaults to the source path (outside reserved ones like /tmp).
	src, err := os.MkdirTemp(".", "src-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(src)
	src, _ = filepath.Abs(src)
	src, _ = filepath.EvalSymlinks(src)
	if s2, err := (Spec{ID: "s1", Workspace: ws, Writable: []Mount{{Source: src}}}).Normalize(); err != nil || s2.Writable[0].Target != src {
		t.Errorf("target defaults to the source path: %v %+v", err, s2.Writable)
	}

	bad := map[string]Spec{
		"bad id":           {ID: "a/b", Workspace: ws},
		"no workspace":     {ID: "s"},
		"relative":         {ID: "s", Workspace: "ws"},
		"workspace file":   {ID: "s", Workspace: filepath.Join(ws, "missing")},
		"host root":        {ID: "s", Workspace: ws, ReadOnly: []Mount{{Source: "/", Target: "/host"}}},
		"reserved target":  {ID: "s", Workspace: ws, ReadOnly: []Mount{{Source: data, Target: "/workspace/x"}}},
		"proc target":      {ID: "s", Workspace: ws, ReadOnly: []Mount{{Source: data, Target: "/proc"}}},
		"tmp itself":       {ID: "s", Workspace: ws, ReadOnly: []Mount{{Source: data, Target: "/tmp"}}},
		"unclean target":   {ID: "s", Workspace: ws, ReadOnly: []Mount{{Source: data, Target: "/a/../b"}}},
		"duplicate target": {ID: "s", Workspace: ws, ReadOnly: []Mount{{Source: data, Target: "/d"}}, Writable: []Mount{{Source: ws, Target: "/d"}}},
		"network":          {ID: "s", Workspace: ws, Network: NetworkPolicy{Mode: "outbound"}},
		"socket not one":   {ID: "s", Workspace: ws, ModelSocket: filepath.Join(ws)},
		"negative limit":   {ID: "s", Workspace: ws, Limits: Limits{PIDs: -1}},
		"bad env":          {ID: "s", Workspace: ws, Env: []string{"NOEQUALS"}},
		"gateway not sock": {ID: "s", Workspace: ws, Network: NetworkPolicy{Mode: NetworkGateway, Gateway: ws}},
		"gateway missing":  {ID: "s", Workspace: ws, Network: NetworkPolicy{Mode: NetworkGateway}},
		"gateway, no mode": {ID: "s", Workspace: ws, Network: NetworkPolicy{Gateway: ws}},
	}
	for name, sp := range bad {
		if _, err := sp.Normalize(); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}

	// A real Unix socket is accepted.
	sock := filepath.Join(t.TempDir(), "m.sock")
	if len(sock) < 100 {
		l, err := net.Listen("unix", sock)
		if err == nil {
			defer l.Close()
			if _, err := (Spec{ID: "s", Workspace: ws, ModelSocket: sock}).Normalize(); err != nil && !strings.Contains(err.Error(), "socket") {
				t.Errorf("socket: %v", err)
			} else if err != nil {
				t.Errorf("a Unix socket must be accepted: %v", err)
			}
			if _, err := (Spec{ID: "s", Workspace: ws, Network: NetworkPolicy{Mode: NetworkGateway, Gateway: sock}}).Normalize(); err != nil {
				t.Errorf("a gateway socket must be accepted: %v", err)
			}
		}
	}
}
