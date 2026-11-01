package gvisor

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestReadUsage(t *testing.T) {
	d := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(d, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok := readUsage(d); ok {
		t.Fatal("measured a cgroup with no memory.peak")
	}
	write("memory.peak", "734003200\n")
	write("cpu.stat", "usage_usec 12500000\nuser_usec 10000000\nsystem_usec 2500000\n")
	write("memory.events", "low 0\nhigh 0\nmax 3\noom 1\noom_kill 1\noom_group_kill 0\n")
	u, ok := readUsage(d)
	if !ok || u.MemoryPeakBytes != 734003200 || u.CPUTime != 12500*time.Millisecond || u.OOMKills != 1 {
		t.Errorf("usage %+v %v", u, ok)
	}
	if statField(filepath.Join(d, "memory.events"), "oom") != 1 || statField(filepath.Join(d, "nope"), "x") != 0 {
		t.Error("statField")
	}
}

// A sandbox without a scope is not measured.
func TestUnmeasuredSandbox(t *testing.T) {
	s := &sandbox{done: make(chan struct{})}
	if _, ok := s.Usage(); ok {
		t.Error("an unscoped sandbox reported usage")
	}
}
