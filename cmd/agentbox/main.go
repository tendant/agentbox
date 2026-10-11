// Command agentbox runs a command in a sandbox, for smoke testing and
// debugging:
//
//	agentbox doctor
//	agentbox run --workspace DIR [--ro SRC[:DST]]... [--rw SRC[:DST]]... \
//	    [--memory 1g] [--cpus 2] [--pids 512] [--timeout 60s] [--gateway SOCK] -- CMD [ARGS...]
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/tendant/agentbox/pkg/agentbox"
	"github.com/tendant/agentbox/pkg/agentbox/gvisor"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	switch os.Args[1] {
	case "doctor":
		os.Exit(doctor(ctx))
	case "run":
		os.Exit(run(ctx, os.Args[2:]))
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: agentbox doctor | agentbox run --workspace DIR [flags] -- CMD [ARGS...]")
	os.Exit(2)
}

func doctor(ctx context.Context) int {
	c, err := gvisor.New(gvisor.Config{}).Capabilities(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "agentbox:", err)
		return 1
	}
	for _, x := range []struct {
		name string
		ok   bool
	}{{"rootless gVisor", c.Rootless}, {"no network", c.NetworkNone}, {"model socket", c.ModelSocket},
		{"several commands per sandbox", c.Persistent}, {"process limit (RLIMIT_NPROC)", c.PIDLimit},
		{"memory limit (systemd user scope)", c.MemoryLimit}, {"CPU limit (systemd user scope)", c.CPULimit},
		{"gateway network (all TCP and DNS to a gateway socket)", c.Gateway}} {
		mark := "no "
		if x.ok {
			mark = "yes"
		}
		fmt.Printf("%s  %s\n", mark, x.name)
	}
	for _, n := range c.Notes {
		fmt.Println("note:", n)
	}
	if !c.Rootless {
		return 1
	}
	return 0
}

type mounts []agentbox.Mount

func (m *mounts) String() string { return fmt.Sprint(*m) }
func (m *mounts) Set(v string) error {
	src, dst, _ := strings.Cut(v, ":")
	*m = append(*m, agentbox.Mount{Source: src, Target: dst})
	return nil
}

func run(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	ws := fs.String("workspace", "", "host directory mounted read-write at /workspace (required)")
	var ro, rw mounts
	fs.Var(&ro, "ro", "read-only mount SRC[:DST] (repeatable)")
	fs.Var(&rw, "rw", "writable mount SRC[:DST] (repeatable)")
	mem := fs.String("memory", "", "memory limit (e.g. 1g, 512m)")
	cpus := fs.Float64("cpus", 0, "CPU limit in cores")
	pids := fs.Int64("pids", 0, "process/thread limit")
	timeout := fs.Duration("timeout", 0, "command timeout")
	socket := fs.String("model-socket", "", "host Unix socket reachable at /run/agentbox/<name>")
	gateway := fs.String("gateway", "", "host Unix socket serving HTTP CONNECT: every TCP connection goes there")
	fs.Parse(args)
	if *ws == "" || fs.NArg() == 0 {
		usage()
	}
	memBytes, err := parseBytes(*mem)
	if err != nil {
		fmt.Fprintln(os.Stderr, "agentbox:", err)
		return 2
	}
	spec := agentbox.Spec{
		ID:          fmt.Sprintf("cli-%d-%d", os.Getpid(), time.Now().UnixNano()%100000),
		Workspace:   *ws,
		ReadOnly:    ro,
		Writable:    rw,
		ModelSocket: *socket,
		Limits:      agentbox.Limits{MemoryBytes: memBytes, CPUs: *cpus, PIDs: *pids},
	}
	if *gateway != "" {
		spec.Network = agentbox.NetworkPolicy{Mode: agentbox.NetworkGateway, Gateway: *gateway}
	}
	sb, err := gvisor.New(gvisor.Config{}).Create(ctx, spec)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer sb.Close(context.Background())
	res, err := sb.Exec(ctx, agentbox.Command{Args: fs.Args(), Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr, Timeout: *timeout})
	if err != nil {
		fmt.Fprintln(os.Stderr, "agentbox:", err)
		return 1
	}
	if res.TimedOut {
		fmt.Fprintln(os.Stderr, "agentbox: command timed out")
		return 124
	}
	return res.ExitCode
}

// parseBytes reads "1g", "512m", "64k" or a byte count.
func parseBytes(s string) (int64, error) {
	if s == "" {
		return 0, nil
	}
	mult := int64(1)
	switch strings.ToLower(s[len(s)-1:]) {
	case "k":
		mult = 1 << 10
	case "m":
		mult = 1 << 20
	case "g":
		mult = 1 << 30
	}
	if mult > 1 {
		s = s[:len(s)-1]
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 {
		return 0, errors.New("bad size " + s)
	}
	return n * mult, nil
}
