# agentbox

Run untrusted agent-generated commands in gVisor sandboxes on Linux, **as a normal user**. The
caller decides what a sandbox may do; agentbox enforces it and fails closed when it can't.
Design: [agentbox-design.md](agentbox-design.md).

## Host setup (once, by an admin)

```bash
scripts/install-runsc.sh   # gVisor runsc into /usr/local/bin, plus the AppArmor profile
                           # Ubuntu 23.10+ needs for rootless runsc
scripts/phase0.sh          # as the user agentbox will run as: checks what this host supports
```

## Use

```go
b := gvisor.New(gvisor.Config{})
sb, err := b.Create(ctx, agentbox.Spec{
    ID:        "task-1",
    Workspace: "/srv/agent/work/task-1",           // read-write at /workspace
    ReadOnly:  []agentbox.Mount{{Source: "/srv/agent/memory"}},
    Limits:    agentbox.Limits{MemoryBytes: 4 << 30, PIDs: 1024},
})
defer sb.Close(ctx)
res, err := sb.Exec(ctx, agentbox.Command{Args: []string{"make", "test"}, Stdout: os.Stdout, Timeout: time.Hour})
```

```bash
go build -o agentbox ./cmd/agentbox
agentbox doctor
agentbox run --workspace "$PWD" --memory 1g --pids 512 -- make test
```

What a sandbox gets: the host's `/usr`, `/etc`, `/opt` and libraries read-only (usrmerge
symlinks recreated), the workspace read-write, its own `/tmp`, no network, an optional model
socket at `/run/agentbox/`, a process limit (`RLIMIT_NPROC`), and memory/CPU limits through a
systemd user scope. Files it writes belong to the caller.

## Develop on macOS

```bash
go test ./...                 # unit tests
scripts/test-linux.sh         # all tests, real rootless runsc, in a Linux container
scripts/phase0-docker.sh      # Phase 0 checks in a container
```
