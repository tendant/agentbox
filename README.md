# agentbox

Run untrusted agent-generated commands in gVisor sandboxes on Linux, **as a normal user**. The
caller decides what a sandbox may do; agentbox enforces it and fails closed when it can't.
Design: [agentbox-design.md](agentbox-design.md).

## Host setup (once, by an admin)

As the user agentbox will run as (the install steps use sudo; the build does not):

```bash
sudo apt install iproute2 nftables   # for the gateway network
make install    # runsc (pinned, sha512-checked) and the agentbox CLI into /usr/local/bin, plus
                # the AppArmor profiles Ubuntu 23.10+ needs for runsc and agentbox-unshare
make check      # agentbox doctor and the Phase 0 checks: what this host supports
```

`make uninstall` removes all of it. `PREFIX` and `GVISOR_RELEASE` override the defaults.

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

**Network.** None by default (loopback only). With `Network: agentbox.NetworkPolicy{Mode:
agentbox.NetworkGateway, Gateway: "/run/me/egress.sock"}` (CLI: `--gateway`), the sandbox gets a
private network namespace in which every TCP connection, to any address and port, whether or
not the program honours proxy settings, reaches that Unix socket as `CONNECT host:port`. DNS is
answered inside with stand-in addresses (198.18.0.0/15), so the CONNECT names the host the
program asked for; HTTPS and HTTP to a literal address carry the TLS server name or Host header.
Other UDP, ICMP and IPv6 are dropped. The gateway decides what is allowed; agentbox has no policy
of its own.

## Develop on macOS

```bash
make test                     # unit tests
make test-linux               # all tests, real rootless runsc, in a Linux container (on Linux: here)
scripts/phase0-docker.sh      # Phase 0 checks in a container
```
