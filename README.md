# agentbox

Run untrusted agent-generated commands in sandboxes, **as a normal user**: gVisor on Linux,
Seatbelt on macOS (weaker; see below). The caller decides what a sandbox may do; agentbox
enforces it and fails closed when it can't.
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

## macOS: Seatbelt

`seatbelt.New(seatbelt.Config{})` (the CLI picks it on macOS) runs each command under
`sandbox-exec` with a profile built from the same `Spec`: reads limited to the system paths,
workspace and mounts; writes to the workspace, writable mounts and a private `TMPDIR`; `Deny`
over both; no network except `HostPorts` on the host's loopback; Mach lookups limited to a few
services (no keychain, no DNS); signals only within the sandbox. Close kills the commands' process
groups and every process still under the sandbox's profile (cgo build).

It is weaker than gVisor, and its `Capabilities` say so: the host's kernel and network stack (no
`NetworkGateway`, no `ModelSockets`), mounts that keep their paths (no `/workspace`), and no
memory, CPU or process limits (a `Spec` asking for one is refused). Nothing to install.

## Develop on macOS

```bash
make test                     # unit tests, and the Seatbelt backend for real
make test-linux               # all tests, real rootless runsc, in a Linux container (on Linux: here)
scripts/phase0-docker.sh      # Phase 0 checks in a container
```
