# agentbox

Run untrusted agent-generated commands in sandboxes, **as a normal user**: gVisor on Linux,
Seatbelt on macOS (weaker; see below). The caller decides what a sandbox may do; agentbox
enforces it and fails closed when it can't.
Design: [agentbox-design.md](agentbox-design.md).

## Quick start

**Linux** (gVisor), once per host, as the user agentbox will run as (the install steps use sudo;
the build does not):

```bash
sudo apt install iproute2 nftables     # for the gateway network
git clone https://github.com/tendant/agentbox && cd agentbox
make install    # runsc (pinned, sha512-checked) and the agentbox CLI into /usr/local/bin, plus
                # the AppArmor profiles Ubuntu 23.10+ needs for runsc and agentbox-unshare
make check      # agentbox doctor and the Phase 0 checks: what this host supports
agentbox run --workspace "$PWD" --memory 1g --pids 512 -- make test
```

**macOS** (Seatbelt): nothing to install.

```bash
go install github.com/tendant/agentbox/cmd/agentbox@latest
agentbox doctor
agentbox run --workspace "$PWD" -- make test
```

`make uninstall` removes the Linux setup. `PREFIX` and `GVISOR_RELEASE` override the defaults.

## Use from Go

```bash
go get github.com/tendant/agentbox@latest
```

```go
var b agentbox.Backend = gvisor.New(gvisor.Config{}) // macOS: seatbelt.New(seatbelt.Config{})
sb, err := b.Create(ctx, agentbox.Spec{
    ID:        "task-1",
    Workspace: "/srv/agent/work/task-1",           // read-write (at /workspace on gVisor)
    ReadOnly:  []agentbox.Mount{{Source: "/srv/agent/memory"}},
    Limits:    agentbox.Limits{MemoryBytes: 4 << 30, PIDs: 1024}, // gVisor only: Seatbelt refuses limits
})
defer sb.Close(ctx)
res, err := sb.Exec(ctx, agentbox.Command{Args: []string{"make", "test"}, Stdout: os.Stdout, Timeout: time.Hour})
```

`b.Capabilities(ctx)` says what this host can enforce; `Create` refuses a `Spec` needing anything
else. `agentbox.Commander` (`sb.(agentbox.Commander).Cmd`) hands back an unstarted `*exec.Cmd`
for callers that stream a command's output themselves.

## Linux: gVisor

What a sandbox gets: the host's `/usr`, `/etc`, `/opt` and libraries read-only (usrmerge
symlinks recreated), the workspace read-write, its own `/tmp`, no network, optional model
sockets at `/run/agentbox/`, a process limit (`RLIMIT_NPROC`), and memory/CPU limits through a
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
memory, CPU or process limits (a `Spec` asking for one is refused).

## Develop

```bash
make test                     # unit tests (on macOS also the Seatbelt backend, for real)
make test-linux               # all tests against real rootless runsc: a Linux container from a
                              # Mac, this host on Linux
make lint                     # gofmt, go vet for Linux and macOS
make release VERSION=vX.Y.Z   # from a clean, pushed main: lint, test, tag, GitHub release
```

Release only after `make test-linux` (and, for agent-runner, its sandbox smoke on a real host)
passes: the release target cannot reach runsc from a Mac.
