#!/usr/bin/env bash
# Phase 0 (design §10): can this host run rootless runsc the way agentbox
# needs? Run as the user agent-runner runs as, never as root:
#
#   scripts/phase0.sh
#
# Each check prints PASS, FAIL or SKIP (with why). Env: RUNSC (default
# runsc on PATH), KEEP=1 to keep the work dir.

set -uo pipefail
# Default: the root-owned copy scripts/install-runsc.sh installs, else PATH.
RUNSC=${RUNSC:-$( [ -x /usr/local/bin/runsc ] && echo /usr/local/bin/runsc || echo runsc )}
W=$(mktemp -d "${TMPDIR:-/tmp}/agentbox-phase0.XXXXXX")
STATE=$W/state
trap 'if [ "${KEEP:-}" = 1 ]; then echo "kept $W"; else "$RUNSC" --root "$STATE" delete -force p0 >/dev/null 2>&1; rm -rf "$W"; fi' EXIT

pass() { printf 'PASS  %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*"; FAILED=1; }
skip() { printf 'SKIP  %s\n' "$*"; }
FAILED=0

echo "== host"
[ "$(id -u)" != 0 ] || { echo "run this as the runner's user, not root" >&2; exit 2; }
echo "user: $(id -un) ($(id -u):$(id -g))"
echo "os: $(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-?}"); kernel: $(uname -r); arch: $(uname -m)"
command -v "$RUNSC" >/dev/null || { fail "runsc not found (RUNSC=$RUNSC): install it with scripts/install-runsc.sh"; exit 1; }
echo "runsc: $("$RUNSC" --version 2>/dev/null | head -1)"
if unshare -Ur true 2>/dev/null; then pass "unprivileged user namespaces"
elif [ "$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null)" = 1 ]; then
	if [ -f /etc/apparmor.d/agentbox-runsc ]; then
		skip "unshare: AppArmor restricts user namespaces; runsc has its own profile, so the runsc checks below decide"
	else
		fail "AppArmor restricts unprivileged user namespaces and runsc has no profile: run scripts/install-runsc.sh"
	fi
else fail "unprivileged user namespaces (unshare -Ur) are disabled on this kernel"; fi
if [ -f /sys/fs/cgroup/cgroup.controllers ]; then pass "cgroup v2"; else fail "cgroup v2 not mounted"; fi
SYSTEMD_USER=0
if command -v systemd-run >/dev/null && systemctl --user show-environment >/dev/null 2>&1; then
	SYSTEMD_USER=1; pass "systemd user manager"
else skip "systemd user manager not reachable (no user session here): scope limits cannot be tested"; fi

# A rootfs of host binds (design §6 Filesystem, option b): the system dirs
# read-only, the usrmerge symlinks recreated, a writable workspace.
mkdir -p "$W/rootfs" "$W/ws" "$W/sock" "$STATE"
for d in usr etc opt; do [ -d /$d ] && mkdir -p "$W/rootfs/$d"; done
for l in bin sbin lib lib32 lib64 libx32; do
	if [ -L /$l ]; then ln -s "$(readlink /$l)" "$W/rootfs/$l"
	elif [ -d /$l ]; then mkdir -p "$W/rootfs/$l"; fi
done
mkdir -p "$W/rootfs/workspace" "$W/rootfs/tmp" "$W/rootfs/sock" "$W/rootfs/proc" "$W/rootfs/dev" # mount points: the rootfs is read-only
printf '#!/bin/sh\necho SCRIPT_OK\n' >"$W/ws/script.sh" && chmod +x "$W/ws/script.sh"

# bundle NAME ARGS...: an OCI bundle running ARGS, with RLIMIT_NPROC=$NPROC
# (default 64; NPROC=0 for none). No user namespace in the
# spec and uid 0 inside: with --rootless, runsc maps the sandbox's root to
# the caller, so what it writes on the host belongs to the caller (design §6
# Identity). Mapping a non-zero uid instead failed (gofer fork/exec EPERM).
bundle() {
	local dir=$W/b-$1; shift
	mkdir -p "$dir"
	python3 - "$dir/config.json" "$W" "${NPROC:-64}" "$@" <<'PY'
import json, os, sys
out, w, nproc, args = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4:]
ro = lambda p: {"destination": p, "type": "bind", "source": p, "options": ["rbind", "ro"]}
mounts = [{"destination": "/proc", "type": "proc", "source": "proc"},
          {"destination": "/dev", "type": "tmpfs", "source": "tmpfs"},
          {"destination": "/tmp", "type": "tmpfs", "source": "tmpfs"},
          {"destination": "/workspace", "type": "bind", "source": w + "/ws", "options": ["rbind", "rw"]},
          {"destination": "/sock", "type": "bind", "source": w + "/sock", "options": ["rbind", "rw"]}]
mounts += [ro(p) for p in ("/usr", "/etc", "/opt") if os.path.isdir(p)]
mounts += [ro("/" + p) for p in ("lib", "lib32", "lib64", "libx32") if os.path.isdir("/" + p) and not os.path.islink("/" + p)]
cfg = {"ociVersion": "1.0.2",
       "process": {"user": {"uid": 0, "gid": 0}, "args": args, "cwd": "/workspace",
                   "env": ["PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/workspace"],
                   "rlimits": [{"type": "RLIMIT_NPROC", "hard": nproc, "soft": nproc}] if nproc else [],
                   "noNewPrivileges": True},
       "root": {"path": w + "/rootfs", "readonly": True},
       "hostname": "agentbox-p0",
       "mounts": mounts,
       "linux": {"namespaces": [{"type": t} for t in ("pid", "ipc", "uts", "mount", "network")]}}
json.dump(cfg, open(out, "w"), indent=1)
PY
	echo "$dir"
}

R=("$RUNSC" --root "$STATE" --rootless --network=none --ignore-cgroups)
# DEBUG=1: runsc's own logs, printed on failure.
[ "${DEBUG:-}" = 1 ] && R+=(--debug --debug-log="$W/logs/")

echo "== runsc do (the simplest rootless path)"
if out=$("${R[@]}" do -- /bin/sh -c 'echo DO_OK' 2>&1) && [[ $out == *DO_OK* ]]; then pass "runsc --rootless do"
else fail "runsc --rootless do: $(tail -c 300 <<<"$out")"; fi

echo "== OCI lifecycle: a held run, exec, delete"
# Rootless runsc refuses "create", and "run --detach" stops at once: nothing
# holds the sandbox. Like Podman's conmon, agentbox keeps a foreground
# "runsc run" alive for the sandbox's lifetime and execs into it.
B=$(bundle p0 /bin/sleep 300)
out=$("${R[@]}" create --bundle "$B" p0 2>&1); echo "      create: $(tail -c 120 <<<"$out")"
"${R[@]}" delete -force p0 >/dev/null 2>&1
"${R[@]}" run --bundle "$B" p0 >"$W/held.log" 2>&1 &
HELD=$!
started=""
for _ in $(seq 50); do
	"$RUNSC" --root "$STATE" --rootless state p0 2>/dev/null | grep -q '"running"' && { started="held run"; break; }
	sleep 0.2
done
[ -n "$started" ] || out=$(cat "$W/held.log")
if [ -z "$started" ] && [ "${DEBUG:-}" = 1 ]; then
	echo "      --- runsc logs (warnings/errors) ---"
	for f in "$W"/logs/*gofer* "$W"/logs/*boot*; do echo "      $(basename "$f"):"; grep -v 'config.go' "$f" | tail -8 | cut -c1-260; done
fi
if [ -n "$started" ]; then
	pass "$started (rootless, network none, rootfs of host binds)"
	if out=$("${R[@]}" exec p0 /bin/sh -c 'id -u; ls /; echo EXEC_OK' 2>&1) && [[ $out == *EXEC_OK* ]]; then
		pass "exec into a running sandbox"
		echo "      uid inside: $(head -1 <<<"$out") (the sandbox's root; the caller on the host)"
	else fail "exec: $(tail -c 300 <<<"$out")"; fi
	out=$("${R[@]}" exec p0 /workspace/script.sh 2>&1)
	[[ $out == *SCRIPT_OK* ]] && pass "#!/bin/sh script starts (usrmerge symlinks recreated)" || fail "#!/bin/sh script: $(tail -c 200 <<<"$out")"
	"${R[@]}" exec p0 /bin/sh -c 'echo x > /workspace/made-inside' >/dev/null 2>&1
	if [ -e "$W/ws/made-inside" ]; then
		owner=$(stat -c %u:%g "$W/ws/made-inside")
		[ "$owner" = "$(id -u):$(id -g)" ] && pass "workspace file owned by the caller ($owner)" || fail "workspace file owned by $owner, want $(id -u):$(id -g)"
	else fail "could not write the workspace"; fi
	out=$("${R[@]}" exec p0 /bin/sh -c 'cat /etc/shadow 2>&1; ls /home /root 2>&1' 2>&1)
	[[ $out == *root:* ]] && fail "read /etc/shadow" || pass "/etc/shadow unreadable (no secrets through the /etc bind)"
	out=$("${R[@]}" exec p0 /bin/sh -c 'curl -sS -m 3 http://1.1.1.1/ 2>&1 || echo NO_NET' 2>&1)
	[[ $out == *NO_NET* ]] && pass "no network" || fail "network reachable: $(tail -c 120 <<<"$out")"
	# Fork bomb against RLIMIT_NPROC from the OCI spec (process.rlimits).
	out=$("${R[@]}" exec p0 /bin/sh -c 'b() { b | b & }; b; sleep 3; echo ALIVE' 2>&1)
	if [[ $out == *ALIVE* ]] && "${R[@]}" exec p0 /bin/true >/dev/null 2>&1; then
		pass "fork bomb contained by process.rlimits RLIMIT_NPROC; sandbox alive"
	else fail "fork bomb: $(tail -c 200 <<<"$out")"; fi
	"${R[@]}" kill p0 KILL >/dev/null 2>&1; wait "$HELD" 2>/dev/null
	if "${R[@]}" delete -force p0 >/dev/null 2>&1; then pass "delete"; else fail "delete"; fi
	left=$(pgrep -u "$(id -u)" -f "runsc.*p0" | wc -l | tr -d ' ')
	[ "$left" = 0 ] && pass "no runsc processes left" || fail "$left runsc processes left"
else
	fail "create/start: $(tail -c 400 <<<"$out")"
fi

echo "== model channel: host Unix socket mounted into the sandbox"
python3 - "$W/sock/model.sock" >"$W/uds.log" 2>&1 <<'PY' &
import os, socket, sys
p = sys.argv[1]
s = socket.socket(socket.AF_UNIX); s.bind(p); os.chmod(p, 0o666); s.listen(1)
c, _ = s.accept(); c.recv(100); c.sendall(b"MODEL_OK\n"); c.close()
PY
UDS=$!
for _ in $(seq 30); do [ -S "$W/sock/model.sock" ] && break; sleep 0.1; done
B=$(bundle uds python3 -c 'import socket; s=socket.socket(socket.AF_UNIX); s.connect("/sock/model.sock"); s.sendall(b"hi"); print(s.recv(100).decode())')
for mode in "--host-uds=open" ""; do
	out=$("$RUNSC" --root "$STATE" --rootless --network=none --ignore-cgroups $mode run --bundle "$B" uds 2>&1)
	"$RUNSC" --root "$STATE" delete -force uds >/dev/null 2>&1
	if [[ $out == *MODEL_OK* ]]; then pass "connect to a mounted host socket (${mode:-no --host-uds})"; break
	else echo "      (${mode:-no --host-uds}): $(tail -c 160 <<<"$out")"; fi
done
[[ ${out:-} == *MODEL_OK* ]] || fail "no way to reach a mounted host socket"
kill $UDS 2>/dev/null

echo "== limits through a systemd user scope"
# scope NAME PROPS... -- ARGS: run a sandbox (no RLIMIT_NPROC) in a transient
# user scope with those limits; sets RC and OUT.
scope() {
	local name=$1; shift; local props=()
	while [ "$1" != -- ]; do props+=(-p "$1"); shift; done; shift
	local b; b=$(NPROC=0 bundle "$name" "$@")
	OUT=$(timeout 90 systemd-run --user --scope -q "${props[@]}" \
		"$RUNSC" --root "$STATE" --rootless --network=none --ignore-cgroups run --bundle "$b" "$name" 2>&1)
	RC=$?
	"$RUNSC" --root "$STATE" delete -force "$name" >/dev/null 2>&1
}
if [ "$SYSTEMD_USER" = 1 ]; then
	scope s1 MemoryMax=1G TasksMax=512 -- /bin/sh -c 'echo SCOPE_OK'
	if [[ $OUT == *SCOPE_OK* ]]; then pass "a sandbox runs in a user scope (MemoryMax=1G, TasksMax=512)"
	else fail "a sandbox in a user scope: exit $RC: $(tail -c 300 <<<"$OUT")"; fi

	# TasksMax as the only limiter: does fork() fail inside, or does runsc die?
	scope s2 MemoryMax=1G TasksMax=256 -- /bin/sh -c 'b() { b | b & }; b; sleep 5; echo BOMB_ALIVE'
	if [[ $OUT == *BOMB_ALIVE* ]]; then pass "fork bomb under TasksMax=256 alone: contained, sandbox alive"
	elif "$RUNSC" --root "$STATE" list 2>/dev/null | grep -q s2; then fail "fork bomb under TasksMax: sandbox left behind (exit $RC)"
	else echo "INFO  fork bomb under TasksMax=256 alone: the sandbox ended (exit $RC), host fine: $(tail -c 200 <<<"$OUT")"
		echo "      (like isobox --pids, the cap counts runsc's own threads: keep RLIMIT_NPROC as the per-sandbox limiter)"; fi

	# MemoryMax: allocate past the cap; the sandbox must end, nothing else.
	scope s3 MemoryMax=512M TasksMax=512 -- python3 -c 'b=[]
while True: b.append(bytearray(64<<20))'
	if [ "$RC" -ne 0 ] && ! "$RUNSC" --root "$STATE" list 2>/dev/null | grep -q s3; then
		pass "memory past MemoryMax=512M ends the sandbox (exit $RC), nothing left behind"
	else fail "MemoryMax not enforced: exit $RC: $(tail -c 200 <<<"$OUT")"; fi
else skip "no systemd user manager here"; fi

echo "== result"
[ "$FAILED" = 0 ] && echo "all checks passed" || echo "some checks FAILED"
exit "$FAILED"
