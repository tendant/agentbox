#!/usr/bin/env bash
# Phase 0 for transparent egress: can every TCP connection and DNS query from
# a rootless gVisor sandbox be caught and handed to the egress gateway,
# without proxy settings and without root? Run as the runner's user:
#
#   scripts/phase0-transparent.sh
#
# The design under test: runsc with host networking inside a private network
# namespace agentbox creates (unshare -n, as a user namespace); nftables there
# redirects all TCP to a local catcher and DNS to a local responder; the
# catcher recovers the original destination (SO_ORIGINAL_DST), peeks the TLS
# server name, and relays over a Unix socket to the gateway outside.
#
# Env: RUNSC (default /usr/local/bin/runsc, else PATH), KEEP=1. Where AppArmor
# restricts user namespaces (Ubuntu 23.10+), the namespace is made with
# /usr/local/bin/agentbox-unshare (scripts/install-runsc.sh installs it with a
# profile, like runsc's); elsewhere plain unshare works.

set -uo pipefail
RUNSC=${RUNSC:-$( [ -x /usr/local/bin/runsc ] && echo /usr/local/bin/runsc || echo runsc )}
UNSHARE=${UNSHARE:-$( [ -x /usr/local/bin/agentbox-unshare ] && echo /usr/local/bin/agentbox-unshare || echo unshare )}
W=$(mktemp -d "${TMPDIR:-/tmp}/abx-tp.XXXXXX")
trap 'if [ "${KEEP:-}" = 1 ]; then echo "kept $W"; else rm -rf "$W"; fi' EXIT
[ "$(id -u)" != 0 ] || { echo "run as the runner's user, not root" >&2; exit 2; }
for t in unshare ip nft python3 curl; do
	command -v "$t" >/dev/null || { echo "FAIL  missing $t (apt install iproute2 nftables python3 curl util-linux)"; exit 1; }
done
command -v "$RUNSC" >/dev/null || { echo "FAIL  runsc not found: scripts/install-runsc.sh"; exit 1; }
echo "== host: $(. /etc/os-release; echo "$PRETTY_NAME"), kernel $(uname -r), $("$RUNSC" --version | head -1)"

# Outside the namespace: a Unix socket server standing in for the gateway.
python3 - "$W/gw.sock" >"$W/gw.log" 2>&1 <<'PY' &
import os, socket, sys
s = socket.socket(socket.AF_UNIX); s.bind(sys.argv[1]); s.listen(8)
while True:
    c, _ = s.accept(); c.sendall(b"GATEWAY_OK\n"); c.close()
PY
GW=$!
trap 'kill $GW 2>/dev/null; if [ "${KEEP:-}" = 1 ]; then echo "kept $W"; else rm -rf "$W"; fi' EXIT
for _ in $(seq 30); do [ -S "$W/gw.sock" ] && break; sleep 0.1; done

# The catcher: a transparent TCP listener that reports the original
# destination and, for TLS, the server name; and a DNS responder answering
# every A query with 203.0.113.7.
cat >"$W/catcher.py" <<'PY'
import socket, struct, sys, threading
SO_ORIGINAL_DST = 80
def sni(data):
    try:
        if data[0] != 0x16: return ""
        p = 43; p += 1 + data[p]                      # session id
        p += 2 + struct.unpack(">H", data[p:p+2])[0]  # cipher suites
        p += 1 + data[p]                              # compression
        end = p + 2 + struct.unpack(">H", data[p:p+2])[0]; p += 2
        while p + 4 <= end:
            t, l = struct.unpack(">HH", data[p:p+4]); p += 4
            if t == 0: return data[p+5:p+l].decode()
            p += l
    except Exception: pass
    return ""
def handle(c):
    raw = c.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
    port, ip = struct.unpack("!H", raw[2:4])[0], socket.inet_ntoa(raw[4:8])
    c.settimeout(3)
    try: first = c.recv(4096)
    except Exception: first = b""
    name = sni(first)
    u = socket.socket(socket.AF_UNIX); u.connect(sys.argv[1]); gw = u.recv(64).decode().strip()
    print(f"CAUGHT {ip}:{port} sni={name} gw={gw}", flush=True)
    try: c.sendall(f"HTTP/1.0 200 OK\r\n\r\nCAUGHT {ip}:{port}\n".encode())
    except Exception: pass
    c.close()
t = socket.socket(); t.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
t.bind(("127.0.0.1", 15001)); t.listen(16)
def dns():
    d = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); d.bind(("127.0.0.1", 15053))
    while True:
        q, a = d.recvfrom(512)
        qend = 12
        while q[qend] != 0: qend += 1 + q[qend]
        qend += 5
        ans = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + socket.inet_aton("203.0.113.7")
        d.sendto(q[:2] + b"\x81\x80" + q[4:6] + b"\x00\x01\x00\x00\x00\x00" + q[12:qend] + ans, a)
        print("DNS_ANSWERED", flush=True)
threading.Thread(target=dns, daemon=True).start()
while True:
    c, _ = t.accept(); threading.Thread(target=handle, args=(c,), daemon=True).start()
PY

# Everything else runs in a new user + network namespace: we are root there.
cat >"$W/inner.sh" <<'SH'
set -u
W=$1 RUNSC=$2
pass() { printf 'PASS  %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*"; }
ip link set lo up
ip link add d0 type dummy 2>/dev/null && ip addr add 10.255.0.1/24 dev d0 && ip link set d0 up && ip route add default dev d0 \
	&& pass "private netns: loopback up, a default route (dummy)" || { fail "cannot configure the namespace"; exit 1; }
if nft -f - <<'NFT'
table ip agentbox {
  chain out {
    type nat hook output priority -100; policy accept;
    ip daddr 127.0.0.0/8 tcp dport 15001 accept
    meta l4proto tcp redirect to :15001
    udp dport 53 redirect to :15053
  }
}
NFT
then pass "nftables redirect rules in a user-owned netns"; else fail "nftables in a user-owned netns"; exit 1; fi
python3 "$W/catcher.py" "$W/gw.sock" >"$W/catch.log" 2>&1 &
sleep 0.5

out=$(curl -sS -m 5 --noproxy '*' http://93.184.216.34:8080/x 2>&1)
grep -q "CAUGHT 93.184.216.34:8080 .*gw=GATEWAY_OK" "$W/catch.log" && pass "kernel: TCP to any address caught, original destination recovered, gateway socket reached across the netns" \
	|| fail "kernel catch: $out / $(tail -2 "$W/catch.log")"

mkdir -p "$W/state"
# Without --rootless is informational only: agentbox always uses --rootless.
bad() { if [ -n "$mode" ]; then fail "$@"; else printf "INFO  %s\n" "$*"; fi; }
for mode in "--rootless" ""; do
	label=${mode:-"(no --rootless; informational, agentbox uses --rootless)"}
	: >"$W/catch.log"
	out=$(timeout 60 "$RUNSC" --root "$W/state" $mode --network=host --ignore-cgroups do -- /bin/sh -c '
		curl -sS -m 5 --noproxy "*" http://198.51.100.9:443/ 2>&1 | head -c 200; echo
		curl -sS -m 5 --noproxy "*" --resolve example.com:443:198.51.100.10 https://example.com/ 2>&1 | head -c 120; echo
		getent hosts example.com || echo NO_DNS' 2>&1)
	if grep -q "CAUGHT 198.51.100.9:443" "$W/catch.log"; then
		pass "gVisor $label --network=host: TCP caught with its original destination"
		grep -q "sni=example.com" "$W/catch.log" && pass "gVisor $label: TLS server name read (sni=example.com)" || bad "gVisor $label: no SNI: $(grep CAUGHT "$W/catch.log" | tail -1)"
		echo "$out" | grep -q "203.0.113.7" && pass "gVisor $label: DNS answered by the local responder" || bad "gVisor $label: DNS not caught: $(echo "$out" | tail -1)"
	else
		bad "gVisor $label --network=host: $(echo "$out" | tail -c 300)"
	fi
done
SH

echo "== inside a user + network namespace"
if ! "$UNSHARE" -Urn true 2>/dev/null; then
	echo "FAIL  $UNSHARE -Urn refused (Ubuntu 23.10+: AppArmor restricts user namespaces; rerun scripts/install-runsc.sh, which installs agentbox-unshare with a profile)"
	exit 1
fi
echo "(namespace made with $UNSHARE)"
"$UNSHARE" -Urn bash "$W/inner.sh" "$W" "$RUNSC"
