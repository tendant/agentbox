#!/usr/bin/env bash
# Install gVisor's runsc for agentbox on a Linux host, run by an admin (it
# uses sudo for the privileged steps; agentbox itself then runs as a normal
# user):
#
#   scripts/install-runsc.sh
#
# 1. downloads the pinned gVisor release for this architecture and verifies
#    its sha512;
# 2. installs runsc and its gvisor-bin/ helpers into a root-owned PREFIX
#    (a user-writable copy could be swapped for any binary, see 3);
# 3. where AppArmor restricts unprivileged user namespaces (Ubuntu 23.10+,
#    kernel.apparmor_restrict_unprivileged_userns=1), adds profiles letting
#    that runsc, and a root-owned copy of unshare (agentbox-unshare, for
#    transparent egress), and only them, create them. Nothing else changes.
#
# Safe to rerun. Env: GVISOR_RELEASE (default 20261005.0), PREFIX (default
# /usr/local/bin).

set -euo pipefail
REL=${GVISOR_RELEASE:-20261005.0}
PREFIX=${PREFIX:-/usr/local/bin}
PROFILE=/etc/apparmor.d/agentbox-runsc

[ "$(uname -s)" = Linux ] || { echo "runsc is Linux-only" >&2; exit 2; }
case $(uname -m) in
x86_64 | amd64) ARCH=x86_64 ;;
aarch64 | arm64) ARCH=aarch64 ;;
*) echo "unsupported architecture: $(uname -m)" >&2; exit 2 ;;
esac
SUDO=sudo; [ "$(id -u)" = 0 ] && SUDO=""
for tool in curl sha512sum tar bzip2; do
	command -v "$tool" >/dev/null || { echo "missing $tool (Debian/Ubuntu: apt install curl coreutils tar bzip2)" >&2; exit 2; }
done

echo "== gVisor $REL ($ARCH) -> $PREFIX"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
URL=https://storage.googleapis.com/gvisor/releases/release/$REL/$ARCH/gvisor.tar.bz2
curl -fsSL -o "$TMP/gvisor.tar.bz2" "$URL"
(cd "$TMP" && curl -fsSL "$URL.sha512" | sed 's/ .*/  gvisor.tar.bz2/' | sha512sum -c - >/dev/null) ||
	{ echo "checksum mismatch: not installing" >&2; exit 1; }
tar -xjf "$TMP/gvisor.tar.bz2" -C "$TMP"
$SUDO install -d -m 0755 "$PREFIX"
$SUDO install -m 0755 -o root -g root "$TMP/runsc" "$PREFIX/runsc"
$SUDO rm -rf "$PREFIX/gvisor-bin"
$SUDO cp -r "$TMP/gvisor-bin" "$PREFIX/gvisor-bin"
$SUDO chown -R root:root "$PREFIX/gvisor-bin"
"$PREFIX/runsc" --version | head -1

echo "== user namespaces"
restrict=$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null || echo 0)
if [ "$restrict" != 1 ]; then
	echo "not restricted by AppArmor here: no profile needed"
elif ! command -v apparmor_parser >/dev/null; then
	echo "AppArmor restricts user namespaces but apparmor_parser is missing (apt install apparmor)" >&2
	exit 1
else
	$SUDO tee "$PROFILE" >/dev/null <<EOF
# Installed by agentbox scripts/install-runsc.sh: lets $PREFIX/runsc, and
# only it, create unprivileged user namespaces (rootless gVisor).
abi <abi/4.0>,
include <tunables/global>

profile agentbox-runsc $PREFIX/runsc flags=(unconfined) {
  userns,
  include if exists <local/agentbox-runsc>
}
EOF
	$SUDO apparmor_parser -r "$PROFILE"
	echo "AppArmor profile $PROFILE loaded for $PREFIX/runsc"
	# Transparent egress makes the sandbox's network namespace before runsc
	# runs: a root-owned copy of unshare gets the same narrow permission.
	$SUDO install -m 0755 -o root -g root "$(command -v unshare)" "$PREFIX/agentbox-unshare"
	$SUDO tee "$PROFILE-unshare" >/dev/null <<EOF
# Installed by agentbox scripts/install-runsc.sh: lets $PREFIX/agentbox-unshare,
# and only it, create unprivileged user namespaces (transparent egress).
abi <abi/4.0>,
include <tunables/global>

profile agentbox-unshare $PREFIX/agentbox-unshare flags=(unconfined) {
  userns,
  include if exists <local/agentbox-unshare>
}
EOF
	$SUDO apparmor_parser -r "$PROFILE-unshare"
	echo "AppArmor profile $PROFILE-unshare loaded for $PREFIX/agentbox-unshare"
fi

echo "== check"
if out=$("$PREFIX/runsc" --rootless --network=none --ignore-cgroups --root "$TMP/state" do -- /bin/true 2>&1); then
	echo "ok: rootless runsc works for $(id -un)"
	[ -n "$SUDO" ] || echo "(checked as root; run scripts/phase0.sh as the runner's user)"
else
	echo "rootless runsc still fails: $out" >&2
	exit 1
fi
echo "next: RUNSC=$PREFIX/runsc scripts/phase0.sh   (as the runner's user)"
