#!/usr/bin/env bash
# An early Phase 0 signal from a Mac (or any Docker host): scripts/phase0.sh
# in an Ubuntu container, as a non-root user, with only what rootless runsc
# needs from the container (user namespaces: seccomp and AppArmor unconfined,
# no --privileged). It is not the production host: rerun phase0.sh there.
#
#   scripts/phase0-docker.sh
#
# Env: GVISOR_RELEASE (default 20261005.0).

set -euo pipefail
cd "$(dirname "$0")/.."
command -v docker >/dev/null || { echo "docker not found" >&2; exit 2; }
case $(docker info --format '{{.Architecture}}') in
aarch64 | arm64) GVARCH=aarch64 ;;
x86_64 | amd64) GVARCH=x86_64 ;;
*) echo "unsupported Docker architecture" >&2; exit 2 ;;
esac
REL=${GVISOR_RELEASE:-20261005.0}
CACHE=${XDG_CACHE_HOME:-$HOME/.cache}/agentbox
TARBALL=$CACHE/gvisor-$REL-$GVARCH.tar.bz2
URL=https://storage.googleapis.com/gvisor/releases/release/$REL/$GVARCH/gvisor.tar.bz2
[ -f "$TARBALL" ] || { mkdir -p "$CACHE" && curl -fsSL -o "$TARBALL.part" "$URL" && mv "$TARBALL.part" "$TARBALL"; }
SUM=$(curl -fsSL "$URL.sha512" | cut -d' ' -f1)

docker run --rm --security-opt seccomp=unconfined --security-opt apparmor=unconfined \
	-v "$PWD/scripts:/scripts:ro" -v "$TARBALL:/gvisor.tar.bz2:ro" -e SUM="$SUM" -e DEBUG="${DEBUG:-}" ubuntu:24.04 bash -euc '
	export DEBIAN_FRONTEND=noninteractive
	apt-get update -qq >/dev/null && apt-get install -y -qq python3 curl bzip2 util-linux >/dev/null
	echo "$SUM  /gvisor.tar.bz2" | sha512sum -c - >/dev/null
	cd /tmp && tar -xjf /gvisor.tar.bz2 && install -m 0755 runsc /usr/local/bin/runsc && cp -r gvisor-bin /usr/local/bin/
	useradd -m -u 1000 -o runner 2>/dev/null || true
	runuser -u "$(id -nu 1000)" -- env DEBUG="${DEBUG:-}" bash /scripts/phase0.sh
'
