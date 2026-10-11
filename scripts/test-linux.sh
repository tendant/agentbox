#!/usr/bin/env bash
# Run agentbox's tests, including the integration tests against real
# rootless runsc, on Linux as a normal user. From a Mac (or any Docker host)
# it uses an Ubuntu container; on Linux it runs them here:
#
#   scripts/test-linux.sh            # Docker
#   scripts/test-linux.sh --here     # this Linux host (runsc installed)
#
# The container allows user namespaces (seccomp/AppArmor unconfined) but is
# not privileged, and has no systemd user session, so the memory-limit test
# only checks that it fails closed there.

set -euo pipefail
cd "$(dirname "$0")/.."

if [ "${1:-}" = --here ]; then
	[ "$(id -u)" != 0 ] || { echo "run as a normal user" >&2; exit 2; }
	AGENTBOX_INTEGRATION=1 go test -race -count=1 ./...
	exit
fi

command -v docker >/dev/null || { echo "docker not found" >&2; exit 2; }
GO=$(sed -n 's/^go //p' go.mod)
# RUN=regex selects tests; RAW=1 shows full output.
FILTER='grep -E "^(=== RUN|--- |ok|FAIL|PASS)|_test.go"'
[ "${RAW:-}" = 1 ] && FILTER=cat
docker run --rm --security-opt seccomp=unconfined --security-opt apparmor=unconfined \
	-e RUN="${RUN:-.}" -e FILTER="$FILTER" -v "$PWD:/src:ro" "golang:$GO" bash -euc '
	export DEBIAN_FRONTEND=noninteractive
	apt-get update -qq >/dev/null && apt-get install -y -qq python3 procps bzip2 >/dev/null 2>&1
	bash /src/scripts/install-runsc.sh >/dev/null
	useradd -m -u 1000 tester
	cp -r /src /home/tester/src && chown -R tester /home/tester/src
	runuser -u tester -- env PATH="$PATH" HOME=/home/tester GOFLAGS=-buildvcs=false \
		RUN="$RUN" FILTER="$FILTER" bash -c "cd /home/tester/src && AGENTBOX_INTEGRATION=1 go test -count=1 -v -run \"\$RUN\" ./... 2>&1 | eval \"\$FILTER\""
'
