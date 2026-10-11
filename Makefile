# agentbox host setup and development. Run as the normal user agentbox
# will run as: the install steps use sudo themselves, the build never does.
#
#   make install     runsc + AppArmor profiles + agentbox-unshare, and the agentbox CLI
#   make check       verify this host (doctor, Phase 0 checks)
#   make test        unit tests; make test-linux: all tests against real runsc

PREFIX ?= /usr/local/bin
GVISOR_RELEASE ?= 20261005.0
SUDO := $(shell [ "$$(id -u)" = 0 ] || echo sudo)

.PHONY: all build install install-runsc install-cli uninstall check doctor test test-linux

all: build

build:
	go build -o agentbox ./cmd/agentbox

# install-runsc.sh: gVisor's runsc (pinned, sha512-checked) and gvisor-bin
# into PREFIX, plus, where AppArmor restricts user namespaces, the profiles
# for runsc and agentbox-unshare (the gateway network's namespace).
install: install-runsc install-cli
	@echo "next: make check"

install-runsc:
	PREFIX=$(PREFIX) GVISOR_RELEASE=$(GVISOR_RELEASE) scripts/install-runsc.sh

install-cli: build
	$(SUDO) install -m 0755 agentbox $(PREFIX)/agentbox

# The gateway network also needs ip and nft (apt install iproute2 nftables).
check: doctor
	scripts/phase0.sh
	scripts/phase0-transparent.sh

doctor:
	@if [ -x $(PREFIX)/agentbox ]; then $(PREFIX)/agentbox doctor; else go run ./cmd/agentbox doctor; fi

uninstall:
	-[ -f /etc/apparmor.d/agentbox-runsc ] && $(SUDO) apparmor_parser -R /etc/apparmor.d/agentbox-runsc
	-[ -f /etc/apparmor.d/agentbox-runsc-unshare ] && $(SUDO) apparmor_parser -R /etc/apparmor.d/agentbox-runsc-unshare
	$(SUDO) rm -rf /etc/apparmor.d/agentbox-runsc /etc/apparmor.d/agentbox-runsc-unshare \
		$(PREFIX)/runsc $(PREFIX)/gvisor-bin $(PREFIX)/agentbox-unshare $(PREFIX)/agentbox

test:
	go test -race ./...

# From a Mac: in an Ubuntu container. On Linux with runsc installed: --here.
test-linux:
	@if [ "$$(uname -s)" = Linux ] && command -v runsc >/dev/null; then scripts/test-linux.sh --here; else scripts/test-linux.sh; fi
