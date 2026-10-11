# agentbox host setup and development. Run as the normal user agentbox
# will run as: the install steps use sudo themselves, the build never does.
#
#   make install     runsc + AppArmor profiles + agentbox-unshare, and the agentbox CLI
#   make check       verify this host (doctor, Phase 0 checks)
#   make test        unit tests; make test-linux: all tests against real runsc
#   make lint        gofmt and go vet for Linux and macOS
#   make release VERSION=v0.0.3   checks, then tag, push and a GitHub release

PREFIX ?= /usr/local/bin
GVISOR_RELEASE ?= 20261005.0
SUDO := $(shell [ "$$(id -u)" = 0 ] || echo sudo)

.PHONY: all build install install-runsc install-cli uninstall check doctor test test-linux lint release

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
# macOS (Seatbelt) has no host setup: doctor is the whole check.
check: doctor
	@if [ "$$(uname -s)" = Linux ]; then scripts/phase0.sh && scripts/phase0-transparent.sh; fi

doctor:
	@if [ -x $(PREFIX)/agentbox ]; then $(PREFIX)/agentbox doctor; else go run ./cmd/agentbox doctor; fi

uninstall:
	-[ -f /etc/apparmor.d/agentbox-runsc ] && $(SUDO) apparmor_parser -R /etc/apparmor.d/agentbox-runsc
	-[ -f /etc/apparmor.d/agentbox-runsc-unshare ] && $(SUDO) apparmor_parser -R /etc/apparmor.d/agentbox-runsc-unshare
	$(SUDO) rm -rf /etc/apparmor.d/agentbox-runsc /etc/apparmor.d/agentbox-runsc-unshare \
		$(PREFIX)/runsc $(PREFIX)/gvisor-bin $(PREFIX)/agentbox-unshare $(PREFIX)/agentbox

test:
	go test -race ./...

lint:
	@out=$$(gofmt -l .); [ -z "$$out" ] || { echo "gofmt needed:"; echo "$$out"; exit 1; }
	go vet ./...
	GOOS=linux go vet ./...
	GOOS=darwin go vet ./...

# Releases come from a clean, pushed main that passes lint and tests. Run
# make test-linux (and agent-runner's sandbox smoke on a real host) first:
# this target cannot reach runsc from a Mac.
release:
	@echo "$(VERSION)" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$$' || { echo "usage: make release VERSION=vX.Y.Z" >&2; exit 2; }
	@[ -z "$$(git status --porcelain)" ] || { echo "the tree is not clean" >&2; exit 1; }
	@[ "$$(git rev-parse --abbrev-ref HEAD)" = main ] || { echo "release from main" >&2; exit 1; }
	@git fetch -q origin && [ "$$(git rev-parse HEAD)" = "$$(git rev-parse origin/main)" ] || { echo "main is not pushed (or behind origin)" >&2; exit 1; }
	@! git rev-parse -q --verify "refs/tags/$(VERSION)" >/dev/null || { echo "$(VERSION) exists" >&2; exit 1; }
	$(MAKE) lint test
	git tag -a $(VERSION) -m "agentbox $(VERSION)"
	git push -q origin $(VERSION)
	@if command -v gh >/dev/null; then gh release create $(VERSION) --title $(VERSION) --generate-notes; \
	else echo "tagged $(VERSION); create the GitHub release by hand (gh not installed)"; fi
	@echo "users: go get github.com/tendant/agentbox@$(VERSION)"

# From a Mac: in an Ubuntu container. On Linux with runsc installed: --here.
test-linux:
	@if [ "$$(uname -s)" = Linux ] && command -v runsc >/dev/null; then scripts/test-linux.sh --here; else scripts/test-linux.sh; fi
