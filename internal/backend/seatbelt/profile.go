package seatbelt

// The Seatbelt (SBPL) profile for a sandbox. Its structure follows isobox's
// (github.com/can1357/isobox, MIT): start from (allow default) and carve
// away, last matching rule winning, so the order of sections matters.

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/tendant/agentbox/pkg/agentbox"
)

// machServices are the Mach services a sandbox may look up; all others are
// denied. Each is something ordinary programs fail without:
var machServices = []string{
	"com.apple.cfprefsd.daemon", // CFPreferences (codex fails without it)
	"com.apple.cfprefsd.agent",
	"com.apple.system.opendirectoryd.libinfo", // getpwuid and friends (HOME lookup, git)
	"com.apple.system.notification_center",
	"com.apple.logd", // os_log
	"com.apple.system.logger",
	"com.apple.trustd", // TLS certificate evaluation
	"com.apple.trustd.agent",
}

// Not among them, on purpose: com.apple.SecurityServer (the keychain: a
// sandboxed /usr/bin/security could read items whose ACL trusts it, such as
// CLI credentials) and com.apple.mDNSResponder (DNS: a sandbox without
// network resolves nothing).

// systemReadable are the host paths every sandbox may read: binaries,
// libraries, frameworks, configuration, the dyld cache, /bin/sh's selector.
var systemReadable = []string{"/usr", "/bin", "/sbin", "/System", "/Library", "/opt",
	"/private/etc", "/private/var/db", "/private/var/select", "/dev"}

// devWritable are device paths every sandbox may write.
var devWritable = []string{"/dev/null", "/dev/zero", "/dev/tty", "/dev/dtracehelper"}

func quote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

func rule(b *strings.Builder, verb, ops, filter string, paths []string) {
	if len(paths) == 0 {
		return
	}
	fmt.Fprintf(b, "(%s %s", verb, ops)
	for _, p := range paths {
		fmt.Fprintf(b, " (%s %s)", filter, quote(p))
	}
	b.WriteString(")\n")
}

// ancestors are the directories above paths, "/" included: a program
// resolving a path stats each of them.
func ancestors(paths []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range paths {
		for d := filepath.Dir(p); ; d = filepath.Dir(d) {
			if !seen[d] {
				seen[d] = true
				out = append(out, d)
			}
			if d == "/" {
				break
			}
		}
	}
	slices.Sort(out)
	return out
}

// profile renders spec (normalized) as SBPL. sys are the system paths that
// exist on this host (systemReadable, resolved); tmp is the sandbox's own
// temporary directory.
func profile(spec agentbox.Spec, sys []string, tmp string, extraMach []string) string {
	var b strings.Builder
	b.WriteString("(version 1)\n(allow default)\n")

	// IPC: only the listed Mach services; signals only within the sandbox.
	b.WriteString("(deny mach-lookup)\n")
	for _, s := range append(slices.Clone(machServices), extraMach...) {
		fmt.Fprintf(&b, "(allow mach-lookup (global-name %s))\n", quote(s))
	}
	b.WriteString("(deny signal)\n(allow signal (target same-sandbox))\n")

	// Network: none, except the listed ports on the host's loopback.
	b.WriteString("(deny network*)\n")
	for _, p := range spec.HostPorts {
		fmt.Fprintf(&b, "(allow network-outbound (remote ip \"localhost:%d\"))\n", p)
	}

	// Reads: the system paths, then the sandbox's own, nothing else.
	writable := []string{spec.Workspace, tmp}
	for _, m := range spec.Writable {
		writable = append(writable, m.Source)
	}
	readable := slices.Clone(writable)
	for _, m := range spec.ReadOnly {
		readable = append(readable, m.Source)
	}
	b.WriteString("(deny file-read* (subpath \"/\"))\n")
	rule(&b, "allow", "file-read*", "subpath", sys)
	// /System lexically covers the firmlinked data volume (all of the
	// disk): never through there.
	b.WriteString("(deny file-read* (subpath \"/System/Volumes/Data\"))\n")
	// "/" itself (dyld lists it at startup: sandbox-exec aborts without), and
	// the symlinks /etc, /tmp and /var.
	rule(&b, "allow", "file-read*", "literal", []string{"/", "/etc", "/tmp", "/var"})
	rule(&b, "allow", "file-read-metadata", "literal", ancestors(append(slices.Clone(readable), sys...)))
	rule(&b, "allow", "file-read*", "subpath", readable)

	// Writes: the workspace, the writable mounts and the sandbox's tmp.
	b.WriteString("(deny file-write* (subpath \"/\"))\n")
	rule(&b, "allow", "file-write*", "literal", devWritable)
	rule(&b, "allow", "file-write*", "subpath", append([]string{"/dev/fd"}, writable...))

	// Denied paths, last: they win over every allow above.
	rule(&b, "deny", "file-read* file-write*", "subpath", spec.Deny)
	return b.String()
}
