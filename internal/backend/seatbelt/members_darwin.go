//go:build darwin && cgo

package seatbelt

/*
#include <stdlib.h>
#include <sys/types.h>
int sandbox_check(pid_t pid, const char *operation, int type, ...);
// 0: SANDBOX_FILTER_NONE, 1: SANDBOX_FILTER_PATH
static int is_sandboxed(pid_t pid) { return sandbox_check(pid, NULL, 0); }
static int write_denied(pid_t pid, const char *path) { return sandbox_check(pid, "file-write-data", 1, path); }
*/
import "C"

import "unsafe"

// member reports whether pid runs under this sandbox's Seatbelt profile:
// sandboxed, allowed to write tmp, and denied outside, a path next to it
// that this profile does not grant. Both are needed: a broad profile (many
// of macOS's own sandboxed services, Docker Desktop's VM among them) may
// write tmp too, but then outside as well; such a process is not a member,
// and must never be killed for one.
func member(pid int, tmp, outside string) bool {
	if C.is_sandboxed(C.pid_t(pid)) != 1 {
		return false
	}
	return !writeDenied(pid, tmp) && writeDenied(pid, outside)
}

func writeDenied(pid int, path string) bool {
	p := C.CString(path)
	defer C.free(unsafe.Pointer(p))
	return C.write_denied(C.pid_t(pid), p) != 0
}

const membersByProfile = true
