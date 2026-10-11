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

// member reports whether pid runs under a Seatbelt profile that lets it
// write tmp: one of this sandbox's processes (no other profile allows that
// directory, and an unsandboxed process is not sandboxed).
func member(pid int, tmp string) bool {
	if C.is_sandboxed(C.pid_t(pid)) != 1 {
		return false
	}
	p := C.CString(tmp)
	defer C.free(unsafe.Pointer(p))
	return C.write_denied(C.pid_t(pid), p) == 0
}

const membersByProfile = true
