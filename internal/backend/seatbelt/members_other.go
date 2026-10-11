//go:build !darwin || !cgo

package seatbelt

// member: without cgo (or off macOS) a sandbox's processes cannot be told
// apart; Close kills the commands' process groups only.
func member(int, string) bool { return false }

const membersByProfile = false
