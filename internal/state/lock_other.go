//go:build !unix

package state

// lock is a no-op where flock is unavailable; the gateway targets Linux.
func lock(string) (func(), error) { return func() {}, nil }
