//go:build !linux && !darwin

package store

// freeSpace cannot be asked here, so the copy is attempted and a full disk is
// reported by SQLite instead. Windows runs addy for `serve -dev`, not for a
// relay anybody upgrades.
var freeSpace = func(dir string) (int64, bool) { return 0, false }
