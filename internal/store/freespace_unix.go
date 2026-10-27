//go:build linux || darwin

package store

import "syscall"

// freeSpace is the bytes available to this process on the filesystem holding
// dir, and whether it could be found out. A variable so a test can make a
// volume look full without filling one.
var freeSpace = func(dir string) (int64, bool) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, false
	}
	return int64(st.Bavail) * int64(st.Bsize), true
}
