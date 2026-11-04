package ownerrename

import "golang.org/x/sys/unix"

func Rename(source uintptr, name string, destination uintptr, target string, replace bool) error {
	if replace {
		return unix.Renameat(int(source), name, int(destination), target)
	}
	// RENAME_EXCL refuses an existing destination atomically.
	return unix.RenameatxNp(int(source), name, int(destination), target, 4)
}
