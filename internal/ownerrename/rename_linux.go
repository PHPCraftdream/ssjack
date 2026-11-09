package ownerrename

import "golang.org/x/sys/unix"

func Rename(source uintptr, name string, destination uintptr, target string, replace bool) error {
	if replace {
		return unix.Renameat(int(source), name, int(destination), target)
	}
	return unix.Renameat2(int(source), name, int(destination), target, unix.RENAME_NOREPLACE)
}
