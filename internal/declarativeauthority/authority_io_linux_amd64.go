//go:build linux && amd64

package declarativeauthority

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

func createMarker(data []byte) error {
	if safeDirectory(false) != nil {
		return ErrAuthority
	}
	f, err := os.OpenFile(filepath.Join(RegistryPath, SetupName), os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0644)
	if err != nil {
		return ErrAuthority
	}
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return ErrAuthority
	}
	return syncDirectory(RegistryPath)
}

func atomicFile(data []byte) error { return atomicNamed(GrantsName, data) }

func atomicNamed(name string, data []byte) error {
	if name != GrantsName && name != "delivery-grants.json" {
		return ErrAuthority
	}
	if os.Geteuid() != 0 || safeDirectory(false) != nil {
		return ErrAuthority
	}
	pending := filepath.Join(RegistryPath, ".pending-"+name)
	f, err := os.OpenFile(pending, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0644)
	if err != nil {
		return ErrAuthority
	}
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		os.Remove(pending)
		return ErrAuthority
	}
	if err = os.Rename(pending, filepath.Join(RegistryPath, name)); err != nil {
		os.Remove(pending)
		return ErrAuthority
	}
	return syncDirectory(RegistryPath)
}

func syncDirectory(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return ErrAuthority
	}
	err = d.Sync()
	d.Close()
	if err != nil {
		return ErrAuthority
	}
	return nil
}

func readTrusted(path string, limit int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, ErrAuthority
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !st.Mode().IsRegular() || sys.Uid != 0 || sys.Nlink != 1 || st.Mode().Perm()&0022 != 0 || st.Size() < 1 || st.Size() > limit {
		return nil, ErrAuthority
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) != st.Size() || int64(len(data)) > limit {
		return nil, ErrAuthority
	}
	return data, nil
}

func safeDirectory(create bool) error {
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return ErrAuthority
	}
	var root syscall.Stat_t
	if syscall.Fstat(fd, &root) != nil || root.Uid != 0 || root.Mode&0022 != 0 {
		syscall.Close(fd)
		return ErrAuthority
	}
	for _, part := range []string{"etc", "ssjack", "declarative"} {
		next, e := syscall.Openat(fd, part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
		if e != nil && create && e == syscall.ENOENT && os.Geteuid() == 0 {
			if syscall.Mkdirat(fd, part, 0755) == nil {
				next, e = syscall.Openat(fd, part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
			}
		}
		syscall.Close(fd)
		if e != nil {
			return ErrAuthority
		}
		fd = next
		var st syscall.Stat_t
		if syscall.Fstat(fd, &st) != nil || st.Uid != 0 || st.Mode&0022 != 0 {
			syscall.Close(fd)
			return ErrAuthority
		}
	}
	return syscall.Close(fd)
}

func safeDeliveryCodeDirectory() error { return safeDriverDirectory() }

func DeliveryDriverDigest() (string, error) { return CodeDigest(DriverPath) }

func CodeDigest(path string) (string, error) {
	if path != DriverPath || safeDriverDirectory() != nil {
		return "", ErrAuthority
	}
	data, err := readTrusted(path, 64<<20)
	if err != nil {
		return "", ErrAuthority
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:]), nil
}

func safeDriverDirectory() error {
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return ErrAuthority
	}
	var root syscall.Stat_t
	if syscall.Fstat(fd, &root) != nil || root.Uid != 0 || root.Mode&0022 != 0 {
		syscall.Close(fd)
		return ErrAuthority
	}
	for _, part := range []string{"usr", "libexec"} {
		next, e := syscall.Openat(fd, part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
		syscall.Close(fd)
		if e != nil {
			return ErrAuthority
		}
		fd = next
		var st syscall.Stat_t
		if syscall.Fstat(fd, &st) != nil || st.Uid != 0 || st.Mode&0022 != 0 {
			syscall.Close(fd)
			return ErrAuthority
		}
	}
	return syscall.Close(fd)
}
