package tarin

import (
	"archive/tar"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferlocal/hashcount"
	"github.com/PHPCraftdream/ssjack/internal/transferlocal/osfs"
	"github.com/PHPCraftdream/ssjack/internal/transferlocal/pathsafe"
)

// ensureDirChain creates every missing directory of relDir under root,
// refusing to write through any pre-existing symlink or reparse point and
// refusing non-directory intermediates. It returns the rel paths it created,
// in order.
func ensureDirChain(root, relDir string) ([]string, error) {
	if relDir == "" {
		return nil, nil
	}
	var created []string
	acc := root
	relAcc := ""
	for _, part := range strings.Split(relDir, "/") {
		relAcc = pathsafe.JoinRel(relAcc, part)
		next := filepath.Join(acc, part)
		info, err := osfs.StatPath(next)
		if err != nil {
			return nil, pathsafe.Refused("archive path cannot be inspected")
		}
		if info.Reparse {
			return nil, pathsafe.Refused("archive entry would be written through a symlink or reparse point")
		}
		if info.Exist && !info.Dir {
			return nil, pathsafe.Refused("archive entry parent is not a directory")
		}
		if !info.Exist {
			if err := os.Mkdir(next, 0755); err != nil {
				if errors.Is(err, os.ErrExist) {
					// Lost a creation race: the winner must be a real dir.
					again, statErr := osfs.StatPath(next)
					if statErr != nil || !again.Exist || !again.Dir || again.Reparse {
						return nil, pathsafe.Refused("archive entry parent is not a directory")
					}
				} else {
					return nil, transfercore.Fail(transfercore.ClassInternal, "archive directories could not be created")
				}
			} else {
				created = append(created, relAcc)
			}
		}
		acc = next
	}
	return created, nil
}

// extractFileEntry creates one regular file exclusively inside the staged
// tree and streams exactly size bytes from tr into it, hashing and enforcing
// the byte limit per chunk.
func extractFileEntry(root, name string, tr *tar.Reader, size int64, executable bool, modTime time.Time, totalBytes *int64, limits transfercore.Limits) (int64, [32]byte, error) {
	mode := os.FileMode(0644)
	if executable {
		mode = 0755
	}
	file, err := osfs.CreateExclusiveFile(joinOSPath(root, name), mode)
	if err == osfs.ErrDestinationExists {
		// An existing link name also fails here, so nothing is written
		// through a pre-existing link.
		return 0, [32]byte{}, pathsafe.Refused("archive entry collides with an existing path")
	}
	if err != nil {
		return 0, [32]byte{}, transfercore.Fail(transfercore.ClassInternal, "archive entry could not be written")
	}
	c := hashcount.New(file)
	remaining := size
	for remaining > 0 {
		chunk := int64(64 << 10)
		if remaining < chunk {
			chunk = remaining
		}
		n, err := io.CopyN(c, tr, chunk)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			_ = file.Close()
			return 0, [32]byte{}, transfercore.Fail(transfercore.ClassIntegrity, "archive entry is truncated")
		}
		if err != nil {
			_ = file.Close()
			return 0, [32]byte{}, transfercore.Fail(transfercore.ClassIntegrity, "archive is truncated or malformed")
		}
		remaining -= n
		*totalBytes += n
		if *totalBytes > limits.MaxBytes {
			_ = file.Close()
			return 0, [32]byte{}, transfercore.Fail(transfercore.ClassLimit, "transfer exceeds the configured limits")
		}
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return 0, [32]byte{}, transfercore.Fail(transfercore.ClassInternal, "archive entry could not be flushed")
	}
	if err := file.Close(); err != nil {
		return 0, [32]byte{}, transfercore.Fail(transfercore.ClassInternal, "archive entry could not be written")
	}
	applyModTime(joinOSPath(root, name), modTime)
	return c.Count(), c.Sum(), nil
}
