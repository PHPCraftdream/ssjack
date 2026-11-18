package source

import (
	"archive/tar"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferlocal/hashcount"
	"github.com/PHPCraftdream/ssjack/internal/transferlocal/osfs"
	"github.com/PHPCraftdream/ssjack/internal/transferlocal/pathsafe"
)

// BuildTar writes a deterministic tar of the manifest tree under rel to w.
// Manifest entry paths are relative to the walked rel directory; a single-file
// manifest carries rel itself as its only entry Path. Every file's size and
// SHA-256 are re-verified while streaming so a file that changed after the
// walk fails as an integrity error.
func BuildTar(root string, w io.Writer, rel string, manifest transfercore.Manifest) error {
	abs, info, err := pathsafe.ResolveStructural(root, rel, transfercore.DefaultLimits())
	if err != nil {
		return err
	}
	if !info.Regular && !info.Dir {
		return pathsafe.Refused("source entry type is not supported")
	}
	singleFile := info.Regular
	srcBase := abs
	m := manifest
	m.Normalize()
	tw := tar.NewWriter(w)
	writeHeader := func(hdr *tar.Header) error {
		if err := tw.WriteHeader(hdr); err != nil {
			return transfercore.Fail(transfercore.ClassInternal, "tar stream could not be completed")
		}
		return nil
	}
	writeDir := func(d string) error {
		if err := pathsafe.ValidateLocalRelPath(d, transfercore.DefaultLimits()); err != nil {
			return err
		}
		info, err := osfs.StatPath(filepath.Join(srcBase, filepath.FromSlash(d)))
		if err != nil || !info.Exist || !info.Dir || info.Reparse {
			return transfercore.Fail(transfercore.ClassIntegrity, "source tree changed since the walk")
		}
		hdr := &tar.Header{
			Name:    d + "/",
			Mode:    0755,
			ModTime: entryModTime(filepath.Join(srcBase, filepath.FromSlash(d))),
			Format:  tar.FormatPAX,
		}
		return writeHeader(hdr)
	}
	writeFile := func(e transfercore.Entry) error {
		if err := pathsafe.ValidateLocalRelPath(e.Path, transfercore.DefaultLimits()); err != nil {
			return err
		}
		entrySrc := filepath.Join(srcBase, filepath.FromSlash(e.Path))
		if singleFile {
			entrySrc = abs
		}
		info, err := osfs.StatPath(entrySrc)
		if err != nil || !info.Exist || !info.Regular || info.Reparse {
			return transfercore.Fail(transfercore.ClassIntegrity, "source tree changed since the walk")
		}
		if info.MultiLinked {
			return transfercore.Fail(transfercore.ClassRefusedPath, "source file has more than one hard link")
		}
		file, size, err := osfs.OpenRegularNoFollow(entrySrc)
		if err != nil {
			return transfercore.Fail(transfercore.ClassRefusedPath, "source file cannot be opened")
		}
		mode := int64(0644)
		if info.Mode&0100 != 0 {
			mode = 0755
		}
		hdr := &tar.Header{
			Name:    e.Path,
			Mode:    mode,
			Size:    e.Size,
			ModTime: entryModTime(entrySrc),
			Format:  tar.FormatPAX,
		}
		if err := writeHeader(hdr); err != nil {
			_ = file.Close()
			return err
		}
		c := hashcount.New(tw)
		_, copyErr := io.CopyN(c, file, e.Size)
		_ = file.Close()
		if copyErr == io.EOF || copyErr == io.ErrUnexpectedEOF {
			return transfercore.Fail(transfercore.ClassIntegrity, "source tree changed since the walk")
		}
		if copyErr != nil {
			return transfercore.Fail(transfercore.ClassInternal, "source could not be read")
		}
		if c.Count() != e.Size || size != e.Size {
			return transfercore.Fail(transfercore.ClassIntegrity, "source tree changed since the walk")
		}
		if c.Sum() != e.SHA256 {
			return transfercore.Fail(transfercore.ClassIntegrity, "source tree changed since the walk")
		}
		return nil
	}
	for _, item := range orderedTree(m) {
		var err error
		if item.dir {
			err = writeDir(item.path)
		} else {
			err = writeFile(item.file)
		}
		if err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return transfercore.Fail(transfercore.ClassInternal, "tar stream could not be completed")
	}
	return nil
}

// entryModTime reads the modification time of a source entry in whole
// seconds; an unreadable entry reads as the epoch, which is never restored.
func entryModTime(path string) time.Time {
	info, err := os.Lstat(path)
	if err != nil {
		return time.Unix(0, 0)
	}
	return info.ModTime().UTC().Truncate(time.Second)
}
