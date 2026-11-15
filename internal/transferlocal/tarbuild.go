package transferlocal

import (
	"archive/tar"
	"io"
	"path/filepath"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
)

// BuildTar writes a deterministic tar of the manifest tree under rel to w.
// Manifest entry paths are relative to the walked rel directory; a single-file
// manifest carries rel itself as its only entry Path. Every file's size and
// SHA-256 are re-verified while streaming so a file that changed after the
// walk fails as an integrity error.
func (r *Root) BuildTar(w io.Writer, rel string, manifest transfercore.Manifest) error {
	abs, info, err := r.resolveStructural(rel, transfercore.DefaultLimits())
	if err != nil {
		return err
	}
	if !info.regular && !info.dir {
		return refusedPath("source entry type is not supported")
	}
	singleFile := info.regular
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
	for _, d := range m.Dirs {
		if err := validateLocalRelPath(d, transfercore.DefaultLimits()); err != nil {
			return err
		}
		info, err := statPath(filepath.Join(srcBase, filepath.FromSlash(d)))
		if err != nil || !info.exist || !info.dir || info.reparse {
			return transfercore.Fail(transfercore.ClassIntegrity, "source tree changed since the walk")
		}
		hdr := &tar.Header{
			Name:   d + "/",
			Mode:   0755,
			Format: tar.FormatPAX,
		}
		if err := writeHeader(hdr); err != nil {
			return err
		}
	}
	for _, e := range m.Files {
		if err := validateLocalRelPath(e.Path, transfercore.DefaultLimits()); err != nil {
			return err
		}
		entrySrc := filepath.Join(srcBase, filepath.FromSlash(e.Path))
		if singleFile {
			entrySrc = abs
		}
		info, err := statPath(entrySrc)
		if err != nil || !info.exist || !info.regular || info.reparse {
			return transfercore.Fail(transfercore.ClassIntegrity, "source tree changed since the walk")
		}
		if info.multiLinked {
			return transfercore.Fail(transfercore.ClassRefusedPath, "source file has more than one hard link")
		}
		file, size, err := openRegularNoFollow(entrySrc)
		if err != nil {
			return transfercore.Fail(transfercore.ClassRefusedPath, "source file cannot be opened")
		}
		mode := int64(0644)
		if info.mode&0100 != 0 {
			mode = 0755
		}
		hdr := &tar.Header{
			Name:   e.Path,
			Mode:   mode,
			Size:   e.Size,
			Format: tar.FormatPAX,
		}
		if err := writeHeader(hdr); err != nil {
			_ = file.Close()
			return err
		}
		c := newHashCounter(tw)
		_, copyErr := io.CopyN(c, file, e.Size)
		_ = file.Close()
		if copyErr == io.EOF || copyErr == io.ErrUnexpectedEOF {
			return transfercore.Fail(transfercore.ClassIntegrity, "source tree changed since the walk")
		}
		if copyErr != nil {
			return transfercore.Fail(transfercore.ClassInternal, "source could not be read")
		}
		if c.count() != e.Size || size != e.Size {
			return transfercore.Fail(transfercore.ClassIntegrity, "source tree changed since the walk")
		}
		if c.sum() != e.SHA256 {
			return transfercore.Fail(transfercore.ClassIntegrity, "source tree changed since the walk")
		}
	}
	if err := tw.Close(); err != nil {
		return transfercore.Fail(transfercore.ClassInternal, "tar stream could not be completed")
	}
	return nil
}
