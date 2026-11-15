//go:build linux

package transferremote

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
)

// linuxExtractTar extracts a tar archive produced by the package into dest,
// enforcing the safe-extraction rules the tests rely on.
func linuxExtractTar(t *testing.T, data []byte, dest string) {
	t.Helper()
	tr := tar.NewReader(bytes.NewReader(data))
	for {
		header, err := tr.Next()
		if err == io.EOF {
			return
		}
		if err != nil {
			t.Fatalf("read tar entry: %v", err)
		}
		name := filepath.Clean(header.Name)
		name = strings.TrimPrefix(name, "./")
		if name == "." {
			continue
		}
		if filepath.IsAbs(name) || strings.HasPrefix(name, "..") {
			t.Fatalf("unsafe tar entry name %q", header.Name)
		}
		target := filepath.Join(dest, name)
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				t.Fatalf("mkdir %s: %v", name, err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				t.Fatalf("mkdir parent of %s: %v", name, err)
			}
			var buf bytes.Buffer
			if _, err := io.Copy(&buf, tr); err != nil {
				t.Fatalf("read %s: %v", name, err)
			}
			if err := os.WriteFile(target, buf.Bytes(), 0o600); err != nil {
				t.Fatalf("write %s: %v", name, err)
			}
		default:
			t.Fatalf("tar entry %q has unsupported type %q", header.Name, string(header.Typeflag))
		}
	}
}

func TestTarOutLinux(t *testing.T) {
	ctx := context.Background()
	r := New(linuxShRunner(), "t", transfercore.DefaultLimits())
	tmp := t.TempDir()
	remoteRoot := tmp + "/remote"
	linuxBuildTree(t, remoteRoot)

	var buf bytes.Buffer
	if err := r.TarOut(ctx, remoteRoot, &buf); err != nil {
		t.Fatalf("TarOut: %v", err)
	}
	if buf.Len() == 0 {
		t.Fatal("TarOut produced an empty archive")
	}
	out := tmp + "/out"
	if err := os.Mkdir(out, 0o755); err != nil {
		t.Fatal(err)
	}
	linuxExtractTar(t, buf.Bytes(), out)
	linuxTreesEqual(t, remoteRoot, out)
}

func TestTarInLinux(t *testing.T) {
	ctx := context.Background()
	r := New(linuxShRunner(), "t", transfercore.DefaultLimits())
	tmp := t.TempDir()
	src := tmp + "/src"
	manifest := linuxBuildTree(t, src)

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, dir := range manifest.Dirs {
		if err := tw.WriteHeader(&tar.Header{
			Name:     dir + "/",
			Typeflag: tar.TypeDir,
			Mode:     0o755,
		}); err != nil {
			t.Fatalf("write dir header %s: %v", dir, err)
		}
	}
	for _, file := range manifest.Files {
		data, err := os.ReadFile(filepath.Join(src, file.Path))
		if err != nil {
			t.Fatalf("read fixture %s: %v", file.Path, err)
		}
		if err := tw.WriteHeader(&tar.Header{
			Name:     file.Path,
			Typeflag: tar.TypeReg,
			Size:     int64(len(data)),
			Mode:     0o600,
		}); err != nil {
			t.Fatalf("write file header %s: %v", file.Path, err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatalf("write file body %s: %v", file.Path, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar writer: %v", err)
	}

	staging := tmp + "/staging"
	if err := os.Mkdir(staging, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := r.TarIn(ctx, staging, bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatalf("TarIn: %v", err)
	}
	if err := r.VerifyTree(ctx, staging, manifest); err != nil {
		t.Fatalf("VerifyTree after TarIn: %v", err)
	}

	missing := tmp + "/no-such-root"
	err := r.TarIn(ctx, missing, bytes.NewReader(buf.Bytes()))
	linuxTestError(t, err, transfercore.ClassRefusedPath)
}
