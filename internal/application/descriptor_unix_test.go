//go:build unix

package application

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestDescriptorRefusesSymlinkedDescriptorAndDirectory(t *testing.T) {
	actual := descriptorDir(t, validDescriptor(""))
	if _, err := LoadDescriptor(actual); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(actual, link); err != nil {
		t.Fatal(err)
	}
	expectRefusal(t, link, "must not be a symlink")

	dir := descriptorDir(t, "")
	target := filepath.Join(t.TempDir(), "target-descriptor.json")
	if err := os.WriteFile(target, []byte(validDescriptor("")), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, DescriptorFile)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	expectRefusal(t, dir, "must not be a symlink")

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	expectRefusal(t, dir, "regular file")
}

func TestDescriptorSymlinkedExecutableAndWorkdir(t *testing.T) {
	dir := descriptorDir(t, validDescriptor(""))
	root := canonical(t, dir)
	tool := filepath.Join(root, "bin", "tool")
	alias := filepath.Join(root, "bin", "alias")
	if err := os.Symlink(tool, alias); err != nil {
		t.Fatal(err)
	}
	app, err := LoadDescriptor(descriptorDir(t, launchDescriptor(`{"executable":`+quoteJSON(t, alias)+`}`)))
	if err != nil || app.Executable != tool {
		t.Fatalf("symlinked executable must resolve to its target: %+v %v", app, err)
	}

	shim := filepath.Join(root, "bin", "actual.cmd")
	if err := os.WriteFile(shim, []byte("fixture, never executed"), 0o700); err != nil {
		t.Fatal(err)
	}
	disguised := filepath.Join(root, "bin", "disguised")
	if err := os.Symlink(shim, disguised); err != nil {
		t.Fatal(err)
	}
	expectRefusal(t, descriptorDir(t, launchDescriptor(`{"executable":`+quoteJSON(t, disguised)+`}`)), "command shim")
	expectRefusal(t, descriptorDir(t, launchDescriptor(`{"executable":`+quoteJSON(t, filepath.Join(root, "bin"))+`}`)), "regular file")
	dangling := filepath.Join(root, "bin", "dangling")
	if err := os.Symlink(filepath.Join(root, "absent"), dangling); err != nil {
		t.Fatal(err)
	}
	expectRefusal(t, descriptorDir(t, launchDescriptor(`{"executable":`+quoteJSON(t, dangling)+`}`)), "unavailable")

	inside := descriptorDir(t, validDescriptor(`,"workdir":"jump"`))
	insideRoot := canonical(t, inside)
	if err := os.Symlink(filepath.Join(insideRoot, "work"), filepath.Join(insideRoot, "jump")); err != nil {
		t.Fatal(err)
	}
	app, err = LoadDescriptor(inside)
	if err != nil || app.Workdir != filepath.Join(insideRoot, "work") {
		t.Fatalf("workdir symlink inside the directory: %+v %v", app, err)
	}
	outside := descriptorDir(t, validDescriptor(`,"workdir":"jump"`))
	if err := os.Symlink(t.TempDir(), filepath.Join(canonical(t, outside), "jump")); err != nil {
		t.Fatal(err)
	}
	expectRefusal(t, outside, "inside the application directory")
}
