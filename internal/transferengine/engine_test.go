package transferengine

import (
	"context"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
)

func TestNewRejectsMissingRemote(t *testing.T) {
	_, err := New(nil, transfercore.DefaultLimits())
	expectClass(t, err, transfercore.ClassInternal)
}

func TestNewRejectsInvalidLimits(t *testing.T) {
	_, err := New(newFakeRemote(), transfercore.Limits{MaxBytes: 1})
	expectClass(t, err, transfercore.ClassInternal)
}

func TestUploadRefusesNilRoot(t *testing.T) {
	engine := testEngine(t, newFakeRemote(), transfercore.DefaultLimits())
	result, err := engine.Upload(context.Background(), nil, "src.bin", "/data/out.bin", false, nil)
	expectClass(t, err, transfercore.ClassRefusedPath)
	expectNoResult(t, result)
}

func TestDownloadRefusesNilRoot(t *testing.T) {
	engine := testEngine(t, newFakeRemote(), transfercore.DefaultLimits())
	result, err := engine.Download(context.Background(), nil, "/data/in.bin", "out.bin", false, nil)
	expectClass(t, err, transfercore.ClassRefusedPath)
	expectNoResult(t, result)
}

func TestUploadRefusesInvalidPathsBeforeRemoteCalls(t *testing.T) {
	fake := newFakeRemote()
	engine := testEngine(t, fake, transfercore.DefaultLimits())
	root := testRoot(t)
	writeLocalFile(t, root, "src.bin", []byte("x"))
	cases := []struct{ local, remote string }{
		{"src.bin", "relative/path"},
		{"src.bin", "/"},
		{"src.bin", "/top.bin"},
		{"src.bin", "/data//x"},
		{"../outside", "/data/x"},
		{"", "/data/x"},
	}
	for _, c := range cases {
		result, err := engine.Upload(context.Background(), root, c.local, c.remote, false, nil)
		expectClass(t, err, transfercore.ClassRefusedPath)
		expectNoResult(t, result)
	}
	if fake.callCount("Probe") != 0 || fake.callCount("CreateStaging") != 0 {
		t.Fatalf("remote was called before path validation passed: %v", fake.callsSnapshot())
	}
}

func TestDownloadRefusesInvalidPathsBeforeRemoteCalls(t *testing.T) {
	fake := newFakeRemote()
	engine := testEngine(t, fake, transfercore.DefaultLimits())
	root := testRoot(t)
	cases := []struct{ remote, local string }{
		{"relative/path", "out.bin"},
		{"", "out.bin"},
		{"/data/x", ".."},
		{"/data/x", ""},
	}
	for _, c := range cases {
		result, err := engine.Download(context.Background(), root, c.remote, c.local, false, nil)
		expectClass(t, err, transfercore.ClassRefusedPath)
		expectNoResult(t, result)
	}
	if len(fake.callsSnapshot()) != 0 {
		t.Fatalf("remote was called before path validation passed: %v", fake.callsSnapshot())
	}
}

func TestUploadProbeFailureBeforeMutation(t *testing.T) {
	fake := newFakeRemote()
	fake.failProbe = transfercore.Fail(transfercore.ClassUnsupportedRemote, "remote target is missing required transfer tools")
	engine := testEngine(t, fake, transfercore.DefaultLimits())
	root := testRoot(t)
	writeLocalFile(t, root, "src.bin", []byte("x"))

	result, err := engine.Upload(context.Background(), root, "src.bin", "/data/out.bin", false, nil)
	expectClass(t, err, transfercore.ClassUnsupportedRemote)
	expectNoResult(t, result)
	if fake.callCount("CreateStaging") != 0 {
		t.Fatal("staging was created despite a failed probe")
	}
}
