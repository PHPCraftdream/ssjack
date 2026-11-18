package streamtest

import (
	"context"
	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferengine"
	"github.com/PHPCraftdream/ssjack/internal/transferengine/internal/enginetest"
	"github.com/PHPCraftdream/ssjack/internal/transferengine/internal/testfixture"
	"testing"
)

func TestNewRejectsMissingRemote(t *testing.T) {
	_, err := transferengine.New(nil, transfercore.DefaultLimits())
	testfixture.ExpectClass(t, err, transfercore.ClassInternal)
}

func TestNewRejectsInvalidLimits(t *testing.T) {
	_, err := transferengine.New(testfixture.NewFakeRemote(), transfercore.Limits{MaxBytes: 1})
	testfixture.ExpectClass(t, err, transfercore.ClassInternal)
}

func TestUploadRefusesNilRoot(t *testing.T) {
	engine := enginetest.TestEngine(t, testfixture.NewFakeRemote(), transfercore.DefaultLimits())
	result, err := engine.Upload(context.Background(), nil, "src.bin", "/data/out.bin", false, nil)
	testfixture.ExpectClass(t, err, transfercore.ClassRefusedPath)
	enginetest.ExpectNoResult(t, result)
}

func TestDownloadRefusesNilRoot(t *testing.T) {
	engine := enginetest.TestEngine(t, testfixture.NewFakeRemote(), transfercore.DefaultLimits())
	result, err := engine.Download(context.Background(), nil, "/data/in.bin", "out.bin", false, nil)
	testfixture.ExpectClass(t, err, transfercore.ClassRefusedPath)
	enginetest.ExpectNoResult(t, result)
}

func TestUploadRefusesInvalidPathsBeforeRemoteCalls(t *testing.T) {
	fake := testfixture.NewFakeRemote()
	engine := enginetest.TestEngine(t, fake, transfercore.DefaultLimits())
	root := enginetest.TestRoot(t)
	testfixture.WriteLocalFile(t, root, "src.bin", []byte("x"))
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
		testfixture.ExpectClass(t, err, transfercore.ClassRefusedPath)
		enginetest.ExpectNoResult(t, result)
	}
	if fake.CallCount("Probe") != 0 || fake.CallCount("CreateStaging") != 0 {
		t.Fatalf("remote was called before path validation passed: %v", fake.CallsSnapshot())
	}
}

func TestDownloadRefusesInvalidPathsBeforeRemoteCalls(t *testing.T) {
	fake := testfixture.NewFakeRemote()
	engine := enginetest.TestEngine(t, fake, transfercore.DefaultLimits())
	root := enginetest.TestRoot(t)
	cases := []struct{ remote, local string }{
		{"relative/path", "out.bin"},
		{"", "out.bin"},
		{"/data/x", ".."},
		{"/data/x", ""},
	}
	for _, c := range cases {
		result, err := engine.Download(context.Background(), root, c.remote, c.local, false, nil)
		testfixture.ExpectClass(t, err, transfercore.ClassRefusedPath)
		enginetest.ExpectNoResult(t, result)
	}
	if len(fake.CallsSnapshot()) != 0 {
		t.Fatalf("remote was called before path validation passed: %v", fake.CallsSnapshot())
	}
}

func TestUploadProbeFailureBeforeMutation(t *testing.T) {
	fake := testfixture.NewFakeRemote()
	fake.FailProbe = transfercore.Fail(transfercore.ClassUnsupportedRemote, "remote target is missing required transfer tools")
	engine := enginetest.TestEngine(t, fake, transfercore.DefaultLimits())
	root := enginetest.TestRoot(t)
	testfixture.WriteLocalFile(t, root, "src.bin", []byte("x"))

	result, err := engine.Upload(context.Background(), root, "src.bin", "/data/out.bin", false, nil)
	testfixture.ExpectClass(t, err, transfercore.ClassUnsupportedRemote)
	enginetest.ExpectNoResult(t, result)
	if fake.CallCount("CreateStaging") != 0 {
		t.Fatal("staging was created despite a failed probe")
	}
}
