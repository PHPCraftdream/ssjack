package buildinfo

import (
	"runtime"
	"strings"
	"testing"
)

func TestBuildIdentity(t *testing.T) {
	oldVersion, oldCommit := Version, Commit
	defer func() { Version, Commit = oldVersion, oldCommit }()
	Version, Commit = "dev-test", "0123456789abcdef"
	for _, value := range []string{"ssjack dev-test", Commit, runtime.GOOS + "/" + runtime.GOARCH} {
		if !strings.Contains(String(), value) {
			t.Fatalf("build identity is missing %q", value)
		}
	}
}
