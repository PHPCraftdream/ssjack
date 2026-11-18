//go:build linux || darwin

package transferacceptance

import (
	"testing"

	fixture "github.com/PHPCraftdream/ssjack/internal/transferacceptance/internal/fixture"
)

// The fixture chunk of the acceptance suite lives in
// internal/transferacceptance/internal/fixture; this facade restores the
// public API that the scenario files in this package consume.

// ExecServer is an in-process SSH server whose exec handler really runs the
// received command with sh -c inside a sandbox directory; see the fixture
// package for details.
type ExecServer = fixture.ExecServer

// StartExecServer starts the fixture on the loopback interface and stops it
// during test cleanup. env replaces the environment of every executed
// command; nil inherits the test process environment.
func StartExecServer(t *testing.T, sandbox string, env []string) *ExecServer {
	return fixture.StartExecServer(t, sandbox, env)
}

// SeedPayload returns deterministic pseudo-random bytes with binary corner
// values, so repeated trees and hashes are reproducible.
func SeedPayload(size int, seed byte) []byte { return fixture.SeedPayload(size, seed) }

// WriteTree creates directories and regular files under base; keys are
// slash-separated relative paths.
func WriteTree(t *testing.T, base string, files map[string][]byte, dirs []string) {
	fixture.WriteTree(t, base, files, dirs)
}

// CompareTrees compares two directory trees byte-exactly: same regular
// files, same bytes, same directory set, nothing else.
func CompareTrees(t *testing.T, want, got string) { fixture.CompareTrees(t, want, got) }

// AssertNoStaging fails when a transfer staging directory remains in base.
func AssertNoStaging(t *testing.T, base string) { fixture.AssertNoStaging(t, base) }

// assertTreeSnapshot requires a fixture tree to retain the same files, bytes,
// and directories as a previously captured state.
func assertTreeSnapshot(t *testing.T, base string, wantFiles map[string][]byte, wantDirs []string) {
	fixture.AssertTreeSnapshot(t, base, wantFiles, wantDirs)
}
