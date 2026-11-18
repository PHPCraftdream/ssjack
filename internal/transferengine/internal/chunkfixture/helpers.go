// Package chunkfixture holds the rigs and shared content helpers of the
// chunked upload/download tests: one engine over the in-memory chunk remote
// with a virtual clock and a real temporary transfer root, so no test sleeps
// or waits on a real timer. The chunk suite and the separate stall suite
// consume these rigs.
package chunkfixture

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/transferengine"
	"github.com/PHPCraftdream/ssjack/internal/transferengine/internal/testfixture"
	"github.com/PHPCraftdream/ssjack/internal/transferlink"
)

// Shared dimensions and remote paths of the chunk suite.
const (
	ChunkMiB  = 1 << 20
	ChunkDest = "/data/out.bin"
	DlRemote  = "/data/remote.bin"
)

// ProgressLog records the progress reports of one job.
type ProgressLog struct{ Items []transferengine.Progress }

func (p *ProgressLog) Add(pr transferengine.Progress) { p.Items = append(p.Items, pr) }

func ChunkContent(n int, seed byte) []byte {
	out := make([]byte, n)
	state := uint32(seed)*2654435761 + 1
	for i := range out {
		state = state*1664525 + 1013904223
		out[i] = byte(state >> 24)
	}
	return out
}

func SumHex(content []byte) string {
	s := sha256.Sum256(content)
	return hex.EncodeToString(s[:])
}

func AssertMonotone(t *testing.T, items []transferengine.Progress) {
	t.Helper()
	var last int64
	for i, p := range items {
		if p.Bytes < last {
			t.Fatalf("progress %d (%s) went back from %d to %d bytes", i, p.Phase, last, p.Bytes)
		}
		last = p.Bytes
	}
}

func AssertTiles(t *testing.T, size int64, parts []transferlink.Range) {
	t.Helper()
	if err := transferlink.ValidateTiling(size, parts); err != nil {
		t.Fatalf("parts do not tile the file: %v (%v)", err, parts)
	}
}

func SumLens(parts []transferlink.Range) int64 {
	var n int64
	for _, p := range parts {
		n += p.Len
	}
	return n
}

func SeedParts(content []byte, ranges ...transferlink.Range) map[transferlink.Range][]byte {
	out := map[transferlink.Range][]byte{}
	for _, r := range ranges {
		out[r] = content[r.Off:r.End()]
	}
	return out
}

// DropFirstStream scripts the first whole-stream attempt to drop after cut
// bytes; later streams run normally.
func DropFirstStream(cut int64) func(int) *testfixture.PartFailure {
	return func(n int) *testfixture.PartFailure {
		if n == 1 {
			return &testfixture.PartFailure{Cut: cut}
		}
		return nil
	}
}

// DlDropFirstStream is the download-side spelling of DropFirstStream.
func DlDropFirstStream(cut int64) func(int) *testfixture.PartFailure {
	return DropFirstStream(cut)
}

// MakeForeignStage creates a staging directory the engine does not own, so a
// keyed lookup finds a foreign object.
func MakeForeignStage(t *testing.T, dir string) {
	t.Helper()
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir+"/keep", []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// DlSnapshot renders a directory tree (names and file contents).
func DlSnapshot(t *testing.T, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, e := range entries {
		b.WriteString(e.Name())
		full := dir + string(os.PathSeparator) + e.Name()
		switch {
		case e.IsDir():
			b.WriteString(" [" + DlSnapshot(t, full) + "]")
		case e.Type().IsRegular():
			data, err := os.ReadFile(full)
			if err != nil {
				t.Fatal(err)
			}
			b.WriteString(" " + string(data))
		}
		b.WriteString("\n")
	}
	return b.String()
}

// ExpectFinish runs op on a goroutine and fails the test if it has not
// returned within the deadline, so a deadlock cannot hang CI.
func ExpectFinish(t *testing.T, deadline time.Duration, op func() (transferengine.Result, error)) (transferengine.Result, error) {
	t.Helper()
	type outcome struct {
		result transferengine.Result
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		result, err := op()
		done <- outcome{result: result, err: err}
		close(done)
	}()
	select {
	case o := <-done:
		return o.result, o.err
	case <-time.After(deadline):
		t.Fatalf("operation did not finish within %s", deadline)
		return transferengine.Result{}, nil
	}
}
