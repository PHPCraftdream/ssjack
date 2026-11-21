package flakediag

import (
	"fmt"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var (
	processStart = time.Now() // Package initialization, not OS process creation.
	entries      sync.Map     // *testing.T -> testEntry
	passes       sync.Map     // test name -> *atomic.Uint64
)

type testEntry struct {
	started time.Time
	pass    uint64
}

// Begin records the test's entry time and process-local invocation index.
// Call it once at entry, before registering diagnostic cleanups.
func Begin(t *testing.T) {
	started := time.Now()
	counter, _ := passes.LoadOrStore(t.Name(), new(atomic.Uint64))
	entries.Store(t, testEntry{started: started, pass: counter.(*atomic.Uint64).Add(1)})
	t.Cleanup(func() { entries.Delete(t) })
}

// EnvironmentLine renders failure diagnostics. Without Begin, started is a
// lower-bound timestamp such as cleanup registration time; zero gives a zero bound.
func EnvironmentLine(t *testing.T, started time.Time) string {
	entry := testEntry{started: started}
	if value, ok := entries.Load(t); ok {
		entry = value.(testEntry)
	}
	now := time.Now()
	if entry.started.IsZero() {
		entry.started = now
	}
	return renderEnvironment(entry.pass, runtime.NumCPU(), runtime.GOMAXPROCS(0),
		now.Sub(processStart), now.Sub(entry.started), runtime.NumGoroutine(), runtime.GOOS, runtime.GOARCH)
}

func renderEnvironment(pass uint64, numCPU, gomaxprocs int, processElapsed, testElapsed time.Duration, goroutines int, goos, goarch string) string {
	passLabel, testField := "unknown", "test_elapsed>="
	if pass != 0 {
		passLabel, testField = strconv.FormatUint(pass, 10), "test_elapsed="
	}
	return fmt.Sprintf("environment: pass=%s num_cpu=%d gomaxprocs=%d process_elapsed>=%s %s%s goroutines=%d goos/goarch=%s/%s",
		passLabel, numCPU, gomaxprocs, processElapsed.Truncate(time.Millisecond), testField, testElapsed.Truncate(time.Millisecond), goroutines, goos, goarch)
}
