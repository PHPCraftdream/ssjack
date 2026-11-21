package flakediag

import (
	"testing"
	"time"
)

func TestLogFailurePassing(t *testing.T) {
	logFailure(false, func(string, ...any) { t.Error("logged on pass") },
		func() string { t.Error("probed environment on pass"); return "" },
		func() string { t.Error("rendered on pass"); return "" })
}

func TestRenderEnvironment(t *testing.T) {
	for _, tc := range []struct {
		pass uint64
		want string
	}{
		{0, "environment: pass=unknown num_cpu=8 gomaxprocs=4 process_elapsed>=2s test_elapsed>=12ms goroutines=9 goos/goarch=windows/amd64"},
		{3, "environment: pass=3 num_cpu=8 gomaxprocs=4 process_elapsed>=2s test_elapsed=12ms goroutines=9 goos/goarch=windows/amd64"},
	} {
		got := renderEnvironment(tc.pass, 8, 4, 2*time.Second+time.Microsecond, 12*time.Millisecond+time.Microsecond, 9, "windows", "amd64")
		if got != tc.want {
			t.Errorf("pass %d: got %q, want %q", tc.pass, got, tc.want)
		}
	}
}
