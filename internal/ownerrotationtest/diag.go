package ownerrotationtest

import (
	"context"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/flakediag"
	"github.com/PHPCraftdream/ssjack/internal/ownerterminal"
)

// rotationDiag collects failure-only child-process and phase evidence for a
// rig. Passing runs only append timestamps; rendering happens solely through
// flakediag.OnFailure when the test has failed.
const rotationDiagTailKeep = 64 << 10

type rotationTail struct {
	mu   sync.Mutex
	data []byte
}

func newRotationTail() *rotationTail { return &rotationTail{} }

func (t *rotationTail) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.data = append(t.data, p...)
	if len(t.data) > rotationDiagTailKeep {
		t.data = append([]byte(nil), t.data[len(t.data)-rotationDiagTailKeep:]...)
	}
	return len(p), nil
}

func (t *rotationTail) snapshot() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return string(t.data)
}

// rotationTailReader tees captured child output into a rotationTail without
// changing the reader the capture sees.
type rotationTailReader struct {
	io.Reader
	closer io.Closer
	tail   *rotationTail
}

func rotationTeeOutput(output io.ReadCloser, tail *rotationTail) io.ReadCloser {
	return &rotationTailReader{Reader: output, closer: output, tail: tail}
}

func (r *rotationTailReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if n > 0 {
		_, _ = r.tail.Write(p[:n])
	}
	return n, err
}

func (r *rotationTailReader) Close() error {
	if r.closer == nil {
		return nil
	}
	return r.closer.Close()
}

type rotationMark struct {
	name string
	at   time.Time
}

type rotationChildRecord struct {
	name     string
	started  time.Time
	terminal *ownerterminal.Terminal
	tail     *rotationTail
}

type rotationDiag struct {
	mu       sync.Mutex
	marks    []rotationMark
	children []rotationChildRecord
}

// newRotationDiag registers the rig-level failure-only evidence renderer.
func newRotationDiag(t *testing.T) *rotationDiag {
	d := &rotationDiag{}
	flakediag.OnFailure(t, d.render)
	return d
}

func (d *rotationDiag) mark(name string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.marks = append(d.marks, rotationMark{name: name, at: time.Now()})
}

func (d *rotationDiag) child(name string, terminal *ownerterminal.Terminal, tail *rotationTail) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.children = append(d.children, rotationChildRecord{name: name, started: time.Now(), terminal: terminal, tail: tail})
}

// childExitStatus reports a bounded, non-blocking view of the child state.
func childExitStatus(terminal *ownerterminal.Terminal) string {
	ctx, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	if err := terminal.Wait(ctx); err != nil {
		return "still running or unjoined"
	}
	return "exited cleanly"
}

func (d *rotationDiag) render() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	var sb strings.Builder
	sb.WriteString("owner rotation rig evidence\n")
	for _, child := range d.children {
		sb.WriteString("child: name=" + child.name)
		sb.WriteString(" started=" + child.started.Format(time.RFC3339))
		sb.WriteString(" elapsed=" + time.Since(child.started).Round(time.Millisecond).String())
		sb.WriteString(" exit=" + childExitStatus(child.terminal))
		sb.WriteString("\n")
		tail := flakediag.Tail(child.tail.snapshot(), 16*1024)
		if strings.TrimSpace(tail) == "" {
			tail = "(no captured output)"
		}
		sb.WriteString("child output tail:" + tail + "\n")
	}
	if len(d.marks) == 0 {
		sb.WriteString("phases: none recorded\n")
	} else {
		origin := d.marks[0].at
		sb.WriteString("harness phases:\n")
		for i, mark := range d.marks {
			sb.WriteString("  " + mark.name + " at+" + mark.at.Sub(origin).Round(time.Millisecond).String())
			if i > 0 {
				sb.WriteString(" (gap " + mark.at.Sub(d.marks[i-1].at).Round(time.Millisecond).String() + ")")
			}
			sb.WriteString("\n")
		}
	}
	sb.WriteString("goroutine dump:\n" + flakediag.GoroutineDump(64*1024))
	return sb.String()
}

// rotationChildName returns only the executable base name for evidence.
func rotationChildName(executable string) string {
	return filepath.Base(executable)
}
