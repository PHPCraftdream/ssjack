//go:build linux || darwin

package fixture

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/faultproxy"
	"github.com/PHPCraftdream/ssjack/internal/flakediag"
	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferengine"
)

const rigFirst, rigLast = 8, 24

// rigWindow preserves the opening and most recent observations in order.
type rigWindow[T any] struct {
	items [rigFirst + rigLast]T
	total int
}

func (w *rigWindow[T]) add(item T) {
	i := w.total
	if i >= rigFirst {
		i = rigFirst + (i-rigFirst)%rigLast
	}
	w.items[i] = item
	w.total++
}

func (w *rigWindow[T]) each(visit func(T), gap func(int)) {
	for i := 0; i < min(w.total, rigFirst); i++ {
		visit(w.items[i])
	}
	start := max(rigFirst, w.total-rigLast)
	if start > rigFirst {
		gap(start - rigFirst)
	}
	for i := start; i < w.total; i++ {
		visit(w.items[rigFirst+(i-rigFirst)%rigLast])
	}
}

// RigAction is a fixed label for a transfer or one of its remote calls.
type RigAction uint8

const (
	RigUpload RigAction = iota + 1
	RigDownload
	RigWrite
	RigRead
	RigPart
	RigRange
	RigStat
	RigAssemble
)

func (a RigAction) label() string {
	labels := [...]string{"unknown", "upload", "download", "write-stream", "read-stream", "upload-part", "download-range", "stat-source", "assemble"}
	if int(a) >= len(labels) {
		return labels[0]
	}
	return labels[a]
}

// RigCall contains only numeric inputs known by the hook. Its transfer ordinal
// is captured at entry and reused on completion, alongside the call attempt.
type RigCall struct {
	Action                     RigAction
	Attempt, Parts             int
	Offset, Length, Grid, Size int64
	transfer                   int
}

type rigResult struct {
	state, mode, class                string
	bytes, chunkBytes, bytesPerSec    int64
	chunksDone, chunksTotal, attempts int
}

type rigRule struct {
	index     int
	from      bool
	stall     bool
	direction faultproxy.Direction
	threshold int64
}

type rigEvent struct {
	seq, transfer int
	at            time.Duration
	label         string
	call          RigCall
	value         int64
	stored        bool
	class         string
	result        rigResult
	rule          rigRule
}

// RigDiagnostics records bounded metadata only. No proxy scans are added on
// the passing path; all formatting is deferred until failure cleanup.
type RigDiagnostics struct {
	mu       sync.Mutex
	started  time.Time
	proxy    *faultproxy.Proxy
	transfer int
	action   RigAction
	state    string
	result   rigResult
	lastRule rigEvent
	events   rigWindow[rigEvent]
	rules    rigWindow[rigEvent]
}

// RegisterRigDiagnostics must run after faultproxy.Start, so its snapshot
// precedes the proxy's blocking Close cleanup.
func RegisterRigDiagnostics(t *testing.T, proxy *faultproxy.Proxy) *RigDiagnostics {
	d := &RigDiagnostics{started: time.Now(), proxy: proxy, state: "not-started", result: rigResult{state: "no-result", mode: "unset", class: "unset"}}
	flakediag.OnFailure(t, d.render)
	return d
}

// record requires d.mu. Sequence makes equal elapsed readings unambiguous.
func (d *RigDiagnostics) record(e rigEvent) {
	e.seq, e.at = d.events.total+1, time.Since(d.started)
	if e.transfer == 0 {
		e.transfer = d.transfer
	}
	d.events.add(e)
	switch e.label {
	case "proxy-armed":
		d.rules.add(e)
		d.lastRule = e
	case "proxy-cleared":
		d.lastRule = e
	}
}

func (d *RigDiagnostics) Start(action RigAction) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.transfer++
	d.action, d.state = action, "running"
	d.result = rigResult{state: "no-result", mode: "unset", class: "unset"}
	d.record(rigEvent{label: "transfer-start", call: RigCall{Action: action}})
}

func (d *RigDiagnostics) Enter(call RigCall) RigCall {
	d.mu.Lock()
	defer d.mu.Unlock()
	call.transfer = d.transfer
	d.record(rigEvent{label: "call-enter", call: call})
	return call
}

func (d *RigDiagnostics) Complete(call RigCall, value int64, stored bool, err error) {
	class := rigErrorClass(err)
	d.mu.Lock()
	defer d.mu.Unlock()
	d.record(rigEvent{label: "call-return", transfer: call.transfer, call: call, value: value, stored: stored, class: class})
}

func rigErrorClass(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline_exceeded"
	case errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, io.EOF):
		return "eof"
	}
	switch class := transfercore.ClassOf(err); class {
	case transfercore.ClassRefusedPath, transfercore.ClassExists, transfercore.ClassLimit,
		transfercore.ClassUnsupportedRemote, transfercore.ClassIntegrity, transfercore.ClassRemoteFailed,
		transfercore.ClassLinkUnstable, transfercore.ClassCancelled, transfercore.ClassInternal:
		return string(class)
	default:
		return "unknown"
	}
}

// Drain captures the returned result before WaitIdle can terminate the test.
func (d *RigDiagnostics) Drain(t *testing.T, server *ExecServer, res transferengine.Result, err error) {
	t.Helper()
	r := rigResult{
		state: "complete", mode: "unset", class: rigErrorClass(err), bytes: res.Bytes,
		chunkBytes: res.ChunkBytes, bytesPerSec: res.BytesPerSecond,
		chunksDone: res.ChunksDone, chunksTotal: res.ChunksTotal, attempts: res.Attempts,
	}
	switch res.Mode {
	case transferengine.ModeStream, transferengine.ModeChunked:
		r.mode = res.Mode
	case "":
	default:
		r.mode = "unknown"
	}
	if err != nil {
		r.state = "partial"
		if res.Bytes == 0 && res.Mode == "" && res.ChunkBytes == 0 && res.ChunksDone == 0 &&
			res.ChunksTotal == 0 && res.Attempts == 0 && res.BytesPerSecond == 0 && res.Files == 0 && res.Dirs == 0 {
			r.state = "no-result"
		}
	}
	d.mu.Lock()
	d.result = r
	d.record(rigEvent{label: "engine-return", result: r})
	d.state = "draining"
	d.record(rigEvent{label: "drain-start"})
	d.mu.Unlock()
	// A command on a cut connection may still be finishing. Keep the
	// sandbox inspection boundary even if the engine already returned.
	server.WaitIdle(t)
	d.mu.Lock()
	d.state = "drained"
	d.record(rigEvent{label: "drain-done"})
	d.mu.Unlock()
}

// ArmProxy reuses the rig's existing next-connection snapshot. Rule
// installation still affects only connections accepted with the new plan.
func (d *RigDiagnostics) ArmProxy(t *testing.T, dir faultproxy.Direction, n int64, from, stall bool) {
	t.Helper()
	index := d.proxy.Stats().Accepted + 1
	selector := faultproxy.Conns(index)
	if from {
		selector = faultproxy.FromConn(index)
	}
	fault := faultproxy.DropAfterBytes(dir, n)
	if stall {
		fault = faultproxy.StallAfterBytes(dir, n)
	}
	d.proxy.MustSetRules(t, faultproxy.Rule{Conns: selector, Faults: []faultproxy.Fault{fault}})
	d.mu.Lock()
	d.record(rigEvent{label: "proxy-armed", rule: rigRule{index: index, from: from, stall: stall, direction: dir, threshold: n}})
	d.mu.Unlock()
}

func (d *RigDiagnostics) ClearProxy(t *testing.T) {
	t.Helper()
	d.proxy.MustSetRules(t)
	d.mu.Lock()
	d.record(rigEvent{label: "proxy-cleared"})
	d.mu.Unlock()
}

// AssemblyKill records configuration only. Actual kills are fixture evidence.
func (d *RigDiagnostics) AssemblyKill(attempt int) {
	label := "assembly-kill-armed"
	if attempt == 0 {
		label = "assembly-kill-cleared"
	}
	d.mu.Lock()
	d.record(rigEvent{label: label, call: RigCall{Attempt: attempt}})
	d.mu.Unlock()
}

func renderRigResult(b *strings.Builder, r rigResult) {
	fmt.Fprintf(b, " result=%s class=%s mode=%s bytes=%d chunk_bytes=%d chunks_done=%d chunks_total=%d attempts=%d bytes_per_second=%d",
		r.state, r.class, r.mode, r.bytes, r.chunkBytes, r.chunksDone, r.chunksTotal, r.attempts, r.bytesPerSec)
}

func renderRigEvent(b *strings.Builder, e rigEvent) {
	fmt.Fprintf(b, "\n+%s seq=%d transfer=%d %s", e.at, e.seq, e.transfer, e.label)
	c := e.call
	switch e.label {
	case "transfer-start":
		fmt.Fprintf(b, " action=%s", c.Action.label())
	case "call-enter", "call-return":
		fmt.Fprintf(b, " action=%s attempt=%d", c.Action.label(), c.Attempt)
		switch c.Action {
		case RigPart:
			fmt.Fprintf(b, " offset=%d length=%d", c.Offset, c.Length)
		case RigRange:
			fmt.Fprintf(b, " offset=%d length=%d grid=%d file_size=%d", c.Offset, c.Length, c.Grid, c.Size)
		case RigAssemble:
			fmt.Fprintf(b, " parts=%d requested_size=%d", c.Parts, c.Size)
		}
		if e.label == "call-return" {
			fmt.Fprintf(b, " class=%s", e.class)
			switch c.Action {
			case RigPart:
				fmt.Fprintf(b, " count=%d stored=%t", e.value, e.stored)
			case RigStat, RigAssemble:
				fmt.Fprintf(b, " size=%d", e.value)
			default:
				fmt.Fprintf(b, " bytes=%d", e.value)
			}
		}
	case "engine-return":
		renderRigResult(b, e.result)
	case "proxy-armed":
		renderRigRule(b, e.rule)
	case "assembly-kill-armed":
		fmt.Fprintf(b, " attempt=%d", c.Attempt)
	}
}

func renderRigRule(b *strings.Builder, r rigRule) {
	kind, scope, direction := "drop", "next", "unknown"
	if r.stall {
		kind = "stall"
	}
	if r.from {
		scope = "from"
	}
	switch r.direction {
	case faultproxy.ClientToServer:
		direction = "c2s"
	case faultproxy.ServerToClient:
		direction = "s2c"
	case faultproxy.Both:
		direction = "both"
	}
	fmt.Fprintf(b, " kind=%s scope=%s conn=%d direction=%s threshold=%d", kind, scope, r.index, direction, r.threshold)
}

func renderRigConn(b *strings.Builder, label string, c faultproxy.ConnStats) {
	reason := "unknown"
	switch c.Reason {
	case faultproxy.ReasonNone:
		reason = "none"
	case faultproxy.ReasonBytes, faultproxy.ReasonDuration, faultproxy.ReasonManual,
		faultproxy.ReasonRefused, faultproxy.ReasonError, faultproxy.ReasonShutdown:
		reason = string(c.Reason)
	}
	fmt.Fprintf(b, "\n%s conn=%d ssh_c2s=%d ssh_s2c=%d closed=%t halted=%t stalled=%t reason=%s",
		label, c.Index, c.ClientToServer, c.ServerToClient, c.Closed, c.Halted, c.Stalled, reason)
}

func (d *RigDiagnostics) render() string {
	d.mu.Lock()
	events, rules, lastRule := d.events, d.rules, d.lastRule
	transfer, action, state, result := d.transfer, d.action, d.state, d.result
	d.mu.Unlock()
	stats := d.proxy.Stats()
	observedAt := time.Since(d.started)
	var b strings.Builder
	fmt.Fprintf(&b, "chunk rig: transfer=%d action=%s engine=%s", transfer, action.label(), state)
	renderRigResult(&b, result)
	events.each(func(e rigEvent) { renderRigEvent(&b, e) }, func(n int) {
		fmt.Fprintf(&b, "\n... timeline_omitted=%d", n)
	})
	// Keep arm metadata available even if intervening calls evicted it from
	// the main timeline. The original sequence ties it to that timeline.
	if cutoff := events.total - rigLast; cutoff > rigFirst {
		wroteHeader := false
		rules.each(func(e rigEvent) {
			if e.seq <= rigFirst || e.seq > cutoff {
				return
			}
			if !wroteHeader {
				b.WriteString("\nretained-arms-outside-timeline:")
				wroteHeader = true
			}
			fmt.Fprintf(&b, "\nretained-arm seq=%d transfer=%d", e.seq, e.transfer)
			renderRigRule(&b, e.rule)
		}, func(int) {})
	}
	if lastRule.seq == 0 {
		b.WriteString("\nproxy-last-config=initial")
	} else {
		fmt.Fprintf(&b, "\nproxy-last-config=%s seq=%d", lastRule.label, lastRule.seq)
	}
	fmt.Fprintf(&b, "\n+%s proxy-observed accepted=%d dropped=%d refused=%d stalled=%d closed=%d ssh_c2s=%d ssh_s2c=%d",
		observedAt, stats.Accepted, stats.Dropped, stats.Refused, stats.Stalled, stats.Closed, stats.ClientToServer, stats.ServerToClient)
	var fires, others rigWindow[faultproxy.ConnStats]
	for _, c := range stats.Conns {
		if c.Reason == faultproxy.ReasonBytes || c.Stalled {
			fires.add(c)
		} else {
			others.add(c)
		}
	}
	fmt.Fprintf(&b, "\nproxy-fire-count=%d arm_history_omitted=%d", fires.total, max(0, rules.total-rigFirst-rigLast))
	fires.each(func(c faultproxy.ConnStats) {
		renderRigConn(&b, "proxy-fire-observed", c)
		// The proxy does not expose the accept/firing timestamps or the rule
		// generation. List compatible retained arms, not attribution. Byte
		// counts only narrow candidates after a fire has been observed.
		// A later clear or replacement does not remove an accepted plan.
		matches := 0
		rules.each(func(e rigEvent) {
			r := e.rule
			var forwarded int64
			if r.direction&faultproxy.ClientToServer != 0 {
				forwarded += c.ClientToServer
			}
			if r.direction&faultproxy.ServerToClient != 0 {
				forwarded += c.ServerToClient
			}
			if forwarded == r.threshold && (c.Index == r.index || r.from && c.Index > r.index) &&
				(r.stall && c.Stalled || !r.stall && c.Reason == faultproxy.ReasonBytes) {
				fmt.Fprintf(&b, " candidate_arm_seq=%d", e.seq)
				matches++
			}
		}, func(int) {})
		if matches == 0 {
			b.WriteString(" candidate_arm=none-retained")
		}
	}, func(n int) { fmt.Fprintf(&b, "\n... proxy_fire_omitted=%d", n) })
	others.each(func(c faultproxy.ConnStats) { renderRigConn(&b, "proxy-conn-observed", c) },
		func(n int) { fmt.Fprintf(&b, "\n... proxy_conn_omitted=%d", n) })
	if n := len(stats.Conns); n != 0 {
		renderRigConn(&b, "proxy-last-conn-observed", stats.Conns[n-1])
	}
	return b.String()
}
