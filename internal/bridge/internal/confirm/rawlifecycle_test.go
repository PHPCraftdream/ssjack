package confirm_test

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"

	"github.com/PHPCraftdream/ssjack/internal/bridge/internal/confirm"
	"github.com/PHPCraftdream/ssjack/internal/flakediag"
)

// The state-machine lifecycle, capacity and concurrency proofs of the raw
// harness, split out of rawwire_test.go to keep both files under the size
// cap. All raw tests replace the SDK-client confirmation tests: the SDK
// client auto-fulfils input_required results and never reaches its own
// assertions.

// frameIDOf returns the response id of a raw frame as a string.
func frameIDOf(t *testing.T, frameBytes []byte) string {
	t.Helper()
	return decodeRawFrame(t, frameBytes).ID.String()
}

// writeAll sends the payloads concurrently over ONE client connection: the
// transport contract allows concurrent Write (mcp/transport.go:81-87), so the
// SERVER sees eight interleaved tools/call retries on one session, which is
// what exercises the one-use atomicity of the pending state.
func writeAll(t *testing.T, ctx context.Context, c *rawClient, payloads []string) {
	t.Helper()
	var wg sync.WaitGroup
	messages := make([]jsonrpc.Message, len(payloads))
	for i, payload := range payloads {
		message, err := jsonrpc.DecodeMessage([]byte(payload))
		if err != nil {
			t.Fatalf("the literal retry %d does not decode: %v", i, err)
		}
		messages[i] = message
	}
	for i := range messages {
		wg.Add(1)
		go func(slot int) {
			defer wg.Done()
			c.writeMu.Lock()
			defer c.writeMu.Unlock()
			if err := c.conn.Write(ctx, messages[slot]); err != nil {
				t.Errorf("retry %d: %v", slot, err)
			}
		}(i)
	}
	wg.Wait()
}

// readAllResponses reads n JSON-RPC responses, answering any elicitation
// request in between, and returns the re-encoded frames by response id.
func readAllResponses(t *testing.T, ctx context.Context, c *rawClient, n int) map[string][]byte {
	t.Helper()
	frames := make(map[string][]byte, n)
	for len(frames) < n {
		frameBytes := c.readUntilResponse(t, ctx)
		frames[frameIDOf(t, frameBytes)] = frameBytes
	}
	return frames
}

// The lifecycle refusal texts of the state machine, ported from the SDK-client
// tests to the raw harness (see the file-top note).
func TestRawStateLifecycleRefusals(t *testing.T) {
	flakediag.Begin(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// remote_download elicits exactly like remote_upload and its accepted
	// retry dispatches exactly one keeper operation.
	t.Run("download_accept_retry_dispatches", func(t *testing.T) {
		keeper := &fakeKeeper{}
		server := newRawBridge(t, ctx, keeper, nil, confirm.NewManager(nil, nil))
		client := connectRawClient(t, ctx, server, true)
		frame := client.callToolName(t, ctx, "remote_download", rawMetaModern, "", "")
		state := requireInputRequiredFrame(t, frame, "2")
		if ops := keeper.recorded(); len(ops) != 0 {
			t.Fatal("the keeper saw operations for a gated download")
		}
		beforeOps := len(keeper.recorded())
		retry := client.callToolName(t, ctx, "remote_download", rawMetaModern, rawResponses("accept"), state)
		requireDispatchFrame(t, beforeOps, retry, "3", "transfer_download", keeper)
	})

	// A tombstone PAST the tombstone window is forgotten: the retry gets the
	// generic error, not the timeout.
	t.Run("evicted_tombstone_generic_error", func(t *testing.T) {
		keeper := &fakeKeeper{}
		clock := newManualClock()
		server := newRawBridge(t, ctx, keeper, clock.Now, confirm.NewManager(clock.Now, nil))
		client := connectRawClient(t, ctx, server, true)
		state := requireInputRequiredFrame(t, client.call(t, ctx, rawMetaModern, "", ""), "2")
		clock.Advance(8 * time.Minute)
		retry := client.call(t, ctx, rawMetaModern, rawResponses("accept"), state)
		requireRefusalFrame(t, retry, rawInvalidText, "3")
		if ops := keeper.recorded(); len(ops) != 0 {
			t.Fatal("an evicted retry dispatched anyway")
		}
	})

	// A retry for a DIFFERENT tool than the confirmed call is generic.
	t.Run("changed_tool_generic_error", func(t *testing.T) {
		keeper := &fakeKeeper{}
		server := newRawBridge(t, ctx, keeper, nil, confirm.NewManager(nil, nil))
		client := connectRawClient(t, ctx, server, true)
		state := requireInputRequiredFrame(t, client.call(t, ctx, rawMetaModern, "", ""), "2")
		retry := client.callToolName(t, ctx, "remote_download", rawMetaModern, rawResponses("accept"), state)
		requireRefusalFrame(t, retry, rawInvalidText, "3")
		if ops := keeper.recorded(); len(ops) != 0 {
			t.Fatal("a changed-tool retry dispatched anyway")
		}
	})

	// A retry whose responses live under a foreign key is generic.
	t.Run("wrong_key_generic_error", func(t *testing.T) {
		keeper := &fakeKeeper{}
		server := newRawBridge(t, ctx, keeper, nil, confirm.NewManager(nil, nil))
		client := connectRawClient(t, ctx, server, true)
		state := requireInputRequiredFrame(t, client.call(t, ctx, rawMetaModern, "", ""), "2")
		responses := `{"wrong-key":{"action":"accept"}}`
		retry := client.call(t, ctx, rawMetaModern, responses, state)
		requireRefusalFrame(t, retry, rawInvalidText, "3")
		if ops := keeper.recorded(); len(ops) != 0 {
			t.Fatal("a wrong-key retry dispatched anyway")
		}
	})

	// An accept carrying content is generic.
	t.Run("accept_with_content_generic_error", func(t *testing.T) {
		keeper := &fakeKeeper{}
		server := newRawBridge(t, ctx, keeper, nil, confirm.NewManager(nil, nil))
		client := connectRawClient(t, ctx, server, true)
		state := requireInputRequiredFrame(t, client.call(t, ctx, rawMetaModern, "", ""), "2")
		responses := fmt.Sprintf(`{%q:{"action":"accept","content":{"extra":"x"}}}`, confirm.RequestKey)
		retry := client.call(t, ctx, rawMetaModern, responses, state)
		requireRefusalFrame(t, retry, rawInvalidText, "3")
		if ops := keeper.recorded(); len(ops) != 0 {
			t.Fatal("an accept-with-content retry dispatched anyway")
		}
	})

	// A replayed accept after a successful dispatch is generic and starts
	// nothing further.
	t.Run("replay_after_accept_generic_error", func(t *testing.T) {
		keeper := &fakeKeeper{}
		server := newRawBridge(t, ctx, keeper, nil, confirm.NewManager(nil, nil))
		client := connectRawClient(t, ctx, server, true)
		state := requireInputRequiredFrame(t, client.call(t, ctx, rawMetaModern, "", ""), "2")
		beforeOps := len(keeper.recorded())
		retry := client.call(t, ctx, rawMetaModern, rawResponses("accept"), state)
		requireDispatchFrame(t, beforeOps, retry, "3", "transfer_upload", keeper)
		replay := client.call(t, ctx, rawMetaModern, rawResponses("accept"), state)
		requireRefusalFrame(t, replay, rawInvalidText, "4")
		if ops := keeper.recorded(); len(ops) != beforeOps+1 {
			t.Fatalf("the keeper saw %d operations, want exactly one", len(ops))
		}
	})
}

// Port of the SDK pending-cap test: 128 prompts mint 128 DISTINCT tokens, the
// 129th is refused generically, and the earlier tokens stay answerable.
func TestRawPendingCapFailsClosed(t *testing.T) {
	flakediag.Begin(t)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	keeper := &fakeKeeper{}
	server := newRawBridge(t, ctx, keeper, nil, confirm.NewManager(nil, nil))
	client := connectRawClient(t, ctx, server, true)
	tokens := make([]string, 128)
	distinct := make(map[string]bool, 128)
	for i := 0; i < 128; i++ {
		frame := client.call(t, ctx, rawMetaModern, "", "")
		tokens[i] = requireInputRequiredFrame(t, frame, fmt.Sprint(client.lastID))
		if distinct[tokens[i]] {
			t.Fatalf("prompt %d reproduced an earlier token", i)
		}
		distinct[tokens[i]] = true
	}
	if len(distinct) != 128 {
		t.Fatalf("%d distinct tokens, want 128", len(distinct))
	}
	if ops := keeper.recorded(); len(ops) != 0 {
		t.Fatal("the keeper saw operations for gated prompts")
	}
	frame := client.call(t, ctx, rawMetaModern, "", "")
	requireRefusalFrame(t, frame, rawInvalidText, fmt.Sprint(client.lastID))
	if ops := keeper.recorded(); len(ops) != 0 {
		t.Fatal("the 129th prompt dispatched anyway")
	}
	// First, last and middle tokens remain answerable; each dispatches once.
	for _, i := range []int{0, 64, 127} {
		beforeOps := len(keeper.recorded())
		retry := client.call(t, ctx, rawMetaModern, rawResponses("accept"), tokens[i])
		requireDispatchFrame(t, beforeOps, retry, fmt.Sprint(client.lastID), "transfer_upload", keeper)
	}
	if ops := keeper.recorded(); len(ops) != 3 {
		t.Fatalf("the keeper saw %d operations, want exactly 3", len(ops))
	}
}

// Port of the one-use-under-parallel-retries test: EIGHT accept retries of the
// SAME state from ONE session are written concurrently (the transport allows
// concurrent Write, mcp/transport.go:81-87) and the server handles them
// concurrently. Exactly one may dispatch; every loser answers EXACTLY the
// fixed generic text.
func TestRawOneUseUnderParallelRetries(t *testing.T) {
	flakediag.Begin(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	keeper := &fakeKeeper{}
	server := newRawBridge(t, ctx, keeper, nil, confirm.NewManager(nil, nil))
	client := connectRawClient(t, ctx, server, true)
	state := requireInputRequiredFrame(t, client.call(t, ctx, rawMetaModern, "", ""), "2")
	if ops := keeper.recorded(); len(ops) != 0 {
		t.Fatal("the keeper saw operations for a gated call")
	}
	const attempts = 8
	payloads := make([]string, attempts)
	for i := range payloads {
		payloads[i] = client.callPayload(rawMetaModern, rawResponses("accept"), state)
	}
	writeAll(t, ctx, client, payloads)
	frames := readAllResponses(t, ctx, client, attempts)
	if client.elicitCount != 0 {
		t.Fatal("an elicitation attempt was observed during the retries")
	}
	dispatched := 0
	for id, frameBytes := range frames {
		frame := decodeRawFrame(t, frameBytes)
		if frame.Error != nil {
			t.Fatalf("retry id %s answered a JSON-RPC error, code %d", id, frame.Error.Code)
		}
		if frame.Result == nil {
			t.Fatalf("retry id %s answered without a result", id)
		}
		if !frame.Result.IsError {
			dispatched++
			continue
		}
		var content []struct {
			Text string `json:"text"`
		}
		if json.Unmarshal(frame.Result.Content, &content) != nil || len(content) != 1 {
			t.Fatalf("retry id %s is not one text block", id)
		}
		if content[0].Text != confirm.Invalid {
			t.Fatalf("a losing retry answered a text other than the fixed generic refusal")
		}
	}
	if dispatched != 1 {
		t.Fatalf("%d retries dispatched, want exactly one", dispatched)
	}
	if ops := keeper.recorded(); len(ops) != 1 || ops[0] != "transfer_upload" {
		t.Fatalf("the keeper saw %v, want exactly one transfer_upload", ops)
	}
}

// Tombstones carry session identity: an expired-but-retained token retried by
// a FOREIGN session gets the generic error, while the originating session is
// told the confirmation timed out.
func TestRawExpiredTombstoneForeignSession(t *testing.T) {
	flakediag.Begin(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	keeper := &fakeKeeper{}
	clock := newManualClock()
	server := newRawBridge(t, ctx, keeper, clock.Now, confirm.NewManager(clock.Now, nil))
	owner := connectRawClient(t, ctx, server, true)
	foreign := connectRawClient(t, ctx, server, true)
	state := requireInputRequiredFrame(t, owner.call(t, ctx, rawMetaModern, "", ""), "2")
	clock.Advance(6 * time.Minute) // expired, inside the tombstone window
	// A fresh gated mint runs the create sweep that moves the expired state
	// into the tombstone map; only the tombstone branch distinguishes
	// sessions (the in-pending expired branch times out whoever asks).
	requireInputRequiredFrame(t, owner.call(t, ctx, rawMetaModern, "", ""), "3")
	foreignRetry := foreign.call(t, ctx, rawMetaModern, rawResponses("accept"), state)
	requireRefusalFrame(t, foreignRetry, rawInvalidText, "2")
	ownerRetry := owner.call(t, ctx, rawMetaModern, rawResponses("accept"), state)
	// The owner's ids so far: initialize=1, gated call=2, fresh gated
	// mint=3, this retry=4 (each callPayload increments nextID).
	requireRefusalFrame(t, ownerRetry, "operation was not started: confirmation timed out", "4")
	if ops := keeper.recorded(); len(ops) != 0 {
		t.Fatal("an expired retry dispatched anyway")
	}
}

// manualClock is the injected clock of the raw tests (moved here from the
// SDK-client test file it used to serve).
type manualClock struct {
	mu sync.Mutex
	at time.Time
}

func newManualClock() *manualClock {
	return &manualClock{at: time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)}
}

func (c *manualClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *manualClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = c.at.Add(d)
}
