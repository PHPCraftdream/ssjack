package mcpgrant

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
	"github.com/PHPCraftdream/ssjack/internal/mcphttp"
)

func assertCleared(t *testing.T, value []byte, what string) {
	t.Helper()
	if len(value) == 0 {
		t.Fatalf("%s reference was empty before the clearing check", what)
	}
	for index, b := range value {
		if b != 0 {
			t.Fatalf("%s byte %d was not cleared", what, index)
		}
	}
}

// A later invalid record must zero the copies already owned by the partial
// construction and leave the original caller buffers untouched.
func TestNewCaptureConstructionFailureClearsOwnedCopies(t *testing.T) {
	valid, _ := grantRecord(t, "https://mcp.example.org/mcp", "bearer", "", []byte("synthetic-private-auth"), mcpdirectory.Header{Name: "X-Api-Key", Value: []byte("synthetic-private-header")})
	callerSecret := append([]byte(nil), valid.Account.Auth.Secret...)
	callerHeader := append([]byte(nil), valid.Account.Headers[0].Value...)
	capture := &Capture{records: make(map[string]Record), now: time.Now}
	if err := capture.adopt([]Record{valid}); err != nil {
		t.Fatal("the valid first record was refused")
	}
	owned, known := capture.records[valid.AccountID]
	if !known {
		t.Fatal("the adopted record was not owned by the partial capture")
	}
	ownedSecret, ownedHeader := owned.Account.Auth.Secret, owned.Account.Headers[0].Value
	stale := valid
	stale.AccountID = "conflicting"
	stale.Account.Enabled = false
	if err := capture.adopt([]Record{stale}); err != ErrGrant {
		t.Fatal("the later invalid record was admitted")
	}
	if capture.records != nil {
		t.Fatal("failed construction retained the record map")
	}
	assertCleared(t, ownedSecret, "owned secret")
	assertCleared(t, ownedHeader, "owned header")
	if !bytes.Equal(valid.Account.Auth.Secret, callerSecret) || !bytes.Equal(valid.Account.Headers[0].Value, callerHeader) {
		t.Fatal("construction failure mutated caller buffers")
	}
}

// Expiry is rechecked at the admission, record and return boundaries with an
// injected clock: no sleeps. The fourth read lands exactly on the captured
// deadline, so the return boundary refuses and consumes the capture.
func TestCaptureExpiryRefusesAtAdmissionAndReturnBoundaries(t *testing.T) {
	recordA, bindingA := grantRecord(t, "https://mcp.example.org/mcp", "bearer", "", []byte("synthetic-a"))
	recordB, bindingB := grantRecord(t, "https://mcp.example.org/mcp", "basic", "owner", []byte("synthetic-b"))
	ctx := grantContext(t)
	capture, err := NewCapture(ctx, "synthetic", 3, [32]byte{7}, []Record{recordA, recordB})
	if err != nil || capture == nil {
		t.Fatal("schema-valid capture was refused")
	}
	calls := 0
	capture.mu.Lock()
	deadline := capture.deadline
	capture.now = func() time.Time {
		calls++
		if calls <= 3 {
			return deadline.Add(-time.Minute)
		}
		return deadline
	}
	capture.mu.Unlock()
	// Two bindings produce exactly four clock reads: admission, both record
	// boundaries and the return boundary, which is the exact deadline instant.
	if launch, err := capture.Issue(ctx, "synthetic", 3, []mcpdirectory.Binding{bindingA, bindingB}); launch != nil || err != ErrGrant {
		t.Fatal("exact-deadline return boundary returned a launch")
	}
	capture.mu.Lock()
	consumed, reads := capture.issued, calls
	capture.now = time.Now
	capture.mu.Unlock()
	if !consumed || reads != 4 {
		t.Fatalf("boundary expiry consumed=%v after %d clock reads", consumed, reads)
	}
	if _, err := capture.Issue(ctx, "synthetic", 3, []mcpdirectory.Binding{bindingA, bindingB}); err != ErrGrant {
		t.Fatal("consumed capture reissued after boundary expiry")
	}
	// A strictly before-deadline capture admits its confirmed choice.
	start := time.Now()
	before := &Capture{
		ctx:      ctx,
		deadline: start.Add(time.Hour),
		now:      func() time.Time { return start },
		profile:  "synthetic",
		revision: 3,
		digest:   [32]byte{7},
		records:  map[string]Record{bindingA.AccountID: {ServerID: bindingA.ServerID, AccountID: bindingA.AccountID, Server: recordA.Server, Account: recordA.Account}},
	}
	launch, err := before.Issue(ctx, "synthetic", 3, []mcpdirectory.Binding{bindingA})
	if err != nil || launch == nil {
		t.Fatal("before-deadline capture refused its admission")
	}
	if err := launch.Close(ctx); err != nil {
		t.Fatal(err)
	}
	// Deadline and past-deadline captures refuse at admission.
	atDeadline := &Capture{
		ctx:      ctx,
		deadline: start,
		now:      func() time.Time { return start },
		profile:  "synthetic",
		revision: 3,
		digest:   [32]byte{7},
		records:  map[string]Record{bindingA.AccountID: {ServerID: bindingA.ServerID, AccountID: bindingA.AccountID, Server: recordA.Server, Account: recordA.Account}},
	}
	if launch, err := atDeadline.Issue(ctx, "synthetic", 3, []mcpdirectory.Binding{bindingA}); launch != nil || err != ErrGrant {
		t.Fatal("exact-deadline capture was admitted")
	}
	expired := &Capture{
		ctx:      ctx,
		deadline: start.Add(-MaxCaptureLifetime),
		now:      func() time.Time { return start },
		profile:  "synthetic",
		revision: 3,
		digest:   [32]byte{7},
		records:  map[string]Record{bindingA.AccountID: {ServerID: bindingA.ServerID, AccountID: bindingA.AccountID, Server: recordA.Server, Account: recordA.Account}},
	}
	if launch, err := expired.Issue(ctx, "synthetic", 3, []mcpdirectory.Binding{bindingA}); launch != nil || err != ErrGrant {
		t.Fatal("expired capture was admitted")
	}
}

// Cancelling the capture's construction parent after a successful issue under
// a distinct live issuance parent must completely propagate into the launch:
// the production callback closes its channel only after cancel returns, so
// waiting on it also waits for the upstream flow contexts to be revoked.
func TestCaptureParentCancellationRevokesIssuedUpstreams(t *testing.T) {
	parent, stopParent := context.WithCancel(context.Background())
	t.Cleanup(stopParent)
	record, binding := grantRecord(t, "https://mcp.example.org/mcp", "bearer", "", []byte("synthetic-a"))
	capture, err := NewCapture(parent, "synthetic", 3, [32]byte{7}, []Record{record})
	if err != nil || capture == nil {
		t.Fatal("schema-valid capture was refused")
	}
	issue := grantContext(t)
	launch, err := capture.Issue(issue, "synthetic", 3, []mcpdirectory.Binding{binding})
	if err != nil || launch == nil {
		t.Fatal("live issuance under a distinct parent failed")
	}
	handles := launch.Upstreams()
	if len(handles) != 1 {
		t.Fatal("launch lost its minted capability")
	}
	stopParent()
	select {
	case <-launch.propagated:
	case <-time.After(2 * time.Second):
		t.Fatal("capture-parent cancellation did not complete launch propagation")
	}
	if _, err := handles[0].Take(); err == nil {
		t.Fatal("capture-parent cancellation did not revoke the issued upstream")
	}
	if err := launch.Close(issue); err != nil {
		t.Fatal("cancelled launch cleanup failed")
	}
	// The issued capture also refuses reissue: one-shot consumption.
	if launch, err := capture.Issue(issue, "synthetic", 3, []mcpdirectory.Binding{binding}); launch != nil || err != ErrGrant {
		t.Fatal("a capture whose construction parent was cancelled still issued")
	}
	// A separate unissued capture isolates the dead-construction-parent
	// refusal from the one-shot gate.
	dead, stopDead := context.WithCancel(context.Background())
	t.Cleanup(stopDead)
	deadCapture, err := NewCapture(dead, "synthetic", 3, [32]byte{7}, []Record{record})
	if err != nil || deadCapture == nil {
		t.Fatal("unissued capture construction failed")
	}
	stopDead()
	if launch, err := deadCapture.Issue(issue, "synthetic", 3, []mcpdirectory.Binding{binding}); launch != nil || err != ErrGrant {
		t.Fatal("an unissued capture with a cancelled construction parent issued")
	}
}

// Mint-time cleanup that cannot join completely must be transferred to the
// capture through the production abandon path instead of being silently
// dropped, and the capture's close retries the retained handles. The zero
// upstream demonstrates error propagation and retention, not active I/O.
func TestIncompleteMintCleanupStaysRetainedUntilClosed(t *testing.T) {
	ctx := grantContext(t)
	capture := &Capture{
		ctx:      ctx,
		deadline: time.Now().Add(time.Hour),
		now:      time.Now,
		records:  make(map[string]Record),
	}
	broken := &Launch{cancel: func() {}, upstreams: []*mcphttp.Upstream{{}}}
	if err := capture.abandon(broken); err != ErrGrant {
		t.Fatal("failed mint cleanup lost its fixed refusal")
	}
	if len(broken.upstreams) != 0 {
		t.Fatal("the abandoned launch kept handles outside the capture")
	}
	if len(capture.doomed) != 1 {
		t.Fatal("incomplete mint cleanup was not transferred to the capture")
	}
	if err := capture.Close(ctx); err != ErrGrant {
		t.Fatal("incomplete cleanup claimed joined completion")
	}
	if len(capture.doomed) != 1 {
		t.Fatal("incomplete cleanup lost retained ownership")
	}
	if err := capture.Close(ctx); err != ErrGrant {
		t.Fatal("retained cleanup stopped being retryable")
	}
	// The same failure, retention and retry contract on a holder that still
	// owns its failing handle.
	stuck := &Launch{cancel: func() {}, upstreams: []*mcphttp.Upstream{{}}}
	if err := stuck.Close(ctx); err != ErrGrant {
		t.Fatal("failed cleanup claimed success")
	}
	if len(stuck.Upstreams()) != 1 {
		t.Fatal("failed cleanup dropped retained state")
	}
	if err := stuck.Close(ctx); err != ErrGrant {
		t.Fatal("retained cleanup stopped being retryable")
	}
	clean := &Capture{records: make(map[string]Record), now: time.Now}
	if err := clean.Close(ctx); err != nil {
		t.Fatal("clean capture reported failed cleanup")
	}
}
