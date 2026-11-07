package mcpgrant

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
	"github.com/PHPCraftdream/ssjack/internal/mcphttp"
	"github.com/PHPCraftdream/ssjack/internal/outputguard"
)

// assertMasked proves a transmitted authentication literal is covered by the
// launch guard without exposing any value.
func assertMasked(t *testing.T, snapshot *outputguard.Snapshot, literal string) {
	t.Helper()
	var output bytes.Buffer
	writer, err := outputguard.NewWriter(snapshot, &output)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []byte(literal) {
		if _, err := writer.Write([]byte{value}); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil || output.String() != outputguard.Marker {
		t.Fatal("launch guard lost a transmitted authentication literal")
	}
}

func TestIssueMintsOneShotLaunchWithUnionGuard(t *testing.T) {
	endpoint := "https://mcp.example.org/mcp"
	recordA, bindingA := grantRecord(t, endpoint, "bearer", "", []byte("synthetic-a"), mcpdirectory.Header{Name: "X-Api-Key", Value: []byte("synthetic-header")})
	recordB, bindingB := grantRecord(t, endpoint, "basic", "owner", []byte("synthetic-b"))
	ctx := grantContext(t)
	capture, err := NewCapture(ctx, "synthetic", 3, [32]byte{7}, []Record{recordA, recordB})
	if err != nil || capture == nil {
		t.Fatal("schema-valid capture was refused")
	}
	launch, err := capture.Issue(ctx, "synthetic", 3, []mcpdirectory.Binding{bindingA, bindingB})
	if err != nil || launch == nil {
		t.Fatal("valid selection failed to mint a launch")
	}
	handles := launch.Upstreams()
	if len(handles) != 2 {
		t.Fatal("launch lost a minted capability")
	}
	if _, err := handles[0].Take(); err != nil {
		t.Fatal("capability refused its first use")
	}
	if _, err := handles[0].Take(); err == nil {
		t.Fatal("capability was reused")
	}
	guard, err := launch.Guard()
	if err != nil || guard == nil {
		t.Fatal("launch refused its output guard")
	}
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("owner:synthetic-b"))
	for _, literal := range []string{"synthetic-a", "Bearer synthetic-a", "synthetic-header", "synthetic-b", basic, strings.TrimPrefix(basic, "Basic ")} {
		assertMasked(t, guard, literal)
	}
	var pair bytes.Buffer
	pairWriter, pairErr := outputguard.NewWriter(guard, &pair)
	if pairErr != nil {
		t.Fatal(pairErr)
	}
	for _, value := range []byte("owner:synthetic-b") {
		if _, err := pairWriter.Write([]byte{value}); err != nil {
			t.Fatal(err)
		}
	}
	if pairErr = pairWriter.Close(); pairErr != nil || pair.String() != "owner:"+outputguard.Marker {
		t.Fatal("launch guard masked outside its transmitted literals")
	}
	again, err := capture.Issue(ctx, "synthetic", 3, []mcpdirectory.Binding{bindingA, bindingB})
	if again != nil || err != ErrGrant {
		t.Fatal("capture minted twice")
	}
	if err := launch.Close(ctx); err != nil {
		t.Fatal("launch cleanup failed")
	}
	if len(launch.Upstreams()) != 0 {
		t.Fatal("closed launch still handles capabilities")
	}
	if _, err := launch.Guard(); err != ErrGrant {
		t.Fatal("closed launch still grants its guard")
	}
	capture.Close(ctx)
}

func TestLaunchCloseFailureRetainsStateAndCanBeWaitedAgain(t *testing.T) {
	ctx := grantContext(t)
	broken := &Launch{cancel: func() {}, upstreams: []*mcphttp.Upstream{{}}}
	if err := broken.Close(ctx); err != ErrGrant {
		t.Fatal("failed cleanup claimed success")
	}
	if len(broken.Upstreams()) != 1 {
		t.Fatal("failed cleanup dropped retained state")
	}
	if err := broken.Close(ctx); err != ErrGrant {
		t.Fatal("retained cleanup stopped being retryable")
	}
	fresh := &Launch{cancel: func() {}}
	if err := fresh.Close(ctx); err != nil {
		t.Fatal("fresh launch cleanup failed")
	}
	if err := fresh.Close(ctx); err != nil {
		t.Fatal("closed launch was not idempotent")
	}
	empty := &Launch{}
	if err := empty.Close(ctx); err != ErrGrant {
		t.Fatal("zero launch claimed cleanup")
	}
	if _, err := empty.Guard(); err != ErrGrant {
		t.Fatal("zero launch granted a guard")
	}
	var gone *Launch
	if handles := gone.Upstreams(); handles != nil {
		t.Fatal("nil launch returned handles")
	}
	if err := gone.Close(ctx); err != ErrGrant {
		t.Fatal("nil launch claimed cleanup")
	}
	if _, err := gone.Guard(); err != ErrGrant {
		t.Fatal("nil launch granted a guard")
	}
}

func TestFailedMintConsumesCaptureWithoutFallbackLaunch(t *testing.T) {
	valid, bindingValid := grantRecord(t, "https://mcp.example.org/mcp", "none", "", nil)
	loopback, bindingLoop := grantRecord(t, "https://127.0.0.1:8443/mcp", "none", "", nil)
	ctx := grantContext(t)
	capture, err := NewCapture(ctx, "synthetic", 3, [32]byte{7}, []Record{valid, loopback})
	if err != nil || capture == nil {
		t.Fatal("schema-valid capture was refused")
	}
	launch, err := capture.Issue(ctx, "synthetic", 3, []mcpdirectory.Binding{bindingValid, bindingLoop})
	if launch != nil || err != ErrGrant {
		t.Fatal("failed mint returned a launch")
	}
	launch2, err := capture.Issue(ctx, "synthetic", 3, []mcpdirectory.Binding{bindingValid})
	if launch2 != nil || err != ErrGrant {
		t.Fatal("failed mint was silently replayed")
	}
	clean, bindingClean := grantRecord(t, "https://mcp.example.org/mcp", "none", "", nil)
	capture2, err := NewCapture(ctx, "synthetic", 3, [32]byte{9}, []Record{clean})
	if err != nil || capture2 == nil {
		t.Fatal("control capture was refused")
	}
	good, err := capture2.Issue(ctx, "synthetic", 3, []mcpdirectory.Binding{bindingClean})
	if err != nil || good == nil {
		t.Fatal("public endpoint mint failed")
	}
	if err := good.Close(ctx); err != nil {
		t.Fatal("control launch cleanup failed")
	}
	capture2.Close(ctx)
	capture.Close(ctx)
}
