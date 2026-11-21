package agent_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	mcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/cli"
	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/remotemcp"
	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/testsupport/childdiag"
	"github.com/PHPCraftdream/ssjack/internal/broker"
	"github.com/PHPCraftdream/ssjack/internal/flakediag"
	"github.com/PHPCraftdream/ssjack/internal/mcpchannel"
	"github.com/PHPCraftdream/ssjack/internal/outputguard"
)

const remoteMCPConnectedHarnessMarker = "REMOTE-MCP-CONNECTED-HARNESS-VERIFIED:"
const remoteMCPConnectedBridgeChildEnv = "SSJACK_REMOTE_MCP_CONNECTED_BRIDGE_CHILD"
const remoteMCPConnectedScenarioEnv = "SSJACK_REMOTE_MCP_CONNECTED_SCENARIO"
const remoteMCPConnectedWaitAckEnv = "SSJACK_REMOTE_MCP_CONNECTED_WAIT_ACK"

// The production bridge negotiates the latest protocol version; the constant
// lives in the internal remotemcp package, so the suite pins the same literal.
const remoteMCPTestProtocol20260728 = "2026-07-28"

func TestNativeRemoteMCPConnectedStartupChild(t *testing.T) {
	if os.Getenv("SSJACK_REMOTE_MCP_STARTUP_CHILD") != "1" || !remoteMCPConnectedScenario(os.Getenv("SSJACK_REMOTE_MCP_STARTUP_SCENARIO")) {
		t.Skip("connected startup fixture only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	scenario := os.Getenv("SSJACK_REMOTE_MCP_STARTUP_SCENARIO")
	if err := installRemoteMCPConnectedRouteFromEnvironment(); err != nil {
		t.Fatal("connected route setup refused")
	}
	_ = os.Unsetenv(remoteMCPConnectedRouteEnv)
	var args []string
	for index, argument := range os.Args {
		if argument == "--" {
			args = os.Args[index+1:]
			break
		}
	}
	code, err := cli.Run(ctx, args)
	if scenario == "connected-cancel" {
		if code != 1 || err == nil || err.Error() != "remote MCP selection cancelled; no database changes were made" {
			t.Fatal("connected prelaunch cancellation was not refused")
		}
		fmt.Fprintln(os.Stderr, "REMOTE-MCP-CONNECTED-CANCEL-VERIFIED")
		return
	}
	if err != nil || code != 0 {
		t.Fatal("connected startup command did not complete")
	}
}

// This is the real stdio MCP process spawned by the production launcher.
func TestNativeRemoteMCPConnectedBridge(t *testing.T) {
	if os.Getenv(remoteMCPConnectedBridgeChildEnv) != "1" {
		t.Skip("connected MCP bridge process only")
	}
	remoteMCPConnectedHarnessEnvironment(t)
	code, err := remotemcp.Run(context.Background())
	if err != nil || code != 0 {
		fmt.Fprintln(os.Stderr, "REMOTE-MCP-CONNECTED-BRIDGE-CLEANUP-FAILED")
		os.Exit(1)
	}
	os.Exit(0)
}

// This real SDK client is the launcher harness and calls namespaced tools over
// the production stdio bridge; the separate bridge process uses remotemcp.Run above.
func TestNativeRemoteMCPConnectedHarness(t *testing.T) {
	scenario := os.Getenv(remoteMCPConnectedScenarioEnv)
	if !remoteMCPConnectedScenario(scenario) {
		t.Skip("connected MCP harness only")
	}
	waitAck, hasWaitAck := os.LookupEnv(remoteMCPConnectedWaitAckEnv)
	if err := os.Unsetenv(remoteMCPConnectedWaitAckEnv); err != nil {
		t.Fatal("connected wait ACK environment could not be cleared")
	}
	if scenario == "connected-active-cancel" {
		if !hasWaitAck || !filepath.IsAbs(waitAck) {
			t.Fatal("connected wait ACK base is missing or not absolute")
		}
	} else if hasWaitAck {
		t.Fatal("connected wait ACK was set outside active cancellation")
	}
	remoteMCPConnectedHarnessEnvironment(t)
	_ = os.Unsetenv(remoteMCPConnectedScenarioEnv)
	_ = os.Unsetenv(remoteMCPConnectedRouteEnv)
	encodedChannels := os.Getenv(mcpchannel.Env)
	var capability string
	if scenario == "connected-empty" {
		if encodedChannels != "" {
			t.Fatal("empty confirmed choice carried a private channel descriptor")
		}
	} else {
		descriptors, err := mcpchannel.DecodeDescriptors(encodedChannels)
		if err != nil || len(descriptors) != 1 || descriptors[0].Ordinal != 0 {
			t.Fatal("confirmed local channel capability is unavailable")
		}
		channelToken := descriptors[0].Token
		keeperToken := os.Getenv(broker.EnvToken)
		if len(channelToken) != 64 || len(keeperToken) != 64 || channelToken == keeperToken {
			t.Fatal("connected harness did not receive distinct per-launch capabilities")
		}
		capability = channelToken + "|" + keeperToken
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal("test executable unavailable")
	}
	command := exec.Command(executable, "-test.run=^TestNativeRemoteMCPConnectedBridge$")
	phases := childdiag.NewPhases()
	flakediag.OnFailure(t, phases.Render)
	// Bridge stderr may contain private data; report process metadata only.
	command.Stderr = io.Discard
	childdiag.ProcessOnFailure(t, "connected bridge child", command, nil, time.Now())
	command.Env = append(nativeStartupEnvironment(), remoteMCPConnectedBridgeChildEnv+"=1")
	if encodedChannels != "" {
		command.Env = append(command.Env, mcpchannel.Env+"="+encodedChannels)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "connected-acceptance-harness", Version: "1"}, nil)
	phases.Mark("bridge attach attempted")
	session, err := client.Connect(ctx, &mcp.CommandTransport{Command: command}, nil)
	if err != nil {
		t.Fatal("connected harness could not attach to the real stdio bridge")
	}
	phases.Mark("bridge attached")
	initializeResult := session.InitializeResult()
	closed := false
	defer func() {
		if !closed {
			_ = session.Close()
		}
	}()
	if initializeResult == nil || initializeResult.ProtocolVersion != remoteMCPTestProtocol20260728 {
		t.Fatal("connected bridge did not negotiate the latest protocol")
	}
	listing := remoteMCPConnectedList(ctx, t, session, scenario != "connected-empty")
	phases.Mark("tools registered")
	if scenario != "connected-empty" {
		remoteMCPConnectedCapabilityNegativeControl(t, ctx, encodedChannels, session)
	}
	if scenario == "connected-cancel" {
		t.Fatal("cancelled selection unexpectedly launched the harness")
	}
	if scenario == "connected-empty" {
		if len(listing) != 12 {
			t.Fatal("empty confirmed choice exposed non-base tools")
		}
	} else {
		remote := make([]string, 0, 3)
		for _, tool := range listing {
			if tool != nil && strings.HasPrefix(tool.Name, "mcp") {
				remote = append(remote, tool.Name)
			}
		}
		if len(remote) != 3 || remoteMCPConnectedTool(remote, "echo") == "" || remoteMCPConnectedTool(remote, "fail") == "" || remoteMCPConnectedTool(remote, "wait") == "" {
			t.Fatal("selected account inventory was not exactly scoped")
		}
		prefix := remote[0][:strings.LastIndex(remote[0], "_")+1]
		for _, name := range remote {
			if !strings.HasPrefix(name, prefix) {
				t.Fatal("connected tools crossed binding namespaces")
			}
		}
		if prefix != os.Getenv("SSJACK_REMOTE_MCP_EXPECTED_NAMESPACE") {
			t.Fatal("connected tools escaped the exact confirmed binding")
		}
		echo := remoteMCPConnectedTool(remote, "echo")
		fail := remoteMCPConnectedTool(remote, "fail")
		waitTool := remoteMCPConnectedTool(remote, "wait")
		remoteMCPConnectedCall(t, ctx, session, echo, false, scenario == "connected-bypass", capability)
		remoteMCPConnectedCall(t, ctx, session, fail, true, scenario == "connected-bypass", "")
		if scenario == "connected-bypass" {
			remoteMCPConnectedRPCFailure(t, ctx, session, fail)
		}
		missing, callErr := session.CallTool(ctx, &mcp.CallToolParams{Name: prefix + "not_selected", Arguments: map[string]any{}})
		if callErr == nil || missing != nil {
			t.Fatal("unknown remote tool was not denied locally")
		}
		if scenario == "connected-active-cancel" {
			remoteMCPConnectedCancelWait(t, ctx, session, waitTool, waitAck, phases)
		}
	}
	phases.Mark("bridge close attempted")
	if err := session.Close(); err != nil {
		t.Fatal("connected bridge session cleanup did not join")
	}
	closed = true
	phases.Mark("bridge closed")
	if scenario != "connected-empty" {
		remoteMCPConnectedCapabilityNegativeControl(t, ctx, encodedChannels, nil)
	}
	fmt.Fprintln(os.Stderr, remoteMCPConnectedHarnessMarker+scenario)
}

// The parent supplies an absolute base in its t.TempDir to the harness only.
// The upstream wait handler creates base+.started as an empty regular file
// on entry. The marker must be absent before the fixture runs.
func remoteMCPConnectedCancelWait(t *testing.T, ctx context.Context, session *mcp.ClientSession, tool, base string, phases *childdiag.Phases) {
	t.Helper()
	// Stay below the channel's 20s operation budget so its timeout cannot
	// provide cancellation evidence in place of the explicit cancel below.
	watchdog, stopWatchdog := context.WithTimeout(context.Background(), 10*time.Second)
	defer stopWatchdog()
	probeMarker := func(path string) (string, bool, error) {
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			return "marker absent", false, nil
		}
		if err != nil || !info.Mode().IsRegular() || info.Size() != 0 {
			return "marker probe failed", true, errors.New("wait ACK marker unreadable or invalid")
		}
		return "marker present", true, nil
	}

	callCtx, cancelCall := context.WithCancel(ctx)
	type callOutcome struct{ canceled, early bool }
	result := make(chan callOutcome, 1)
	pending := true
	defer func() {
		cancelCall()
		if pending {
			drain := time.NewTimer(2 * time.Second)
			defer drain.Stop()
			select {
			case <-result:
				phases.Mark("wait call drained during cleanup")
			case <-drain.C:
				phases.Mark("wait call cleanup drain expired")
			}
		}
	}()
	phases.Mark("wait call launched")
	go func() {
		_, err := session.CallTool(callCtx, &mcp.CallToolParams{Name: tool, Arguments: map[string]any{}})
		early := callCtx.Err() == nil
		result <- callOutcome{canceled: errors.Is(err, context.Canceled), early: early}
	}()
	watchdogDeadline, _ := watchdog.Deadline()
	watchdogSpent := func() bool {
		return watchdog.Err() != nil || !time.Now().Before(watchdogDeadline) || ctx.Err() != nil
	}
	done, lastState, probeErr := flakediag.WaitForDesc(t, "connected wait dispatch ACK", childdiag.DeadlineOf(watchdog), func() (string, bool, error) {
		select {
		case <-result:
			pending = false
			return "wait call returned early", true, nil
		default:
		}
		if watchdogSpent() {
			return "wait dispatch deadline reached", true, nil
		}
		return probeMarker(base + ".started")
	})
	phases.Mark("wait dispatch: " + lastState)
	if probeErr != nil {
		t.Fatal("connected wait started marker probe failed")
	}
	// Check again after the marker probe, immediately before explicit cancel.
	select {
	case <-result:
		pending = false
	default:
	}
	if !pending {
		t.Fatal("connected wait call returned before explicit cancellation")
	}
	if !done || lastState != "marker present" || watchdogSpent() || callCtx.Err() != nil {
		t.Fatal("connected wait dispatch ACK deadline expired")
	}
	cancelCall()
	phases.Mark("wait call explicitly canceled")
	select {
	case outcome := <-result:
		pending = false
		if watchdogSpent() {
			t.Fatal("connected wait call return deadline expired")
		}
		if outcome.early {
			t.Fatal("connected wait call returned before explicit cancellation")
		}
		if !outcome.canceled {
			t.Fatal("connected wait call did not return context.Canceled")
		}
	case <-watchdog.Done():
		t.Fatal("connected wait call return deadline expired")
	case <-ctx.Done():
		t.Fatal("connected wait call return deadline expired")
	}
	// This confirms local cancellation only. Broker dispatch uses its server
	// context; the parent checks upstream handler completion after child exit.
	phases.Mark("wait call returned context.Canceled")
}

func remoteMCPConnectedList(ctx context.Context, t *testing.T, session *mcp.ClientSession, wantRemote bool) []*mcp.Tool {
	t.Helper()
	deadline, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var tools []*mcp.Tool
	done, _, listErr := flakediag.WaitForDesc(t, "connected harness tool registration state", childdiag.DeadlineOf(deadline), func() (string, bool, error) {
		listing, err := session.ListTools(deadline, nil)
		if err != nil {
			return "tools/list failed", false, errors.New("tools/list RPC failed")
		}
		if listing == nil {
			return "tools/list returned nil result", false, nil
		}
		if len(listing.Tools) <= 72 {
			remote := 0
			for _, tool := range listing.Tools {
				if tool != nil && strings.HasPrefix(tool.Name, "mcp") {
					remote++
				}
			}
			if wantRemote && remote == 3 || !wantRemote && remote == 0 {
				tools = listing.Tools
				return "", true, nil
			}
			return fmt.Sprintf("remote tools=%d total=%d", remote, len(listing.Tools)), false, nil
		}
		return fmt.Sprintf("total tools=%d", len(listing.Tools)), false, nil
	})
	if listErr != nil {
		t.Fatal("connected harness tool listing failed")
	}
	if !done {
		t.Fatal("bounded tool listing did not reach the expected registration state")
	}
	return tools
}

func remoteMCPConnectedTool(names []string, suffix string) string {
	for _, name := range names {
		if strings.HasSuffix(name, "_"+suffix) {
			return name
		}
	}
	return ""
}

func remoteMCPConnectedCall(t *testing.T, ctx context.Context, session *mcp.ClientSession, name string, wantError, bypass bool, capability string) {
	t.Helper()
	if name == "" {
		t.Fatal("selected synthetic tool is missing")
	}
	arguments := map[string]any{}
	if capability != "" {
		arguments["capability"] = capability
	}
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: arguments})
	if err != nil || result == nil || len(result.Content) != 1 || result.StructuredContent == nil || result.IsError != wantError {
		t.Fatal("actual connected tool call omitted its structured or error result")
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal("connected result could not be inspected")
	}
	joined := []byte("synthetic-mcp-owner:synthetic startup Basic credential")
	basicEncoded := []byte(base64.StdEncoding.EncodeToString(joined))
	if capability != "" {
		channelToken, keeperToken, ok := strings.Cut(capability, "|")
		structured, structuredOK := result.StructuredContent.(map[string]any)
		text, textOK := result.Content[0].(*mcp.TextContent)
		if !ok || channelToken == "" || keeperToken == "" || !structuredOK || !textOK || text == nil || structured["capability"] != outputguard.Marker+"|"+outputguard.Marker || !strings.HasSuffix(text.Text, "|"+outputguard.Marker+"|"+outputguard.Marker) || strings.Contains(string(encoded), channelToken) || strings.Contains(string(encoded), keeperToken) {
			t.Fatal("actual connected result did not guard both local capabilities")
		}
	}
	if !bypass {
		for _, secret := range [][]byte{[]byte("synthetic startup Basic credential"), []byte("Basic " + string(basicEncoded)), basicEncoded, []byte("synthetic MCP custom header")} {
			if strings.Contains(string(encoded), string(secret)) {
				t.Fatal("actual MCP result exposed a captured credential")
			}
		}
	}
	if bypass {
		structured, ok := result.StructuredContent.(map[string]any)
		text, textOK := result.Content[0].(*mcp.TextContent)
		if !ok || !textOK || text == nil || !strings.Contains(text.Text, "synthetic SSH account password") || !strings.Contains(text.Text, "synthetic-unselected-account-secret") || structured["owner"] != "synthetic SSH account password" || structured["known"] != "synthetic-unselected-account-secret" {
			t.Fatal("explicit bypass did not preserve known owner literals")
		}
	} else {
		structured, ok := result.StructuredContent.(map[string]any)
		text, textOK := result.Content[0].(*mcp.TextContent)
		if !ok || !textOK || text == nil || !strings.Contains(text.Text, "[REDACTED]") || structured["owner"] != "[REDACTED]" || structured["known"] != "[REDACTED]" || structured["raw"] != "[REDACTED]" || structured["authorization"] != "[REDACTED]" || structured["encoded"] != "[REDACTED]" || structured["custom"] != "[REDACTED]" {
			t.Fatal("connected text or structured output was not faithfully guarded")
		}
	}
	if !strings.Contains(string(encoded), `"n":7`) {
		t.Fatal("connected structured output was not faithfully preserved")
	}
}

func remoteMCPConnectedRPCFailure(t *testing.T, ctx context.Context, session *mcp.ClientSession, name string) {
	t.Helper()
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: map[string]any{"rpc": true}})
	if err != nil || result == nil || !result.IsError || result.StructuredContent != nil || len(result.Content) != 1 {
		t.Fatal("private RPC failure did not become a fixed tool result")
	}
	text, ok := result.Content[0].(*mcp.TextContent)
	if !ok || text.Text != "remote MCP tool call failed" {
		t.Fatal("private RPC failure text was not fixed under bypass")
	}
}

type remoteMCPReconnectConnector func(context.Context, mcpchannel.Descriptor, context.CancelFunc) (func(), bool, error)

// This is the shared attempt used by the connected capability control and its
// seam-driven regression. Only the connector varies; admission and evidence do not.
func remoteMCPReconnectAttempt(caller context.Context, encoded string, connect remoteMCPReconnectConnector) bool {
	attempt, cancel := context.WithTimeout(context.Background(), remoteMCPReconnectAttemptBudget)
	defer cancel()
	descriptor, ok := remoteMCPReconnectPreflight(caller, attempt, encoded, time.Now())
	if !ok {
		return false
	}
	callerBeforeErr, attemptBeforeErr := caller.Err(), attempt.Err()
	started := time.Now()
	encodedBefore := encoded
	closeClient, returned, connectErr := connect(attempt, descriptor, cancel)
	ended := time.Now()
	attemptDeadline, _ := attempt.Deadline()
	evidence := remoteMCPReconnectEvidence{
		caller: caller, callerBeforeErr: callerBeforeErr, callerAfterErr: caller.Err(),
		attempt: attempt, attemptBeforeErr: attemptBeforeErr, attemptAfterErr: attempt.Err(),
		attemptDeadline: attemptDeadline, encodedBefore: encodedBefore,
		encodedAfter: encoded, started: started, ended: ended, duration: ended.Sub(started),
		connectErr: connectErr, clientReturned: returned,
	}
	admitted := remoteMCPReconnectEvidenceAdmitted(evidence)
	cancel()
	if closeClient != nil {
		closeClient()
	}
	return admitted
}

func TestRemoteMCPReconnectSharedAttempt(t *testing.T) {
	encoded := remoteMCPReconnectTestDescriptor(t, time.Now(), 30*time.Second)
	descriptor, ok := remoteMCPReconnectDecode(encoded)
	if !ok {
		t.Fatal("test descriptor was invalid")
	}
	assertRefusedWithoutConnect := func(name, channels string, caller context.Context) {
		t.Run(name, func(t *testing.T) {
			called := false
			admitted := remoteMCPReconnectAttempt(caller, channels, func(context.Context, mcpchannel.Descriptor, context.CancelFunc) (func(), bool, error) {
				called = true
				return nil, false, errors.New("synthetic connection failure")
			})
			if called || admitted {
				t.Fatal("spent caller reached connector or earned refusal evidence")
			}
		})
	}
	assertRefusedWithoutConnect("caller already canceled", encoded, canceledRemoteMCPReconnectContext())
	assertRefusedWithoutConnect("nil caller", encoded, nil)
	spentDeadline, cancelSpentDeadline := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancelSpentDeadline()
	assertRefusedWithoutConnect("caller with spent deadline", encoded, spentDeadline)
	assertRefusedWithoutConnect("invalid descriptor", "not-a-descriptor", context.Background())

	t.Run("live bounded exact descriptor invokes connector", func(t *testing.T) {
		caller := context.Background()
		called := false
		admitted := remoteMCPReconnectAttempt(caller, encoded, func(attempt context.Context, got mcpchannel.Descriptor, _ context.CancelFunc) (func(), bool, error) {
			called = true
			deadline, bounded := attempt.Deadline()
			if attempt == caller || attempt.Err() != nil || !bounded || !deadline.After(time.Now()) || deadline.Sub(time.Now()) > remoteMCPReconnectAttemptBudget || got != descriptor {
				t.Fatal("connector did not receive the exact descriptor and independent bounded context")
			}
			return nil, false, errors.New("synthetic broker refusal")
		})
		if !called || !admitted {
			t.Fatal("live connector refusal was not admitted as bounded evidence")
		}
	})

	for _, test := range []struct {
		name     string
		cancel   string
		returned bool
		err      error
	}{
		{name: "caller canceled during connect", cancel: "caller", err: errors.New("synthetic refusal")},
		{name: "attempt canceled during connect", cancel: "attempt", err: errors.New("synthetic refusal")},
		{name: "successful client", returned: true},
		{name: "unexpected client with error", returned: true, err: errors.New("synthetic refusal")},
		{name: "live caller with canceled error", err: context.Canceled},
		{name: "live caller with deadline error", err: context.DeadlineExceeded},
	} {
		t.Run(test.name, func(t *testing.T) {
			caller, cancelCaller := context.WithCancel(context.Background())
			defer cancelCaller()
			called, cleaned, callerCancellationIsolated := false, 0, false
			admitted := remoteMCPReconnectAttempt(caller, encoded, func(attempt context.Context, _ mcpchannel.Descriptor, cancelAttempt context.CancelFunc) (func(), bool, error) {
				called = true
				if test.cancel == "caller" {
					cancelCaller()
					callerCancellationIsolated = attempt.Err() == nil
				}
				if test.cancel == "attempt" {
					cancelAttempt()
				}
				return func() { cleaned++ }, test.returned, test.err
			})
			if !called || admitted || cleaned != 1 || test.cancel == "caller" && !callerCancellationIsolated {
				t.Fatal("spent context or client result was credited as refusal, or cleanup was skipped")
			}
		})
	}
}

const (
	remoteMCPReconnectAttemptBudget = 8 * time.Second
	remoteMCPReconnectBrokerTimeout = 5 * time.Second
	remoteMCPReconnectLeaseMargin   = 14 * time.Second
	remoteMCPReconnectPostMargin    = 9 * time.Second
)

type remoteMCPReconnectEvidence struct {
	caller           context.Context
	callerCancel     context.CancelFunc
	callerBeforeErr  error
	callerAfterErr   error
	attempt          context.Context
	attemptCancel    context.CancelFunc
	attemptBeforeErr error
	attemptAfterErr  error
	attemptDeadline  time.Time
	encodedBefore    string
	encodedAfter     string
	started          time.Time
	ended            time.Time
	duration         time.Duration
	connectErr       error
	clientReturned   bool
}

func remoteMCPReconnectDecode(encoded string) (mcpchannel.Descriptor, bool) {
	descriptors, err := mcpchannel.DecodeDescriptors(encoded)
	if err != nil || len(descriptors) != 1 {
		return mcpchannel.Descriptor{}, false
	}
	canonical, err := mcpchannel.EncodeDescriptors(descriptors)
	if err != nil || canonical != encoded {
		return mcpchannel.Descriptor{}, false
	}
	return descriptors[0], true
}

func remoteMCPReconnectPreflight(caller, attempt context.Context, encoded string, now time.Time) (mcpchannel.Descriptor, bool) {
	if caller == nil || caller.Err() != nil || attempt == nil || attempt.Err() != nil {
		return mcpchannel.Descriptor{}, false
	}
	deadline, ok := attempt.Deadline()
	if !ok || !deadline.After(now) || deadline.Sub(now) > remoteMCPReconnectAttemptBudget {
		return mcpchannel.Descriptor{}, false
	}
	descriptor, ok := remoteMCPReconnectDecode(encoded)
	if !ok || time.Unix(descriptor.ExpiresUnix, 0).Sub(now) < remoteMCPReconnectLeaseMargin {
		return mcpchannel.Descriptor{}, false
	}
	return descriptor, true
}

// The five-second cutoff is conservative refusal of evidence, not attribution of ErrClient to a particular broker or OS failure.
func remoteMCPReconnectEvidenceAdmitted(e remoteMCPReconnectEvidence) bool {
	if e.caller == nil || e.callerBeforeErr != nil || e.callerAfterErr != nil || e.caller.Err() != nil ||
		e.attempt == nil || e.attemptBeforeErr != nil || e.attemptAfterErr != nil || e.attempt.Err() != nil ||
		e.connectErr == nil || errors.Is(e.connectErr, context.Canceled) || errors.Is(e.connectErr, context.DeadlineExceeded) || e.clientReturned || e.duration < 0 || e.duration >= remoteMCPReconnectBrokerTimeout ||
		e.ended.Before(e.started) || e.ended.Sub(e.started) != e.duration {
		return false
	}
	deadline, ok := e.attempt.Deadline()
	if !ok || !deadline.Equal(e.attemptDeadline) || !deadline.After(e.started) || deadline.Sub(e.started) > remoteMCPReconnectAttemptBudget {
		return false
	}
	before, beforeOK := remoteMCPReconnectDecode(e.encodedBefore)
	after, afterOK := remoteMCPReconnectDecode(e.encodedAfter)
	if !beforeOK || !afterOK || e.encodedBefore != e.encodedAfter || before != after {
		return false
	}
	expires := time.Unix(before.ExpiresUnix, 0)
	return expires.Sub(e.started) >= remoteMCPReconnectLeaseMargin && expires.Sub(e.ended) > remoteMCPReconnectPostMargin
}

func TestRemoteMCPReconnectEvidenceAdmission(t *testing.T) {
	cases := []struct {
		name string
		edit func(*testing.T, *remoteMCPReconnectEvidence)
		want bool
	}{
		{name: "live bounded quick error", want: true},
		{name: "exact lease margin", edit: func(t *testing.T, e *remoteMCPReconnectEvidence) {
			e.encodedBefore = remoteMCPReconnectTestDescriptor(t, e.started, 14*time.Second)
			e.encodedAfter = e.encodedBefore
		}, want: true},
		{name: "just under broker timeout", edit: func(t *testing.T, e *remoteMCPReconnectEvidence) {
			e.duration = remoteMCPReconnectBrokerTimeout - time.Nanosecond
			e.ended = e.started.Add(e.duration)
			e.encodedBefore = remoteMCPReconnectTestDescriptor(t, e.started, 16*time.Second)
			e.encodedAfter = e.encodedBefore
		}, want: true},
		{name: "exact post margin overlaps lease margin", edit: func(t *testing.T, e *remoteMCPReconnectEvidence) {
			e.encodedBefore = remoteMCPReconnectTestDescriptor(t, e.started, 10*time.Second)
			e.encodedAfter = e.encodedBefore
		}},
		{name: "lease below margin", edit: func(t *testing.T, e *remoteMCPReconnectEvidence) {
			e.encodedBefore = remoteMCPReconnectTestDescriptor(t, e.started, 13*time.Second)
			e.encodedAfter = e.encodedBefore
		}},
		{name: "expired descriptor", edit: func(t *testing.T, e *remoteMCPReconnectEvidence) {
			e.encodedBefore = remoteMCPReconnectTestDescriptor(t, e.started, -2*time.Minute)
			e.encodedAfter = e.encodedBefore
		}},
		{name: "invalid descriptor after", edit: func(_ *testing.T, e *remoteMCPReconnectEvidence) { e.encodedAfter = "not-a-descriptor" }},
		{name: "changed descriptor", edit: func(t *testing.T, e *remoteMCPReconnectEvidence) {
			e.encodedAfter = remoteMCPReconnectTestDescriptorWithToken(t, e.started, 30*time.Second, "4")
		}},
		{name: "changed encoding", edit: func(_ *testing.T, e *remoteMCPReconnectEvidence) { e.encodedAfter += " " }},
		{name: "successful result without client", edit: func(_ *testing.T, e *remoteMCPReconnectEvidence) { e.connectErr = nil }},
		{name: "unexpected client with error", edit: func(_ *testing.T, e *remoteMCPReconnectEvidence) { e.clientReturned = true }},
		{name: "connect returned canceled", edit: func(_ *testing.T, e *remoteMCPReconnectEvidence) {
			e.connectErr = errors.Join(context.Canceled, errors.New("synthetic detail"))
		}},
		{name: "connect returned deadline exceeded", edit: func(_ *testing.T, e *remoteMCPReconnectEvidence) {
			e.connectErr = errors.Join(context.DeadlineExceeded, errors.New("synthetic detail"))
		}},
		{name: "duration reaches broker timeout", edit: func(_ *testing.T, e *remoteMCPReconnectEvidence) {
			e.duration = remoteMCPReconnectBrokerTimeout
			e.ended = e.started.Add(e.duration)
		}},
		{name: "inconsistent duration", edit: func(_ *testing.T, e *remoteMCPReconnectEvidence) { e.duration++ }},
		{name: "nil caller", edit: func(_ *testing.T, e *remoteMCPReconnectEvidence) { e.caller = nil }},
		{name: "caller spent before attempt", edit: func(_ *testing.T, e *remoteMCPReconnectEvidence) { e.callerBeforeErr = context.Canceled }},
		{name: "caller spent after attempt", edit: func(_ *testing.T, e *remoteMCPReconnectEvidence) { e.callerAfterErr = context.Canceled }},
		{name: "caller canceled", edit: func(t *testing.T, e *remoteMCPReconnectEvidence) {
			e.callerBeforeErr = context.Canceled
			e.callerAfterErr = context.Canceled
			e.callerCancel()
		}},
		{name: "nil attempt", edit: func(_ *testing.T, e *remoteMCPReconnectEvidence) { e.attempt = nil }},
		{name: "attempt spent before connect", edit: func(_ *testing.T, e *remoteMCPReconnectEvidence) { e.attemptBeforeErr = context.Canceled }},
		{name: "attempt spent after connect", edit: func(_ *testing.T, e *remoteMCPReconnectEvidence) { e.attemptAfterErr = context.Canceled }},
		{name: "attempt canceled", edit: func(t *testing.T, e *remoteMCPReconnectEvidence) {
			e.attemptBeforeErr = context.Canceled
			e.attemptAfterErr = context.Canceled
			e.attemptCancel()
		}},
		{name: "attempt missing deadline", edit: func(_ *testing.T, e *remoteMCPReconnectEvidence) {
			e.attempt = context.Background()
			e.attemptDeadline = time.Time{}
		}},
		{name: "attempt deadline beyond budget", edit: func(t *testing.T, e *remoteMCPReconnectEvidence) {
			e.attempt, e.attemptCancel, e.attemptDeadline = remoteMCPReconnectTestAttempt(t, e.started.Add(remoteMCPReconnectAttemptBudget+time.Nanosecond))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := remoteMCPReconnectTestEvidence(t, 30*time.Second, time.Second)
			if tc.edit != nil {
				tc.edit(t, &e)
			}
			if got := remoteMCPReconnectEvidenceAdmitted(e); got != tc.want {
				t.Fatal("reconnect evidence admission boundary was incorrect")
			}
		})
	}
}

func TestRemoteMCPReconnectPreflightAdmission(t *testing.T) {
	now := time.Unix(time.Now().Add(time.Minute).Unix(), 0)
	caller, cancelCaller := context.WithCancel(context.Background())
	defer cancelCaller()
	attempt, cancelAttempt := context.WithDeadline(context.Background(), now.Add(remoteMCPReconnectAttemptBudget))
	defer cancelAttempt()
	encoded := remoteMCPReconnectTestDescriptor(t, now, 30*time.Second)
	cases := []struct {
		name    string
		caller  context.Context
		attempt context.Context
		encoded string
		want    bool
	}{
		{name: "live", caller: caller, attempt: attempt, encoded: encoded, want: true},
		{name: "deadline equals preflight time", caller: caller, attempt: func() context.Context {
			c, stop := context.WithDeadline(context.Background(), now)
			t.Cleanup(stop)
			return c
		}(), encoded: encoded},
		{name: "expired attempt deadline", caller: caller, attempt: func() context.Context {
			c, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
			t.Cleanup(stop)
			return c
		}(), encoded: encoded},
		{name: "attempt deadline over budget", caller: caller, attempt: func() context.Context {
			c, stop := context.WithDeadline(context.Background(), now.Add(remoteMCPReconnectAttemptBudget+time.Nanosecond))
			t.Cleanup(stop)
			return c
		}(), encoded: encoded},
		{name: "nil caller", attempt: attempt, encoded: encoded},
		{name: "canceled caller", caller: canceledRemoteMCPReconnectContext(), attempt: attempt, encoded: encoded},
		{name: "nil attempt", caller: caller, encoded: encoded},
		{name: "canceled attempt", caller: caller, attempt: canceledRemoteMCPReconnectContext(), encoded: encoded},
		{name: "no attempt deadline", caller: caller, attempt: context.Background(), encoded: encoded},
		{name: "near expiry", caller: caller, attempt: attempt, encoded: remoteMCPReconnectTestDescriptor(t, now, 13*time.Second)},
		{name: "one descriptor required", caller: caller, attempt: attempt, encoded: remoteMCPReconnectMultipleTestDescriptors(t, now)},
		{name: "invalid descriptor", caller: caller, attempt: attempt, encoded: "not-a-descriptor"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, got := remoteMCPReconnectPreflight(tc.caller, tc.attempt, tc.encoded, now)
			if got != tc.want {
				t.Fatal("reconnect preflight admission boundary was incorrect")
			}
		})
	}
}

func canceledRemoteMCPReconnectContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func remoteMCPReconnectTestEvidence(t *testing.T, lease, duration time.Duration) remoteMCPReconnectEvidence {
	t.Helper()
	started := time.Unix(time.Now().Add(time.Minute).Unix(), 0)
	caller, cancelCaller := context.WithCancel(context.Background())
	t.Cleanup(cancelCaller)
	attempt, cancelAttempt, deadline := remoteMCPReconnectTestAttempt(t, started.Add(remoteMCPReconnectAttemptBudget))
	encoded := remoteMCPReconnectTestDescriptor(t, started, lease)
	return remoteMCPReconnectEvidence{caller: caller, callerCancel: cancelCaller, attempt: attempt, attemptCancel: cancelAttempt, attemptDeadline: deadline, callerBeforeErr: caller.Err(), callerAfterErr: caller.Err(), attemptBeforeErr: attempt.Err(), attemptAfterErr: attempt.Err(), encodedBefore: encoded, encodedAfter: encoded, started: started, ended: started.Add(duration), duration: duration, connectErr: errors.New("synthetic bounded failure")}
}

func remoteMCPReconnectTestAttempt(t *testing.T, deadline time.Time) (context.Context, context.CancelFunc, time.Time) {
	t.Helper()
	attempt, cancel := context.WithDeadline(context.Background(), deadline)
	t.Cleanup(cancel)
	actual, _ := attempt.Deadline()
	return attempt, cancel, actual
}

func remoteMCPReconnectTestDescriptor(t *testing.T, started time.Time, lease time.Duration) string {
	return remoteMCPReconnectTestDescriptorWithToken(t, started, lease, "3")
}

func remoteMCPReconnectMultipleTestDescriptors(t *testing.T, started time.Time) string {
	t.Helper()
	one := remoteMCPReconnectTestDescriptorWithToken(t, started, 30*time.Second, "3")
	var descriptors []mcpchannel.Descriptor
	if err := json.Unmarshal([]byte(one), &descriptors); err != nil {
		t.Fatal("test descriptor could not be decoded")
	}
	two := descriptors[0]
	two.Ordinal = 1
	two.Endpoint = "127.0.0.1:47822"
	two.Session = strings.Repeat("5", 64)
	two.Pin = strings.Repeat("6", 64)
	two.Token = strings.Repeat("4", 64)
	encoded, err := json.Marshal(append(descriptors, two))
	if err != nil {
		t.Fatal("multiple test descriptors could not be encoded")
	}
	return string(encoded)
}

func remoteMCPReconnectTestDescriptorWithToken(t *testing.T, started time.Time, lease time.Duration, token string) string {
	t.Helper()
	descriptor := mcpchannel.Descriptor{Version: mcpchannel.VersionRemoteMCP, Ordinal: 0, Session: strings.Repeat("1", 64), Endpoint: "127.0.0.1:47821", Pin: strings.Repeat("2", 64), Token: strings.Repeat(token, 64), ExpiresUnix: started.Unix() + int64(lease/time.Second)}
	encoded, err := mcpchannel.EncodeDescriptors([]mcpchannel.Descriptor{descriptor})
	if err != nil {
		data, marshalErr := json.Marshal([]mcpchannel.Descriptor{descriptor})
		if marshalErr != nil {
			t.Fatal("test descriptor could not be encoded")
		}
		encoded = string(data)
	}
	return encoded
}

func TestRemoteMCPConnectedWaitLifetime(t *testing.T) {
	for _, source := range []string{"request", "tool", "shutdown"} {
		t.Run(source, func(t *testing.T) {
			fixture := &remoteMCPConnectedServer{waitStarted: make(chan struct{}), waitFinish: make(chan struct{})}
			fixture.initLifetime()
			toolCtx, cancelTool := context.WithCancel(context.Background())
			requestCtx, cancelRequest := context.WithCancel(context.Background())
			done := make(chan struct{})
			t.Cleanup(func() {
				cancelTool()
				cancelRequest()
				fixture.closeAdmission()
				cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				for _, signal := range []<-chan struct{}{done, fixture.activeDone} {
					select {
					case <-signal:
					case <-cleanup.Done():
						t.Error("connected fixture wait cleanup did not join")
					}
				}
			})
			if !fixture.beginWork() {
				t.Fatal("fresh fixture refused wait worker")
			}
			go func() {
				defer close(done)
				defer fixture.endWork()
				_, _ = fixture.wait(toolCtx, requestCtx)
			}()
			operation, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			select {
			case <-fixture.waitStarted:
			case <-operation.Done():
				t.Fatal("wait worker did not start")
			}
			select {
			case <-fixture.waitFinish:
				t.Fatal("live wait finished before cancellation")
			default:
			}
			switch source {
			case "request":
				cancelRequest()
			case "tool":
				cancelTool()
			case "shutdown":
				fixture.closeAdmission()
			}
			select {
			case <-done:
			case <-operation.Done():
				t.Fatal("wait worker did not finish after cancellation")
			}
			select {
			case <-fixture.waitFinish:
			default:
				t.Fatal("wait completion omitted its handler barrier")
			}
			wantDone := int32(1)
			if source == "shutdown" {
				wantDone = 0
			}
			if fixture.calls.Load() != 1 || fixture.waitCalls.Load() != 1 || fixture.waitDone.Load() != wantDone {
				t.Fatal("wait replayed or fixture shutdown became cancellation evidence")
			}
			if source != "tool" && toolCtx.Err() != nil || source != "request" && requestCtx.Err() != nil {
				t.Fatal("cancellation crossed an independent context owner")
			}
		})
	}
}

func TestRemoteMCPConnectedRequestHandlerLifetime(t *testing.T) {
	fixture := &remoteMCPConnectedServer{waitStarted: make(chan struct{}), waitFinish: make(chan struct{})}
	fixture.initLifetime()
	requestOwner, cancelRequestOwner := context.WithCancel(context.Background())
	transportCtx, cancelTransport := context.WithCancel(context.Background())
	done := make(chan struct{})
	t.Cleanup(func() {
		fixture.closeAdmission()
		cancelRequestOwner()
		cancelTransport()
		cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		for _, signal := range []<-chan struct{}{done, fixture.activeDone} {
			select {
			case <-signal:
			case <-cleanup.Done():
				t.Error("connected request handler cleanup did not join")
			}
		}
	})
	if !fixture.beginWork() {
		t.Fatal("fresh fixture refused HTTP handler worker")
	}

	// Keep the transport live so only the captured request owner can release
	// the tool; SDK transport-context cancellation must not satisfy this oracle.
	request := httptest.NewRequest(http.MethodPost, "https://coordinator.invalid/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"wait","arguments":{}}}`)).WithContext(transportCtx)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	request.Header.Set("Mcp-Protocol-Version", "2025-06-18")
	response := httptest.NewRecorder()
	handler := fixture.handlerForRequest(requestOwner)
	go func() {
		defer close(done)
		defer fixture.endWork()
		handler.ServeHTTP(response, request)
	}()

	operation, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	select {
	case <-fixture.waitStarted:
	case <-operation.Done():
		t.Fatal("SDK HTTP handler did not start wait tool")
	}
	if requestOwner.Err() != nil || transportCtx.Err() != nil {
		t.Fatal("request contexts ended before request-owner cancellation")
	}
	select {
	case <-fixture.waitFinish:
		t.Fatal("SDK HTTP wait finished before request-owner cancellation")
	default:
	}
	cancelRequestOwner()
	select {
	case <-done:
	case <-operation.Done():
		t.Fatal("SDK HTTP handler did not finish after captured request-owner cancellation")
	}
	select {
	case <-fixture.waitFinish:
	default:
		t.Fatal("wait completion omitted its handler barrier")
	}
	if fixture.calls.Load() != 1 || fixture.waitCalls.Load() != 1 || fixture.waitDone.Load() != 1 {
		t.Fatal("SDK HTTP handler replayed wait or omitted cancellation evidence")
	}
	if transportCtx.Err() != nil {
		t.Fatal("captured request-owner cancellation crossed into the live HTTP transport")
	}
}

func TestRemoteMCPConnectedWorkAdmission(t *testing.T) {
	fixture := &remoteMCPConnectedServer{}
	fixture.initLifetime()
	if !fixture.beginWork() {
		t.Fatal("fresh fixture refused work")
	}
	fixture.closeAdmission()
	fixture.closeAdmission()
	select {
	case <-fixture.activeDone:
		t.Fatal("fixture joined before admitted worker finished")
	default:
	}
	if fixture.beginWork() {
		t.Fatal("closing fixture admitted new work")
	}
	fixture.endWork()
	select {
	case <-fixture.activeDone:
	default:
		t.Fatal("fixture did not join its last worker")
	}
}
