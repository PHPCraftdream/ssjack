// Package agent owns the CLI agent session credentials: the private runtime
// state (runner, stream, SSH admission, remote MCP launch/bridge/channels),
// the credential loader, the ordered shutdown sequence, and the manager/guard
// construction used by the full-mode session composition.
package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"sync"
	"time"

	tea "charm.land/bubbletea/v2"
	"golang.org/x/term"

	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/credential"
	"github.com/PHPCraftdream/ssjack/internal/mcpbridge"
	"github.com/PHPCraftdream/ssjack/internal/mcpchannel"
	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
	"github.com/PHPCraftdream/ssjack/internal/mcpgrant"
	"github.com/PHPCraftdream/ssjack/internal/mcpjson"
	"github.com/PHPCraftdream/ssjack/internal/mcpselect"
	"github.com/PHPCraftdream/ssjack/internal/outputguard"
	"github.com/PHPCraftdream/ssjack/internal/ownerdb"
	"github.com/PHPCraftdream/ssjack/internal/ownerservice"
	"github.com/PHPCraftdream/ssjack/internal/ownerssh"
	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/sshlive"
	"github.com/PHPCraftdream/ssjack/internal/vault"
	"github.com/PHPCraftdream/ssjack/internal/wire"
)

// OwnerSession is the owner database handle adopted for the session.
type OwnerSession interface {
	Close(context.Context) error
}

// OwnerService is the started owner service lifecycle.
type OwnerService interface {
	Close(context.Context) error
	Done() <-chan struct{}
}

// Credentials holds the private per-session agent state. While a bridge
// runtime is active, launch cleanup ownership is exercised through the
// bridge's close callback; mcpLaunch stays set only so the merged output
// guard keeps resolving.
type Credentials struct {
	runner        remote.Runner
	guard         remote.GuardProvider
	stream        remote.StreamRunner
	targets       []string
	owner         OwnerSession
	service       OwnerService
	capture       *mcpgrant.Capture
	mcpBridge     *mcpbridge.Runtime
	mcpLaunch     *mcpgrant.Launch
	mcpLaunchUsed bool
	channels      *mcpchannel.ChannelSet
	ssh           *sshlive.Runtime
}

// NewOwnerCredentials returns credentials owning exactly the given owner
// session. Partial-start semantics are preserved: the loader keeps mutating
// the returned value and may return it together with an error; Finish still
// closes everything acquired so far.
func NewOwnerCredentials(owner OwnerSession) *Credentials {
	return &Credentials{owner: owner}
}

// ApplicationApprovals returns owner application approval records from the
// unlocked directory database. Other owner sessions have no approvals.
func (credentials *Credentials) ApplicationApprovals() ([]vault.Approval, error) {
	manager, ok := credentials.owner.(*ownerdb.Manager)
	if !ok {
		return nil, nil
	}
	metadata, err := manager.Metadata()
	if err != nil {
		return nil, err
	}
	return metadata.Approvals, nil
}

// SetService records the started owner service for the text owner path.
func (credentials *Credentials) SetService(service OwnerService) { credentials.service = service }

// Guard returns the session output guard provider.
func (credentials *Credentials) Guard() remote.GuardProvider {
	return credentials.guard
}

// Targets returns the selected credential targets.
func (credentials *Credentials) Targets() []string {
	return credentials.targets
}

// Stream returns the stream runner used by application and transfer managers.
func (credentials *Credentials) Stream() remote.StreamRunner {
	return credentials.stream
}

// BridgeRuntime exposes the active remote MCP bridge runtime for bootstrap
// output preparation.
func (credentials *Credentials) Bridge() *mcpbridge.Runtime {
	return credentials.mcpBridge
}

// withMCPLaunch grants one-shot access to the owned launch.
func (credentials *Credentials) withMCPLaunch(use func(*mcpgrant.Launch) error) error {
	if credentials == nil || use == nil || credentials.mcpLaunch == nil || credentials.mcpLaunchUsed {
		return errors.New("remote MCP launch is unavailable")
	}
	credentials.mcpLaunchUsed = true
	return use(credentials.mcpLaunch)
}

// FixedOutputGuard resolves to the snapshot while the context is live.
func FixedOutputGuard(snapshot *outputguard.Snapshot) remote.GuardProvider {
	return func(ctx context.Context) (*outputguard.Snapshot, error) {
		if snapshot == nil || ctx == nil || ctx.Err() != nil {
			return nil, outputguard.ErrGuard
		}
		return snapshot, nil
	}
}

// Load opens the vault credential and assembles the agent session state in
// the original package-main ordering: runner, stream, remote MCP selection
// and capture, owner adoption, launch/bridge preparation, merged output
// guard, live SSH admission, owner service, or the legacy guard fallback.
// Partial-start semantics are preserved: a non-nil credentials value may be
// returned together with an error and Finish still closes everything
// acquired so far.
func Load(ctx context.Context, path, name string) (*Credentials, error) {
	v, config, address, selected, err := credential.OpenVaultCredential(ctx, path, name, "agent")
	if err != nil {
		return nil, err
	}
	adopted := false
	defer func() {
		if !adopted {
			v.Close()
		}
	}()
	runner, err := remote.NewCredentialRunner(selected, address, config)
	if err != nil {
		return nil, err
	}
	stream, err := remote.NewCredentialStreamRunner(selected, address, config)
	if err != nil {
		return nil, err
	}
	credentials := &Credentials{runner: runner, stream: stream, targets: []string{selected}, guard: FixedOutputGuard(nil)}
	liveSSH := false
	if v.Version == 2 {
		selectedTarget, exists := v.Targets[selected]
		liveSSH = exists && selectedTarget.Proxy == nil
	}
	if v.Version == 2 {
		var choice mcpselect.Choice
		var capture *mcpgrant.Capture
		var originDigest [32]byte
		if v.RemoteMCP != nil {
			if !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stdout.Fd())) {
				return nil, errors.New("remote MCP selection requires a trusted input and output terminal")
			}
			var readErr error
			originDigest, readErr = credential.CredentialCipherDigest(path)
			if readErr != nil {
				return nil, errors.New("remote MCP selection could not verify the saved database")
			}
			model, modelErr := mcpselect.New(selected, 0, v.RemoteMCP.Metadata())
			if modelErr != nil {
				return nil, errors.New("remote MCP selection metadata is unavailable")
			}
			if _, runErr := tea.NewProgram(model, tea.WithContext(ctx), tea.WithInput(os.Stdin), tea.WithOutput(os.Stdout)).Run(); runErr != nil {
				return nil, errors.New("remote MCP selection stopped before confirmation")
			}
			var confirmed bool
			choice, confirmed = model.Result()
			if !confirmed || choice.Profile != selected || choice.Revision != 0 {
				return nil, errors.New("remote MCP selection cancelled; no database changes were made")
			}
			if len(choice.Bindings) != 0 {
				capture, err = v.RemoteMCPCapture(ctx, path, originDigest, selected, choice.Bindings)
				if err != nil {
					return nil, errors.New("remote MCP capture could not validate the selected saved state")
				}
			}
		}
		hasRemoteMCP := v.RemoteMCP != nil
		credentials.capture = capture
		owner, err := ownerdb.Adopt(ctx, path, v)
		if err != nil {
			return credentials, err
		}
		credentials.owner, adopted = owner, true
		if hasRemoteMCP {
			if err := owner.RememberRemoteMCPAt(ctx, 0, originDigest, selected, choice.Bindings); err != nil {
				return credentials, err
			}
			if err := owner.Flush(ctx); err != nil {
				return credentials, errors.New("remote MCP preference save is pending; inspect owner database persistence")
			}
			metadata, databaseStatus, savedDigest, receiptErr := owner.MetadataSnapshot()
			diskDigest, diskErr := credential.CredentialCipherDigest(path)
			var savedPreference []mcpdirectory.Binding
			preferenceExists := false
			if metadata.RemoteMCP.Last != nil {
				savedPreference, preferenceExists = metadata.RemoteMCP.Last[selected]
			}
			if receiptErr != nil || diskErr != nil || databaseStatus.Err != nil || databaseStatus.Pending || databaseStatus.Revision != 1 || databaseStatus.SavedRevision != 1 || savedDigest == ([32]byte{}) || diskDigest != savedDigest || !preferenceExists || !slices.Equal(savedPreference, choice.Bindings) {
				return credentials, errors.New("remote MCP preference save receipt did not match the expected revision")
			}
			if capture != nil {
				launch, issueErr := capture.Issue(ctx, selected, 0, choice.Bindings)
				if issueErr != nil {
					return credentials, errors.New("remote MCP launch preparation failed")
				}
				credentials.mcpLaunch = launch
				launchGuard, guardErr := launch.Guard()
				if guardErr != nil {
					// A failed guard take consumes the launch; leave it on the
					// credentials so finish still closes it.
					return credentials, errors.New("remote MCP launch preparation failed")
				}
				handles := make([]mcpbridge.UpstreamHandle, 0, len(launch.Upstreams()))
				for _, upstream := range launch.Upstreams() {
					handles = append(handles, &mcpbridge.LaunchUpstream{Upstream: upstream})
				}
				runtime, openErr := mcpbridge.Open(ctx, handles, launchGuard, launch.Close, choice.Bindings)
				if openErr != nil {
					// Open is pure validation; the launch stays owned by the
					// credentials and finish closes it.
					return credentials, errors.New("remote MCP launch preparation failed")
				}
				credentials.mcpBridge = runtime
				credentials.mcpLaunchUsed = true // ownership transferred to the bridge
				fmt.Fprintln(os.Stderr, "Remote MCP bridge is active for this session's selected connections.")
			}
		}
		baseGuard, guardErr := owner.OutputGuard(ctx)
		if guardErr != nil || baseGuard == nil {
			if credentials.mcpLaunch != nil {
				return credentials, errors.New("owner output guard is unavailable")
			}
		} else {
			credentials.guard = func(guardCtx context.Context) (*outputguard.Snapshot, error) {
				ownerGuard, err := owner.OutputGuard(guardCtx)
				if err != nil {
					return nil, outputguard.ErrGuard
				}
				if credentials.mcpLaunch == nil {
					return ownerGuard, nil
				}
				launchGuard, err := credentials.mcpLaunch.Guard()
				if err != nil {
					return nil, outputguard.ErrGuard
				}
				merged, err := outputguard.Union(ownerGuard, launchGuard)
				if err != nil {
					return nil, outputguard.ErrGuard
				}
				return merged, nil
			}
		}
		if liveSSH {
			credentials.ssh, err = ownerssh.Open(ctx, path, selected, owner)
			if err != nil {
				return credentials, ownerssh.ErrUnavailable
			}
			owner.SetSSHStatus(credentials.ssh.Status)
		}
		service, err := ownerservice.Start(ctx, owner)
		if err != nil {
			return credentials, err
		}
		credentials.service = service
	} else {
		snapshot, _ := v.LegacyOutputGuard(ctx, path)
		credentials.guard = FixedOutputGuard(snapshot)
	}
	return credentials, nil
}

var errOwnerShutdown = errors.New("owner session could not close safely; inspect database persistence and pending recovery before retrying")

// ErrOwnerShutdown is reported by Finish whenever any close stage fails.
var ErrOwnerShutdown error = errOwnerShutdown

// Finish closes the owned session state in dependency order: channels,
// bridge (which joins the launch), launch, capture, service, then owner. Any
// failure reports code 1 and ErrOwnerShutdown and leaves the remaining
// stages untouched.
func (credentials *Credentials) Finish(code *int, result *error) {
	if credentials == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	failed := false
	if credentials.channels != nil {
		if credentials.channels.Close(ctx) != nil {
			*code, *result = 1, errOwnerShutdown
			return
		}
		credentials.channels = nil
	}
	if credentials.mcpBridge != nil {
		if credentials.mcpBridge.Close(ctx) != nil {
			*code, *result = 1, errOwnerShutdown
			return
		}
		// Bridge close already joined the SDK sessions and closed the launch;
		// clearing both prevents double close.
		credentials.mcpBridge, credentials.mcpLaunch = nil, nil
	}
	if credentials.mcpLaunch != nil {
		if credentials.mcpLaunch.Close(ctx) != nil {
			*code, *result = 1, errOwnerShutdown
			return
		}
		credentials.mcpLaunch = nil
	}
	if credentials.capture != nil {
		if credentials.capture.Close(ctx) != nil {
			*code, *result = 1, errOwnerShutdown
			return
		}
		credentials.capture = nil
	}
	if credentials.service != nil {
		failed = credentials.service.Close(ctx) != nil || failed
		select {
		case <-credentials.service.Done():
		default:
			*code, *result = 1, errOwnerShutdown
			return // Parent key and role must outlive unfinished peers.
		}
	}
	if credentials.owner != nil && credentials.owner.Close(ctx) != nil {
		failed = true
	}
	if failed {
		*code, *result = 1, errOwnerShutdown
	}
}

// PrepareMCPBootstrapOutput wraps a known guard with a one-shot setup hook
// that installs a mandatory token snapshot before the MCP bootstrap session
// starts; until then the provider refuses to resolve.
func PrepareMCPBootstrapOutput(ctx context.Context, known remote.GuardProvider, runtime *mcpbridge.Runtime) (remote.GuardProvider, func(*outputguard.Snapshot) error) {
	var mu sync.RWMutex
	var mandatory *outputguard.Snapshot
	attempted := false
	setup := func(snapshot *outputguard.Snapshot) error {
		mu.Lock()
		defer mu.Unlock()
		if attempted {
			return mcpchannel.ErrSetup
		}
		attempted = true
		if snapshot == nil || known == nil || ctx == nil || ctx.Err() != nil {
			return mcpchannel.ErrSetup
		}
		knownSnapshot, err := known(ctx)
		if err != nil || knownSnapshot == nil {
			return mcpchannel.ErrSetup
		}
		if _, err := outputguard.Union(knownSnapshot, snapshot); err != nil || ctx.Err() != nil {
			return mcpchannel.ErrSetup
		}
		if runtime != nil && runtime.ConfigureOutput(knownSnapshot, snapshot) != nil {
			return mcpchannel.ErrSetup
		}
		if ctx.Err() != nil {
			return mcpchannel.ErrSetup
		}
		mandatory = snapshot
		return nil
	}
	provider := func(ctx context.Context) (*outputguard.Snapshot, error) {
		if ctx == nil || ctx.Err() != nil || known == nil {
			return nil, outputguard.ErrGuard
		}
		knownSnapshot, err := known(ctx)
		if err != nil || knownSnapshot == nil {
			return nil, outputguard.ErrGuard
		}
		mu.RLock()
		tokenSnapshot := mandatory
		mu.RUnlock()
		if tokenSnapshot == nil {
			return nil, outputguard.ErrGuard
		}
		combined, err := outputguard.Union(knownSnapshot, tokenSnapshot)
		if err != nil || ctx.Err() != nil {
			return nil, outputguard.ErrGuard
		}
		return combined, nil
	}
	return provider, setup
}

// PrepareRemoteMCPChannels opens the owned channel set in front of an active
// bridge, records it on the credentials so Finish closes it first, configures
// the bridge output, and returns the combined guard plus the encoded channel
// descriptors for the bootstrap envelope. Without an active bridge the known
// guard passes through unchanged.
func (credentials *Credentials) PrepareRemoteMCPChannels(ctx context.Context, known remote.GuardProvider, ttl time.Duration) (remote.GuardProvider, string, error) {
	if credentials == nil || credentials.mcpBridge == nil {
		return known, "", nil
	}
	if ctx == nil || known == nil {
		return nil, "", mcpchannel.ErrSetup
	}
	knownSnapshot, err := known(ctx)
	if err != nil || knownSnapshot == nil || credentials.mcpLaunch == nil {
		return nil, "", mcpchannel.ErrSetup
	}
	upstreams := credentials.mcpLaunch.Upstreams()
	channels, err := mcpchannel.Open(ctx, len(upstreams), ttl, func(ordinal int) mcpchannel.Handler {
		return remoteChannelHandler{bridge: credentials.mcpBridge, ordinal: ordinal}
	})
	if channels != nil {
		credentials.channels = channels
	}
	if err != nil || channels == nil {
		return nil, "", mcpchannel.ErrSetup
	}
	mandatory := channels.OutputGuard()
	if credentials.mcpBridge.ConfigureOutput(knownSnapshot, mandatory) != nil {
		return nil, "", mcpchannel.ErrSetup
	}
	wrapped := func(guardCtx context.Context) (*outputguard.Snapshot, error) {
		snapshot, guardErr := known(guardCtx)
		if guardErr != nil || snapshot == nil {
			return nil, outputguard.ErrGuard
		}
		combined, unionErr := channels.GuardWith(snapshot)
		if unionErr != nil {
			return nil, outputguard.ErrGuard
		}
		return combined, nil
	}
	encoded, err := mcpchannel.EncodeDescriptors(channels.Descriptors())
	if err != nil {
		return nil, "", mcpchannel.ErrSetup
	}
	return wrapped, encoded, nil
}

type remoteOrdinal struct {
	Ordinal int `json:"ordinal"`
}

type remoteChannelHandler struct {
	bridge  *mcpbridge.Runtime
	ordinal int
}

func (h remoteChannelHandler) Close(ctx context.Context) error {
	return h.bridge.CloseBinding(ctx, h.ordinal)
}

func (h remoteChannelHandler) Describe(ctx context.Context) ([]byte, error) {
	request, err := wire.Encode(remoteOrdinal{Ordinal: h.ordinal})
	if err != nil {
		return nil, mcpchannel.ErrSetup
	}
	reply, handled := h.bridge.Handle(ctx, wire.Request{Operation: mcpbridge.OpDescribe, Data: request})
	if !handled || !reply.OK {
		return nil, mcpchannel.ErrSetup
	}
	var envelope mcpbridge.InventoryEnvelope
	if wire.Decode(reply.Data, &envelope) != nil || envelope.Inventory == "" || len(envelope.Inventory) > mcpchannel.MaxInventoryBytes {
		return nil, mcpchannel.ErrSetup
	}
	if _, err := mcpjson.Decode([]byte(envelope.Inventory), mcpchannel.MaxInventoryBytes, 32, mcpbridge.MaxMaskNodes); err != nil {
		return nil, mcpchannel.ErrSetup
	}
	decoder := json.NewDecoder(bytes.NewReader([]byte(envelope.Inventory)))
	decoder.UseNumber()
	var inventory mcpbridge.InventoryOutput
	if decoder.Decode(&inventory) != nil || inventory.Ordinal != h.ordinal {
		return nil, mcpchannel.ErrSetup
	}
	return []byte(envelope.Inventory), nil
}

func (h remoteChannelHandler) Call(ctx context.Context, tool string, raw []byte) ([]byte, error) {
	request, err := wire.Encode(mcpbridge.CallInput{Ordinal: h.ordinal, Tool: tool, Arguments: string(raw)})
	if err != nil {
		return nil, mcpchannel.ErrSetup
	}
	reply, handled := h.bridge.Handle(ctx, wire.Request{Operation: mcpbridge.OpCall, Data: request})
	if !handled || !reply.OK {
		return nil, mcpchannel.ErrSetup
	}
	var output mcpbridge.CallOutput
	if wire.Decode(reply.Data, &output) != nil || len(output.Result) > mcpchannel.MaxResultBytes || !json.Valid([]byte(output.Result)) {
		return nil, mcpchannel.ErrSetup
	}
	return []byte(output.Result), nil
}

// agentSSHSetup pairs the runner with an optional live SSH admission runtime.
type agentSSHSetup struct {
	runner  remote.Runner
	runtime *sshlive.Runtime
}

func (setup agentSSHSetup) manager(ctx context.Context, targets []string, guard remote.GuardProvider, noOutputFilter bool) *remote.Manager {
	if setup.runtime == nil {
		return remote.NewGuardedManager(ctx, targets, setup.runner, guard)
	}
	return remote.NewAdmittedManager(ctx, targets, func(admitCtx context.Context, target, command string) (remote.AdmittedOperation, error) {
		if guard == nil {
			return remote.AdmittedOperation{}, remote.ErrAdmission
		}
		extra, err := guard(admitCtx)
		if err != nil || extra == nil {
			return remote.AdmittedOperation{}, remote.ErrAdmission
		}
		operation, err := setup.runtime.Admit(admitCtx, target, command)
		if err != nil {
			return remote.AdmittedOperation{}, remote.ErrAdmission
		}
		if noOutputFilter {
			// Keep mandatory upstream masks while bypassing known-literal filtering.
			operation.Guard = extra
			return operation, nil
		}
		merged, err := outputguard.Union(operation.Guard, extra)
		if err != nil {
			return remote.AdmittedOperation{}, remote.ErrAdmission
		}
		operation.Guard = merged
		return operation, nil
	})
}

// Manager builds the session remote manager: a guarded manager when no live
// SSH admission runtime is present, an admitted manager otherwise, merging
// or bypassing the known-literal output filter as requested.
func (credentials *Credentials) Manager(ctx context.Context, targets []string, guard remote.GuardProvider, noOutputFilter bool) *remote.Manager {
	setup := agentSSHSetup{runner: credentials.runner, runtime: credentials.ssh}
	return setup.manager(ctx, targets, guard, noOutputFilter)
}
