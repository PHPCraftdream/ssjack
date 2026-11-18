package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/agent"
	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/launchguard"
	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/transfercmd"
	"github.com/PHPCraftdream/ssjack/internal/application"
	"github.com/PHPCraftdream/ssjack/internal/broker"
	"github.com/PHPCraftdream/ssjack/internal/enrollment"
	"github.com/PHPCraftdream/ssjack/internal/launch"
	"github.com/PHPCraftdream/ssjack/internal/mcpbridge"
	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/wire"
)

// keeperCredentials is the private session surface the full-mode startup
// composition consumes; *agent.Credentials is the production implementation.
type keeperCredentials interface {
	Guard() remote.GuardProvider
	Targets() []string
	Stream() remote.StreamRunner
	Bridge() *mcpbridge.Runtime
	PrepareRemoteMCPChannels(ctx context.Context, known remote.GuardProvider, ttl time.Duration) (remote.GuardProvider, string, error)
	Manager(ctx context.Context, targets []string, guard remote.GuardProvider, noOutputFilter bool) *remote.Manager
	Finish(code *int, result *error)
}

// loadKeeperCredentials adapts agent.Load to the keeper interface, normalizing
// a nil *Credentials result to a nil interface so the partial-error and
// missing-credential startup paths stay exact.
func loadKeeperCredentials(ctx context.Context, path, profile string) (keeperCredentials, error) {
	credentials, err := agent.Load(ctx, path, profile)
	if credentials == nil {
		return nil, err
	}
	return credentials, err
}

type fullModeOptions struct {
	vaultPath, profile    string
	appRoute              string
	appDirectories        []string
	transferRoots         []string
	transferMaxBytes      int64
	transferMaxEntries    int
	noOutputFilter, named bool
	ttl                   time.Duration
}

type fullModeSession struct {
	handler       broker.Handler
	remoteMCP     string
	prepareOutput launch.OutputSetup
}

// startFullMode unlocks the profile and builds the keeper handler. The
// returned cleanup is never nil and must be deferred even when err is set: it
// releases whatever was acquired so far, in reverse order.
func startFullMode(ctx context.Context, opts fullModeOptions) (fullModeSession, func(*int, *error), error) {
	var cleanups []func(*int, *error)
	cleanup := func(code *int, result *error) {
		for i := len(cleanups) - 1; i >= 0; i-- {
			cleanups[i](code, result)
		}
	}
	var session fullModeSession
	applicationOptions, err := registeredApplications(opts.appDirectories, opts.appRoute, opts.profile, nil)
	if err != nil {
		return session, cleanup, err
	}
	transfers, err := transfercmd.Prepare(opts.vaultPath, opts.transferRoots, opts.transferMaxBytes, opts.transferMaxEntries)
	if err != nil {
		return session, cleanup, err
	}
	credentials, err := cliLoadAgentCredentials(ctx, opts.vaultPath, opts.profile)
	if credentials != nil {
		cleanups = append(cleanups, func(code *int, result *error) { credentials.Finish(code, result) })
	}
	if err != nil {
		return session, cleanup, err
	}
	if credentials == nil {
		return session, cleanup, errors.New("credential session is unavailable")
	}
	guard, err := launchguard.Select(credentials.Guard(), opts.noOutputFilter, os.Stderr)
	if err != nil {
		return session, cleanup, err
	}
	guard, session.remoteMCP, err = credentials.PrepareRemoteMCPChannels(ctx, guard, opts.ttl)
	if err != nil {
		return session, cleanup, errors.New("remote MCP channel setup failed")
	}
	guard, session.prepareOutput = agent.PrepareMCPBootstrapOutput(ctx, guard, credentials.Bridge())
	if opts.named {
		if err := bindNamedApplication(applicationOptions, credentials.Targets()); err != nil {
			return session, cleanup, err
		}
	}
	manager := credentials.Manager(ctx, credentials.Targets(), guard, opts.noOutputFilter)
	cleanups = append(cleanups, func(*int, *error) { manager.Close() })
	if applicationOptions != nil {
		applicationOptions.Runner, applicationOptions.Guard = credentials.Stream(), guard
	}
	applicationManager, err := application.New(ctx, applicationOptions)
	if err != nil {
		return session, cleanup, err
	}
	cleanups = append(cleanups, func(*int, *error) { applicationManager.Close() })
	transferManager, err := transfercmd.NewManager(transfers, credentials.Targets(), credentials.Stream())
	if err != nil {
		return session, cleanup, err
	}
	cleanups = append(cleanups, func(*int, *error) { transferManager.Close() })
	session.handler = func(ctx context.Context, request wire.Request) wire.Reply {
		if reply, handled := applicationManager.Handle(ctx, request); handled {
			return reply
		}
		if reply, handled := transferManager.Handle(ctx, request); handled {
			return reply
		}
		return manager.Handle(ctx, request)
	}
	return session, cleanup, nil
}

type enrollmentInputs struct {
	mode                                               string
	metadataPath, policyPath, identityPath             string
	metadataSupplied, policySupplied, identitySupplied bool
}

// loadEnrollment validates the declarative enrollment flags and loads the
// snapshots they name; nothing is returned when none were supplied.
func loadEnrollment(in enrollmentInputs) (*enrollment.Metadata, *enrollment.Policy, *enrollment.Snapshot, error) {
	var metadata *enrollment.Metadata
	var policy *enrollment.Policy
	var identity *enrollment.Snapshot
	if in.metadataSupplied {
		if in.metadataPath == "" {
			return nil, nil, nil, errors.New("--enrollment-metadata requires a non-empty absolute path")
		}
		if in.mode != string(broker.ModeDeclarative) {
			return nil, nil, nil, errors.New("--enrollment-metadata requires --mode declarative")
		}
		if !filepath.IsAbs(in.metadataPath) {
			return nil, nil, nil, errors.New("--enrollment-metadata path must be absolute")
		}
		loaded, err := enrollment.Load(in.metadataPath)
		if err != nil {
			return nil, nil, nil, err
		}
		metadata = &loaded
		if in.policySupplied {
			if in.policyPath == "" || !filepath.IsAbs(in.policyPath) {
				return nil, nil, nil, errors.New("--policy-snapshot requires a non-empty absolute path")
			}
			installed, err := enrollment.LoadPolicy(in.policyPath, loaded)
			if err != nil {
				return nil, nil, nil, err
			}
			policy = &installed
		}
		if in.identitySupplied {
			if in.identityPath == "" || !filepath.IsAbs(in.identityPath) {
				return nil, nil, nil, errors.New("--enrollment-identity requires a non-empty absolute path")
			}
			if policy == nil {
				return nil, nil, nil, errors.New("--enrollment-identity requires --policy-snapshot")
			}
			loaded, err := enrollment.LoadSnapshot(in.identityPath, loaded, *policy)
			if err != nil {
				return nil, nil, nil, err
			}
			identity = &loaded
		}
	} else if in.policySupplied {
		return nil, nil, nil, errors.New("--policy-snapshot requires --enrollment-metadata")
	} else if in.identitySupplied {
		return nil, nil, nil, errors.New("--enrollment-identity requires --enrollment-metadata")
	}
	return metadata, policy, identity, nil
}

// appDirectoryFlags collects repeatable --app DIR registrations.
type appDirectoryFlags []string

func (l *appDirectoryFlags) String() string {
	if l == nil {
		return ""
	}
	return strings.Join(*l, " ")
}

func (l *appDirectoryFlags) Set(value string) error {
	if value == "" {
		return errors.New("--app requires a directory")
	}
	*l = append(*l, value)
	return nil
}

// registeredApplications validates every --app directory and the optional
// --app-route before the vault is unlocked. It returns nil when none is given.
func registeredApplications(directories []string, route, profile string, runner remote.StreamRunner) (*application.Options, error) {
	if len(directories) == 0 {
		if route != "" {
			return nil, errors.New("--app-route requires --app")
		}
		return nil, nil
	}
	if len(directories) > application.MaxApplications {
		return nil, errors.New("too many --app directories")
	}
	container, user, err := application.ParseRoute(route)
	if err != nil {
		return nil, err
	}
	apps := make([]application.App, 0, len(directories))
	names := make(map[string]bool, len(directories))
	for _, directory := range directories {
		app, err := application.LoadDescriptor(directory)
		if err != nil {
			return nil, err
		}
		if names[app.Name] {
			return nil, errors.New("--app directories declare the same application name twice")
		}
		names[app.Name] = true
		apps = append(apps, app)
	}
	return &application.Options{
		Apps:      apps,
		Profile:   profile,
		Runner:    runner,
		Container: container,
		User:      user,
	}, nil
}
