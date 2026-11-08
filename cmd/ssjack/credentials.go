package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"

	tea "charm.land/bubbletea/v2"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"github.com/PHPCraftdream/ssjack/internal/keyfile"
	"github.com/PHPCraftdream/ssjack/internal/mcpbridge"
	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
	"github.com/PHPCraftdream/ssjack/internal/mcpgrant"
	"github.com/PHPCraftdream/ssjack/internal/mcpselect"
	"github.com/PHPCraftdream/ssjack/internal/outputguard"
	"github.com/PHPCraftdream/ssjack/internal/ownerdb"
	"github.com/PHPCraftdream/ssjack/internal/ownerservice"
	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func chooseCredential(v *vault.Vault, name string) (string, error) {
	if name == "" {
		name = "main"
	}
	server, account, named, err := parseCredentialSelection(name)
	if err != nil {
		return "", err
	}
	if named {
		return resolveNamedCredential(v, server, account)
	}
	if _, exists := v.Targets[name]; !exists {
		return "", errors.New("selected profile does not exist; create it with ssjack -p NAME add")
	}
	return name, nil
}

func readVaultCredential(ctx context.Context, path, name, usage string) (*ssh.ClientConfig, string, string, error) {
	v, config, address, selected, err := openVaultCredential(ctx, path, name, usage)
	if err != nil {
		return nil, "", "", err
	}
	v.Close()
	return config, address, selected, nil
}

func openVaultCredential(ctx context.Context, path, name, usage string) (_ *vault.Vault, _ *ssh.ClientConfig, _ string, _ string, err error) {
	if name != "" {
		if err := validateCredentialSelection(name); err != nil {
			return nil, nil, "", "", err
		}
	}
	secret, err := readVaultPassword(ctx, "Vault secret: ")
	if err != nil {
		return nil, nil, "", "", err
	}
	v, err := vault.Load(path, secret)
	clear(secret)
	if err != nil {
		return nil, nil, "", "", err
	}
	defer func() {
		if err != nil {
			v.Close()
		}
	}()
	name, err = chooseCredential(v, name)
	if err != nil {
		return nil, nil, "", "", err
	}
	target := v.Targets[name]
	if usage != "" {
		if err := target.RequireUsage(usage); err != nil {
			return nil, nil, "", "", err
		}
	}
	config, err := target.ClientConfig()
	if err != nil {
		return nil, nil, "", "", err
	}
	fmt.Fprintln(os.Stderr, "Using credentials:", name)
	return v, config, target.Address, name, nil
}

func credentialCipherDigest(path string) ([sha256.Size]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	if !info.Mode().IsRegular() || info.Size() > keyfile.MaxSize {
		return [sha256.Size]byte{}, errors.New("vault must be a regular encrypted file within the size limit")
	}
	file, err := os.Open(path)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || opened.Size() > keyfile.MaxSize {
		return [sha256.Size]byte{}, errors.New("vault must be a regular encrypted file within the size limit")
	}
	hash := sha256.New()
	encodedSize, err := io.Copy(hash, io.LimitReader(file, int64(keyfile.MaxSize)+1))
	if err != nil || encodedSize > int64(keyfile.MaxSize) {
		return [sha256.Size]byte{}, errors.New("failed to read encrypted vault")
	}
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return digest, nil
}

func loadAgentCredentials(ctx context.Context, path, name string) (*agentCredentials, error) {
	v, config, address, selected, err := openVaultCredential(ctx, path, name, "agent")
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
	credentials := &agentCredentials{runner: runner, stream: stream, targets: []string{selected}, guard: fixedOutputGuard(nil)}
	if v.Version == 2 {
		var choice mcpselect.Choice
		var capture *mcpgrant.Capture
		var originDigest [32]byte
		if v.RemoteMCP != nil {
			if !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stdout.Fd())) {
				return nil, errors.New("remote MCP selection requires a trusted input and output terminal")
			}
			var readErr error
			originDigest, readErr = credentialCipherDigest(path)
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
			diskDigest, diskErr := credentialCipherDigest(path)
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
		service, err := ownerservice.Start(ctx, owner)
		if err != nil {
			return credentials, err
		}
		credentials.service = service
	} else {
		snapshot, _ := v.LegacyOutputGuard(ctx, path)
		credentials.guard = fixedOutputGuard(snapshot)
	}
	return credentials, nil
}
