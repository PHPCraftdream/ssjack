//go:build linux && amd64

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto"
	"github.com/PHPCraftdream/ssjack/internal/appstoreentry"
	"github.com/PHPCraftdream/ssjack/internal/apptransport"
	"github.com/PHPCraftdream/ssjack/internal/canonicaljson"
	"github.com/PHPCraftdream/ssjack/internal/declarativeauthority"
	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

// credentialIdentity hashes stable public credential identity, never vault bytes.
func credentialIdentity(profile string, target vault.Target) (string, error) {
	key, err := ssh.ParsePrivateKey(target.PrivateKey)
	if err != nil {
		return "", errors.New("invalid credential key")
	}
	pins := append([]string(nil), target.HostKeys...)
	for i := range pins {
		for j := i + 1; j < len(pins); j++ {
			if pins[j] < pins[i] {
				pins[i], pins[j] = pins[j], pins[i]
			}
		}
	}
	identity := struct {
		Profile  string   `json:"profile"`
		Address  string   `json:"address"`
		User     string   `json:"user"`
		HostKeys []string `json:"host_keys"`
		Signer   string   `json:"ssh_signer_fingerprint"`
	}{profile, target.Address, target.User, pins, ssh.FingerprintSHA256(key.PublicKey())}
	raw, err := json.Marshal(identity)
	if err != nil {
		return "", errors.New("cannot encode credential identity")
	}
	canonical, err := canonicaljson.Canonicalize(raw)
	if err != nil {
		return "", errors.New("cannot canonicalize credential identity")
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

func readVaultTextCredential(path, profile string) (remote.StreamRunner, string, string, error) {
	secret, err := readSecret("Vault secret: ")
	if err != nil {
		return nil, "", "", err
	}
	v, err := vault.Load(path, secret)
	clear(secret)
	if err != nil {
		return nil, "", "", err
	}
	defer v.Close()
	return textCredentialFromVault(v, profile)
}

func textCredentialFromVault(v *vault.Vault, profile string) (remote.StreamRunner, string, string, error) {
	selected, err := chooseCredential(v, profile)
	if err != nil {
		return nil, "", "", err
	}
	target := v.Targets[selected]
	if err = target.RequireUsage("agent"); err != nil {
		return nil, "", "", err
	}
	config, err := target.ClientConfig()
	if err != nil {
		return nil, "", "", err
	}
	var digest string
	if len(target.Password) != 0 {
		digest, err = v.PasswordCredentialIdentity(selected)
	} else {
		digest, err = credentialIdentity(selected, target)
	}
	if err != nil {
		return nil, "", "", err
	}
	runner, err := remote.NewCredentialStreamRunner(selected, target.Address, config)
	if err != nil {
		return nil, "", "", err
	}
	return runner, selected, digest, nil
}

func runTextAdapterCommand(ctx context.Context, vaultPath, profile string, args []string) (int, error) {
	if len(args) > 0 && args[0] == "register" {
		return registerTextAdapter(ctx, args[1:])
	}
	if len(args) > 0 && args[0] == "register-stream" {
		return registerTextAdapterMode(ctx, args[1:], "hydrate-stream-v2")
	}
	if len(args) > 0 && args[0] == "revoke-stream" {
		return revokeTextStreamAdapter(ctx, args[1:])
	}
	if len(args) > 0 && args[0] == "register-reverse" {
		return registerReverseTextAdapter(ctx, args[1:])
	}
	if len(args) > 0 && args[0] == "revoke" {
		return revokeTextAdapter(ctx, args[1:])
	}
	return runTextAdapter(ctx, vaultPath, profile, args)
}

func runTextAdapter(ctx context.Context, vaultPath, profile string, args []string) (int, error) {
	if profile == "" {
		profile = "main"
	}
	if len(args) > 0 && args[0] == "identity" {
		if len(args) != 1 || rejectAppstoreBrokerEnv() != nil || os.Geteuid() <= 0 {
			return 1, errors.New("text-adapter identity requires an unlocked vault in a non-root terminal")
		}
		_, _, digest, err := readVaultTextCredential(vaultPath, profile)
		if err != nil {
			return 1, errors.New("cannot derive credential identity")
		}
		fmt.Fprintln(os.Stdout, digest)
		return 0, nil
	}
	streaming := len(args) > 0 && args[0] == "serve-stream"
	if len(args) < 3 || (args[0] != "serve" && !streaming) {
		return 1, errors.New("usage: ssjack [-p PROFILE] text-adapter serve|serve-stream GRANT_ID HARNESS [ARGS...] | identity")
	}
	if rejectAppstoreBrokerEnv() != nil || os.Geteuid() <= 0 {
		return 1, errors.New("text adapter requires a non-root terminal outside broker sessions")
	}
	runner, profile, digest, err := readVaultTextCredential(vaultPath, profile)
	if err != nil {
		return 1, errors.New("cannot unlock text-adapter credential")
	}
	grant, err := loadCLITextGrant(args[1], streaming)
	if err != nil || (streaming && grant.Mode != "hydrate-stream-v2") || grant.Profile != profile || grant.CredentialSHA256 != digest {
		return 1, errors.New("no matching active text-adapter grant")
	}
	store, err := appstoreentry.Open(grant.StorePath)
	if err != nil {
		return 1, errAppstore
	}
	encoded, hash, err := store.Load()
	if err != nil {
		store.Close()
		return 1, errAppstore
	}
	if hex.EncodeToString(hash[:]) != grant.InstallationSHA256 {
		clear(encoded)
		store.Close()
		return 1, errAppstore
	}
	master, err := appstoreReadInput("Application-store master secret: ", false)
	if err != nil {
		clear(master)
		clear(encoded)
		store.Close()
		return 1, errAppstore
	}
	installation, err := appstorecrypto.UnlockInstallation(ctx, encoded, master)
	clear(master)
	clear(encoded)
	if err != nil {
		store.Close()
		return 1, errAppstore
	}
	dev, ino, err := store.Identity()
	unchanged := store.VerifyUnchanged(hash)
	_ = store.Close()
	if err != nil || unchanged != nil || dev != grant.DirectoryDev || ino != grant.DirectoryIno || !installation.DirectoryMatches(dev, ino) {
		installation.Close()
		return 1, errAppstore
	}
	defer installation.Close()
	if streaming {
		return runForwardStreamHarness(ctx, installation, args[1], profile, digest, runner, args[2:])
	}
	var adapter *appstorecrypto.TextAdapter
	if grant.Mode == "reverse-copy-v1" {
		adapter, err = appstorecrypto.NewReverseTextAdapter(ctx, installation, args[1], profile, digest, runner)
	} else {
		adapter, err = appstorecrypto.NewTextAdapter(ctx, installation, args[1], profile, digest, runner)
	}
	if err != nil {
		return 1, errors.New("text-adapter grant validation failed")
	}
	defer adapter.Close()
	var server *apptransport.Server
	if grant.Mode == "reverse-copy-v1" {
		server, err = apptransport.ListenWithReverseTextAdapter(ctx, profile, runner, adapter)
	} else {
		server, err = apptransport.ListenWithTextAdapter(ctx, profile, runner, adapter)
	}
	if err != nil {
		return 1, err
	}
	defer server.Close()
	cmd := exec.CommandContext(ctx, args[2], args[3:]...)
	cmd.Env = apptransport.Environment(os.Environ(), server.Bootstrap())
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err = cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode(), nil
		}
		return 1, err
	}
	return 0, nil
}

func registerTextAdapter(ctx context.Context, args []string) (int, error) {
	return registerTextAdapterMode(ctx, args, "hydrate-v1")
}

func registerReverseTextAdapter(ctx context.Context, args []string) (int, error) {
	return registerTextAdapterMode(ctx, args, "reverse-copy-v1")
}

func registerTextAdapterMode(_ context.Context, args []string, mode string) (int, error) {
	if mode != "hydrate-v1" && mode != "reverse-copy-v1" && mode != "hydrate-stream-v2" {
		return 1, errors.New("invalid text-adapter mode")
	}
	if os.Geteuid() != 0 {
		return 1, errors.New("text-adapter registration requires root")
	}
	if rejectAppstoreBrokerEnv() != nil {
		return 1, errors.New("registration is unavailable in broker sessions")
	}
	if len(args) != 0 {
		return 1, errors.New("registration metadata must be entered interactively")
	}
	var grant declarativeauthority.TextAdapterGrant
	read := func(label string) (string, error) {
		b, err := readVisibleInput(label, false)
		if err != nil {
			return "", err
		}
		defer clear(b)
		return string(b), nil
	}
	var err error
	if grant.ID, err = read("New 16-byte base64url grant ID: "); err != nil {
		return 1, err
	}
	uid, err := read("Recipient UID: ")
	if err != nil {
		return 1, err
	}
	n, err := strconv.Atoi(uid)
	if err != nil {
		return 1, errors.New("invalid recipient UID")
	}
	grant.RecipientUID = n
	fields := []struct {
		label string
		dst   *string
	}{
		{"Absolute store path: ", &grant.StorePath},
		{"Installation SHA-256: ", &grant.InstallationSHA256},
		{"Encoded hash: ", &grant.EncodedHash},
		{"Profile: ", &grant.Profile},
		{"Credential identity SHA-256: ", &grant.CredentialSHA256},
		{"Exact command: ", &grant.Command},
		{"Exact absolute file: ", &grant.File},
		{"Expiry RFC3339 UTC: ", &grant.ExpiresAt},
	}
	for _, field := range fields {
		if *field.dst, err = read(field.label); err != nil {
			return 1, err
		}
	}
	dev, err := read("Directory device number: ")
	if err != nil {
		return 1, err
	}
	if grant.DirectoryDev, err = strconv.ParseUint(dev, 10, 64); err != nil {
		return 1, errors.New("invalid directory device number")
	}
	ino, err := read("Directory inode number: ")
	if err != nil {
		return 1, err
	}
	if grant.DirectoryIno, err = strconv.ParseUint(ino, 10, 64); err != nil {
		return 1, errors.New("invalid directory inode number")
	}
	countText, err := read("Reference count (1-16): ")
	if err != nil {
		return 1, err
	}
	count, err := strconv.Atoi(countText)
	if err != nil || count < 1 || count > 16 {
		return 1, errors.New("invalid reference count")
	}
	for i := 0; i < count; i++ {
		ref, readErr := read(fmt.Sprintf("Exact canonical placeholder %d/%d: ", i+1, count))
		if readErr != nil {
			return 1, readErr
		}
		grant.References = append(grant.References, ref)
	}
	grant.Mode = mode
	validate := declarativeauthority.ValidateTextAdapterGrant
	register := declarativeauthority.RegisterTextAdapter
	if mode == "hydrate-stream-v2" {
		validate, register = declarativeauthority.ValidateTextStreamGrant, declarativeauthority.RegisterTextStream
	}
	if err = validate(grant, time.Now()); err != nil {
		return 1, errors.New("invalid grant metadata")
	}
	metadata, err := json.MarshalIndent(grant, "", "  ")
	if err != nil {
		return 1, errors.New("cannot display grant metadata")
	}
	fmt.Fprintln(os.Stderr, string(metadata))
	phrase := "APPROVE TEXT ADAPTER " + grant.ID
	if mode == "hydrate-stream-v2" {
		phrase = "APPROVE STREAM TEXT ADAPTER " + grant.ID
		fmt.Fprintln(os.Stderr, "Approve only the exact streamed target command/file and references, with finite 64 MiB bounds; no raw fallback or automatic retry is authorized.")
	}
	if mode == "reverse-copy-v1" {
		phrase = "APPROVE REVERSE TEXT COPY " + grant.ID
		fmt.Fprintln(os.Stderr, "Approve only the exact source command and file for a reference-only selected copy; raw fallback and live-file rewrites are not authorized.")
	}
	fmt.Fprintln(os.Stderr, "Independently confirm the credential digest, file, command, and references before repeating the approval phrase.")
	if err = confirmVisibleValue("Type exact approval phrase", phrase); err != nil {
		return 1, err
	}
	if err = register(grant); err != nil {
		return 1, err
	}
	fmt.Fprintln(os.Stdout, grant.ID)
	return 0, nil
}

func revokeTextAdapter(_ context.Context, args []string) (int, error) {
	if os.Geteuid() != 0 {
		return 1, errors.New("text-adapter revocation requires root")
	}
	if rejectAppstoreBrokerEnv() != nil {
		return 1, errors.New("revocation is unavailable in broker sessions")
	}
	if len(args) != 1 {
		return 1, errors.New("usage: ssjack text-adapter revoke GRANT_ID")
	}
	if err := declarativeauthority.RevokeTextAdapter(args[0]); err != nil {
		return 1, err
	}
	return 0, nil
}
