package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"

	"github.com/PHPCraftdream/ssjack/internal/buildinfo"
	"github.com/PHPCraftdream/ssjack/internal/diagnostic"
	"github.com/PHPCraftdream/ssjack/internal/keyfile"
	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func runSafetyCommand(ctx context.Context, path string, args []string) (int, error) {
	if len(args) == 1 && args[0] == "doctor" {
		return runDoctor(ctx, path)
	}
	if len(args) == 2 && args[0] == "check" {
		if err := vault.ValidateName(args[1]); err != nil {
			return 1, err
		}
		config, address, name, err := readVaultCredential(path, args[1], "")
		if err != nil {
			return 1, err
		}
		if err := remote.Check(ctx, address, config); err != nil {
			return 1, err
		}
		fmt.Fprintf(os.Stdout, "OK %s: server pin, SSH authentication, and session opening verified; no remote command was executed.\n", name)
		return 0, nil
	}
	if len(args) > 0 && args[0] == "hostkey" {
		return runHostKey(ctx, path, args[1:])
	}
	if len(args) == 2 && args[0] == "rotate" {
		return runRotation(ctx, path, args[1])
	}
	return 1, errors.New("invalid command arguments; use ssjack help COMMAND")
}

func runDoctor(ctx context.Context, path string) (int, error) {
	fmt.Fprintln(os.Stdout, buildinfo.String())
	executable, err := os.Executable()
	if err != nil {
		return 1, err
	}
	root, err := os.Getwd()
	if err != nil {
		return 1, err
	}
	resolved, _ := exec.LookPath("ssjack")
	findings := diagnostic.Inspect(diagnostic.Paths{Root: root, Vault: path, Executable: executable, PathExecutable: resolved})
	for _, finding := range findings {
		fmt.Fprintf(os.Stdout, "%s %-18s %s\n", finding.Status, finding.Check, finding.Detail)
	}
	if info, err := os.Lstat(path); err != nil || !info.Mode().IsRegular() {
		return 1, errors.New("vault is unavailable; create it with ssjack vault init")
	}
	secret, err := readSecret("Vault secret for full validation: ")
	if err != nil {
		return 1, err
	}
	v, err := vault.Load(path, secret)
	clear(secret)
	if err != nil {
		return 1, err
	}
	defer v.Close()
	if err := ctx.Err(); err != nil {
		return 1, err
	}
	fmt.Fprintf(os.Stdout, "OK vault integrity    verified %d records; 4 Argon2id operations at %d KiB each, %d AES-GCM data layers\n", len(v.Targets), keyfile.MemoryKiB, keyfile.Layers)
	fmt.Fprintln(os.Stdout, "WARN UI compatibility requires a harness supporting function-hook render plugins; no harness was launched")
	if err := diagnostic.Failed(findings); err != nil {
		return 1, err
	}
	return 0, nil
}
