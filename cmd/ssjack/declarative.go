package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/broker"
	"github.com/PHPCraftdream/ssjack/internal/declarativeauthority"
	"github.com/PHPCraftdream/ssjack/internal/declarativeslice"
	"github.com/PHPCraftdream/ssjack/internal/launch"
)

func runDeclarative(ctx context.Context, args []string) (int, error) {
	if os.Geteuid() != 0 && len(args) > 0 && args[0] != "run" {
		return 1, errors.New("authority administration requires root")
	}
	if len(args) == 0 {
		return 1, errors.New("usage: ssjack declarative setup|register|revoke|register-delivery|revoke-delivery|run")
	}
	for _, name := range []string{broker.EnvFile, broker.EnvToken, broker.EnvSession, broker.EnvEndpoint, broker.EnvPin, "SSJACK_APP_ENDPOINT", "SSJACK_APP_TOKEN", "SSJACK_APP_CERTIFICATE_SHA256"} {
		if os.Getenv(name) != "" {
			return 1, errors.New("declarative authority commands cannot run inside a broker session")
		}
	}
	switch args[0] {
	case "setup":
		if len(args) != 1 {
			return 1, errors.New("usage: ssjack declarative setup")
		}
		fmt.Fprintln(os.Stderr, "This creates fixed-path metadata-only authority state. Verify the installed driver and scope outside any model session.")
		if err := confirmVisibleValue("Type SETUP DECLARATIVE SYNTHETIC METADATA ONLY: ", "SETUP DECLARATIVE SYNTHETIC METADATA ONLY"); err != nil {
			return 1, err
		}
		return 0, declarativeauthority.Setup()
	case "register":
		if len(args) != 1 {
			return 1, errors.New("usage: ssjack declarative register")
		}
		return registerDeclarative()
	case "revoke":
		if len(args) != 1 {
			return 1, errors.New("usage: ssjack declarative revoke")
		}
		return revokeDeclarative()
	case "register-delivery":
		if len(args) != 1 {
			return 1, errors.New("usage: ssjack declarative register-delivery")
		}
		return registerDelivery()
	case "revoke-delivery":
		if len(args) != 1 {
			return 1, errors.New("usage: ssjack declarative revoke-delivery")
		}
		return revokeDelivery()
	case "run":
		if len(args) < 2 {
			return 1, errors.New("usage: ssjack declarative run HARNESS [ARGUMENTS...]")
		}
		for _, n := range []string{broker.EnvFile, broker.EnvToken, broker.EnvSession, broker.EnvEndpoint, broker.EnvPin} {
			if os.Getenv(n) != "" {
				return 1, errors.New("cannot start a declarative keeper from an MCP bootstrap")
			}
		}
		session, err := declarativeslice.New()
		if err != nil {
			return 1, err
		}
		defer session.Close()
		exe, err := os.Executable()
		if err != nil {
			return 1, err
		}
		root, err := os.Getwd()
		if err != nil {
			return 1, err
		}
		fmt.Fprintln(os.Stderr, "Starting restricted synthetic metadata-only session.")
		return launch.Run(ctx, launch.Options{Root: root, Mode: broker.ModeDeclarative, Executable: exe, Command: args[1:], BootstrapTTL: 2 * time.Minute, Synthetic: session, Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr})
	default:
		return 1, errors.New("unknown declarative command")
	}
}
func registerDeclarative() (int, error) { return registerAuthority() }
func revokeDeclarative() (int, error) {
	refBytes, err := readVisibleInput("Exact canonical placeholder to revoke: ", false)
	if err != nil {
		return 1, err
	}
	ref := string(refBytes)
	if err = declarativeauthority.ValidateReference(ref); err != nil {
		return 1, err
	}
	if err = confirmVisibleValue("Repeat exact canonical reference: ", ref); err != nil {
		return 1, err
	}
	return 0, declarativeauthority.Revoke(ref)
}
func registerAuthority() (int, error) {
	refBytes, err := readVisibleInput("Exact canonical metadata placeholder: ", false)
	if err != nil {
		return 1, err
	}
	ref := string(refBytes)
	if declarativeauthority.ValidateReference(ref) != nil {
		return 1, errors.New("reference must be the exact canonical placeholder")
	}
	if err = confirmVisibleValue("Repeat exact canonical reference: ", ref); err != nil {
		return 1, err
	}
	code, err := declarativeauthority.CodeDigest(declarativeauthority.DriverPath)
	if err != nil {
		return 1, err
	}
	fmt.Fprintln(os.Stderr, "Installed fixed driver SHA256:", code, "; independently verify and enter the same digest twice.")
	first, err := readVisibleInput("Independent installed driver SHA256: ", false)
	if err != nil {
		return 1, err
	}
	defer clear(first)
	second, err := readVisibleInput("Repeat independently verified SHA256: ", false)
	if err != nil {
		return 1, err
	}
	defer clear(second)
	if !strings.EqualFold(string(first), code) || !strings.EqualFold(string(second), code) || !digestHex(code) {
		return 1, errors.New("installed driver digest confirmation failed")
	}
	contract := declarativeslice.Contract()
	if contract.DesiredSchemaSHA256 == "" || contract.ProjectionSchemaSHA256 == "" {
		return 1, errors.New("fixed contract unavailable")
	}
	fmt.Fprintln(os.Stderr, "Target:", contract.Target, "purpose: synthetic-metadata; desired schema:", contract.DesiredSchemaID, contract.DesiredSchemaSHA256, "projection:", contract.ProjectionSchemaID, contract.ProjectionSchemaSHA256)
	if err = confirmVisibleValue("Type the exact target identifier to authorize: ", contract.Target); err != nil {
		return 1, err
	}
	expText, err := readVisibleInput("Expiry RFC3339 UTC (within 30 days): ", false)
	if err != nil {
		return 1, err
	}
	defer clear(expText)
	exp, err := time.Parse(time.RFC3339, string(expText))
	if err != nil || exp.UTC().Format(time.RFC3339) != string(expText) || !exp.After(time.Now()) || exp.Sub(time.Now()) > declarativeauthority.MaxLifetime {
		return 1, errors.New("invalid grant expiry")
	}
	uidText, err := readVisibleInput("Keeper effective UID (non-root): ", false)
	if err != nil {
		return 1, err
	}
	defer clear(uidText)
	uid, err := strconv.Atoi(string(uidText))
	if err != nil || uid <= 0 {
		return 1, errors.New("invalid keeper UID")
	}
	if err = confirmVisibleValue("Repeat keeper UID: ", strconv.Itoa(uid)); err != nil {
		return 1, err
	}
	fmt.Fprintln(os.Stderr, "Authority grant scope: recipient UID", uid, "ref", ref, "driver SHA256", code, "target", contract.Target, "purpose synthetic-metadata", "desired schema", contract.DesiredSchemaID, contract.DesiredSchemaSHA256, "projection schema", contract.ProjectionSchemaID, contract.ProjectionSchemaSHA256, "policy synthetic-v1", "expiry", exp.UTC().Format(time.RFC3339))
	if err = confirmVisibleValue("Type REGISTER SYNTHETIC METADATA GRANT: ", "REGISTER SYNTHETIC METADATA GRANT"); err != nil {
		return 1, err
	}
	if err = declarativeauthority.PrepareState(uid); err != nil {
		return 1, err
	}
	g := declarativeauthority.Grant{RecipientUID: uid, Ref: ref, CodeSHA256: code, Target: contract.Target, Purpose: "synthetic-metadata", DesiredSchemaID: contract.DesiredSchemaID, DesiredSchemaSHA256: contract.DesiredSchemaSHA256, ProjectionSchemaID: contract.ProjectionSchemaID, ProjectionSchemaSHA256: contract.ProjectionSchemaSHA256, PolicyRevision: "synthetic-v1", ExpiresAt: string(expText)}
	if err = declarativeauthority.Register(g); err != nil {
		return 1, err
	}
	fmt.Fprintln(os.Stderr, "Synthetic metadata grant registered for recipient UID", uid, "and fixed target", contract.Target)
	return 0, nil
}
func digestHex(v string) bool {
	b, e := hex.DecodeString(v)
	return e == nil && len(b) == sha256.Size && hex.EncodeToString(b) == v
}
