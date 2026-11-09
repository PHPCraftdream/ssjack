package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/startupsecret"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func TestVaultStartupPasswordFullProfile(t *testing.T) {
	if os.Getenv("SSJACK_TEST_FULL_KDF") != "1" {
		t.Skip("production KDF acceptance is CI-only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	password := []byte("synthetic-startup-vault-password")
	defer clear(password)
	path := filepath.Join(t.TempDir(), "directory.ktav")
	v := vault.NewDirectory()
	defer v.Close()
	if err := vault.CreateWithRecords(ctx, path, v, password); err != nil {
		t.Fatal("cannot create synthetic full-profile database")
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"environment", "argument-override", "wrong-password"} {
		t.Run(mode, func(t *testing.T) {
			args := []string{"--vault", path, "list"}
			environment := string(password)
			if mode == "argument-override" {
				environment = "synthetic-wrong-environment"
				args = []string{"--vault", path, "--vault-password", string(password), "list"}
			} else if mode == "wrong-password" {
				environment = "synthetic-wrong-password"
			}
			t.Setenv(startupsecret.Environment, environment)
			code, runErr, output := captureStartup(t, func() (int, error) { return run(ctx, args) })
			if (mode == "wrong-password") != (code != 0 || runErr != nil) {
				t.Fatal("startup source failed real database authentication or accepted a wrong password")
			}
			for _, secret := range []string{string(password), environment} {
				if strings.Contains(output, secret) || (runErr != nil && strings.Contains(runErr.Error(), secret)) {
					t.Fatal("startup output exposed a password")
				}
			}
			if _, present := os.LookupEnv(startupsecret.Environment); present {
				t.Fatal("startup retained the environment password")
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("read-only startup changed ciphertext")
			}
		})
	}
}

func captureStartup(t *testing.T, call func() (int, error)) (int, error, string) {
	t.Helper()
	input, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	stdin, stdout, stderr := os.Stdin, os.Stdout, os.Stderr
	os.Stdin, os.Stdout, os.Stderr = input, writer, writer
	defer func() { os.Stdin, os.Stdout, os.Stderr = stdin, stdout, stderr }()
	code, runErr := call()
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	output, err := io.ReadAll(io.LimitReader(reader, 8193))
	if err != nil || len(output) > 8192 {
		t.Fatal("unexpected startup output")
	}
	return code, runErr, string(output)
}
