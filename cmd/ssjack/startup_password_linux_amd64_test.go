package main

import (
	"context"
	"os"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/startupsecret"
)

func TestStartupPasswordDoesNotBypassTextAdapterTerminal(t *testing.T) {
	input, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	previous := os.Stdin
	os.Stdin = input
	defer func() { os.Stdin = previous }()
	source := startupsecret.New("synthetic-password", true)
	defer source.Close()
	ctx := context.WithValue(context.Background(), startupPasswordKey{}, source)
	if _, _, _, err := readVaultTextCredential(ctx, "unused", "main"); err == nil {
		t.Fatal("startup password removed the text-adapter terminal boundary")
	}
	password, err := readVaultPassword(ctx, "must not prompt")
	defer clear(password)
	if err != nil || string(password) != "synthetic-password" {
		t.Fatal("refused text adapter consumed the startup password")
	}
}
