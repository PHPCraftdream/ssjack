package clitest

import (
	"context"
	"testing"

	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/cli"
)

func TestProfileModeValidation(t *testing.T) {
	for _, args := range [][]string{
		{"--config", "legacy", "run", "claude"},
		{"ssh", "positional-profile"},
		{"--generate-key", "new", "run", "claude"},
		{"run"},
		{"-p", "../invalid", "ssh"},
		{"--profile", "../invalid", "edit"},
	} {
		if code, err := cli.Run(context.Background(), args); code == 0 || err == nil {
			t.Fatalf("invalid profile mode accepted: %v", args)
		}
	}
}
