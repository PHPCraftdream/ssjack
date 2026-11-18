package declarative

import (
	"context"

	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/terminal"
)

// Run dispatches the declarative subcommands for the root CLI.
func Run(ctx context.Context, args []string) (int, error) {
	return runDeclarative(ctx, args)
}

func readVisibleInput(prompt string, allowEmpty bool) ([]byte, error) {
	return terminal.VisibleInput(prompt, allowEmpty)
}

func confirmVisibleValue(prompt, expected string) error {
	return terminal.ConfirmVisibleValue(prompt, expected)
}
