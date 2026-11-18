package startup

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/PHPCraftdream/ssjack/internal/startupsecret"
)

type contextKey struct{}

// WithInput attaches the startup password input to the context.
func WithInput(ctx context.Context, input *startupsecret.Input) context.Context {
	return context.WithValue(ctx, contextKey{}, input)
}

func Register(ctx context.Context, flags *flag.FlagSet) {
	input := ctx.Value(contextKey{}).(*startupsecret.Input)
	flags.Var(input, "vault-password", "Existing vault unlock password (exposed in argv; hidden prompt is safer)")
}

func Validate(ctx context.Context) error {
	return ctx.Value(contextKey{}).(*startupsecret.Input).Validate()
}

// Supplied reports whether a startup password was provided through
// --vault-password or the environment. A context without an input yields
// false, mirroring the previous nil check in the owner.
func Supplied(ctx context.Context) bool {
	input, ok := ctx.Value(contextKey{}).(*startupsecret.Input)
	if !ok || input == nil {
		return false
	}
	return input.Supplied()
}

func ReadVaultPassword(ctx context.Context, prompt string, fallback func(string) ([]byte, error)) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	input, ok := ctx.Value(contextKey{}).(*startupsecret.Input)
	if !ok {
		return fallback(prompt)
	}
	if input.Supplied() {
		fmt.Fprintln(os.Stderr, "WARNING: vault password supplied through argv/environment; hidden terminal input is safer.")
	}
	return input.Read(func() ([]byte, error) { return fallback(prompt) })
}
