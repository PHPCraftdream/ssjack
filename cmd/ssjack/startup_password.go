package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/PHPCraftdream/ssjack/internal/startupsecret"
)

type startupPasswordKey struct{}

func run(ctx context.Context, args []string) (int, error) {
	value, present := os.LookupEnv(startupsecret.Environment)
	if present {
		if err := os.Unsetenv(startupsecret.Environment); err != nil {
			return 1, errors.New("cannot remove startup vault password from child environment")
		}
	}
	input := startupsecret.New(value, present)
	value = ""
	defer input.Close()
	return runWithStartupPassword(context.WithValue(ctx, startupPasswordKey{}, input), args)
}

func registerStartupPassword(ctx context.Context, flags *flag.FlagSet) {
	input := ctx.Value(startupPasswordKey{}).(*startupsecret.Input)
	flags.Var(input, "vault-password", "Existing vault unlock password (exposed in argv; hidden prompt is safer)")
}

func validateStartupPassword(ctx context.Context) error {
	return ctx.Value(startupPasswordKey{}).(*startupsecret.Input).Validate()
}

func readVaultPassword(ctx context.Context, prompt string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	fallback := func() ([]byte, error) { return readSecret(prompt) }
	input, ok := ctx.Value(startupPasswordKey{}).(*startupsecret.Input)
	if !ok {
		return fallback()
	}
	if input.Supplied() {
		fmt.Fprintln(os.Stderr, "WARNING: vault password supplied through argv/environment; hidden terminal input is safer.")
	}
	return input.Read(fallback)
}
