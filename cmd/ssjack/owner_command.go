package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	tea "charm.land/bubbletea/v2"
	"golang.org/x/term"

	"github.com/PHPCraftdream/ssjack/internal/ownercommand"
	"github.com/PHPCraftdream/ssjack/internal/ownercontrol"
	"github.com/PHPCraftdream/ssjack/internal/ownerrotatecli"
	"github.com/PHPCraftdream/ssjack/internal/ownertui"
	"github.com/PHPCraftdream/ssjack/internal/startupsecret"
)

func runOwnerCommand(ctx context.Context, flags *flag.FlagSet, path, server, account string, args []string) (int, error) {
	if len(args) > 0 && args[0] == "rotate-key" {
		if flags == nil {
			return 1, ownercommand.ErrArguments
		}
		invalid := false
		flags.Visit(func(f *flag.Flag) {
			if f.Name != "vault" && f.Name != "server" && f.Name != "account" {
				invalid = true
			}
		})
		if invalid {
			return 1, ownercommand.ErrArguments
		}
		var startupPasswordSupplied bool
		if ctx != nil {
			input, _ := ctx.Value(startupPasswordKey{}).(*startupsecret.Input)
			startupPasswordSupplied = input != nil && input.Supplied()
		}
		return ownerrotatecli.Run(ctx, path, server, account, args, startupPasswordSupplied, readSecret)
	}
	invalid := false
	flags.Visit(func(f *flag.Flag) {
		if f.Name != "vault" && f.Name != "server" && f.Name != "account" && f.Name != "vault-password" {
			invalid = true
		}
	})
	if invalid {
		return 1, ownercommand.ErrArguments
	}
	request, err := ownercommand.Parse(args, server, account)
	if err != nil {
		return 1, err
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stdout.Fd())) {
		return 1, errors.New("owner commands require a trusted input and output terminal")
	}
	if err := ctx.Err(); err != nil {
		return 1, err
	}
	password, err := readVaultPassword(ctx, "Vault secret: ")
	if err != nil {
		return 1, err
	}
	control, err := ownercontrol.Open(ctx, path, password)
	clear(password)
	if err != nil {
		return 1, ownercontrol.ErrControl
	}
	defer control.Detach()
	model := ownertui.New(ctx, control.Backend())
	err = model.ConfigureCommand(request)
	if err == nil {
		_, err = tea.NewProgram(model, tea.WithContext(ctx), tea.WithInput(os.Stdin), tea.WithOutput(os.Stdout)).Run()
		model.ClearInput()
		if err == nil {
			err = model.CommandResult()
		} else {
			err = ownercommand.ErrOperation
		}
	}
	closeCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if closeErr := control.Close(closeCtx); closeErr != nil {
		return 1, ownercommand.ErrOperation
	}
	if err != nil {
		return 1, err
	}
	fmt.Fprintln(os.Stdout, "Owner command completed; encrypted persistence confirmed.")
	return 0, nil
}
