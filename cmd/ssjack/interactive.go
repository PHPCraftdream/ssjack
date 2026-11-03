package main

import (
	"context"
	"errors"
	"os"
	"time"

	tea "charm.land/bubbletea/v2"
	"golang.org/x/term"

	"github.com/PHPCraftdream/ssjack/internal/ownerdb"
	"github.com/PHPCraftdream/ssjack/internal/ownertui"
)

func runInteractive(ctx context.Context, path, server, account string) (int, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stdout.Fd())) {
		return 1, errors.New("--interactive requires a trusted input and output terminal")
	}
	if err := ctx.Err(); err != nil {
		return 1, err
	}
	password, err := readSecret("Vault secret: ")
	if err != nil {
		return 1, err
	}
	manager, err := ownerdb.Open(ctx, path, password)
	clear(password)
	if err != nil {
		return 1, errors.New("cannot unlock owner database; legacy databases require explicit vault migrate-directory")
	}
	model := ownertui.New(ctx, manager)
	if err := model.Select(server, account); err != nil {
		closeCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if closeErr := manager.Close(closeCtx); closeErr != nil {
			return 1, errors.New("named selection failed; inspect the saved owner database and pending recovery")
		}
		return 1, err
	}
	_, runErr := tea.NewProgram(model, tea.WithContext(ctx), tea.WithInput(os.Stdin), tea.WithOutput(os.Stdout)).Run()
	model.ClearInput()
	closeCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := manager.Close(closeCtx); err != nil {
		return 1, errors.New("owner editor stopped with unsaved or unresolved changes; reopen the encrypted database and inspect pending recovery")
	}
	if runErr != nil {
		return 1, errors.New("owner terminal editor stopped unexpectedly")
	}
	return 0, nil
}
