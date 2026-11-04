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
	"github.com/PHPCraftdream/ssjack/internal/remote"
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
	// Each selected connection ends the Program, which restores the terminal, so
	// the SSH session owns it exclusively; the same model then resumes in a new
	// Program. The manager stays open and no second unlock happens.
	var runErr, inputErr error
	for {
		_, runErr = tea.NewProgram(model, tea.WithContext(ctx), tea.WithInput(os.Stdin), tea.WithOutput(os.Stdout)).Run()
		model.ClearInput()
		connection, requested := model.TakeConnection()
		if runErr != nil || ctx.Err() != nil || !requested {
			break
		}
		config, address, err := manager.HumanSSH(connection.ServerID, connection.Account)
		if err != nil {
			model.Connected(1, err)
			continue
		}
		code, err := runShell(ctx, config, address)
		resume, fatal := shellOutcome(code, err)
		if !resume {
			// A competing Program would read the same stdin as the stuck reader.
			inputErr = fatal
			break
		}
		model.Connected(code, err)
		if err := ctx.Err(); err != nil {
			runErr = err
			break
		}
	}
	closeCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := manager.Close(closeCtx); err != nil {
		return 1, errors.New("owner editor stopped with unsaved or unresolved changes; reopen the encrypted database and inspect pending recovery")
	}
	if inputErr != nil {
		return 1, inputErr
	}
	if runErr != nil {
		return 1, errors.New("owner terminal editor stopped unexpectedly")
	}
	return 0, nil
}

// shellOutcome fails closed when terminal input could not be released: the
// picker must not resume. The text claims a safe database close, so callers
// return it only after manager.Close succeeded.
func shellOutcome(_ int, err error) (resume bool, fatal error) {
	if errors.Is(err, remote.ErrInputNotReleased) {
		return false, errors.New("terminal input could not be released after the SSH session; restart ssjack (the database was closed safely)")
	}
	return true, nil
}
