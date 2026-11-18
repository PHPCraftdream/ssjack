package terminal

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"os"

	"golang.org/x/term"
)

func Secret(prompt string) ([]byte, error) {
	return TerminalInput(prompt, false)
}

func TerminalInput(prompt string, allowEmpty bool) ([]byte, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, errors.New("an interactive terminal is required for this prompt; only existing vault unlock accepts --vault-password or SSJACK_VAULT_PASSWORD")
	}
	fmt.Fprint(os.Stderr, prompt)
	secret, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		clear(secret)
		return nil, errors.New("failed to read secret")
	}
	if (!allowEmpty && len(secret) == 0) || len(secret) > 16*1024 {
		clear(secret)
		return nil, errors.New("secret must contain 1 to 16384 bytes")
	}
	return secret, nil
}

func ConfirmedSecret() ([]byte, error) {
	return ConfirmedSecretFor("container secret")
}

func ConfirmedSecretFor(label string) ([]byte, error) {
	secret, err := Secret("New " + label + ": ")
	if err != nil {
		return nil, err
	}
	confirmation, err := Secret("Confirm " + label + ": ")
	defer clear(confirmation)
	if err != nil {
		clear(secret)
		return nil, err
	}
	if subtle.ConstantTimeCompare(secret, confirmation) != 1 {
		clear(secret)
		return nil, errors.New("secrets do not match")
	}
	return secret, nil
}
