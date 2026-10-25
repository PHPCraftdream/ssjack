package main

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/term"

	"github.com/PHPCraftdream/ssjack/internal/keyfile"
)

func runKeyCommand(ctx context.Context, generatePath, protectPath, output string) (int, error) {
	if generatePath != "" && (protectPath != "" || output != "") {
		return 1, errors.New("--generate-key cannot be combined with --protect-key or --key-output")
	}
	if generatePath == "" && protectPath == "" {
		return 1, errors.New("--key-output requires --protect-key")
	}
	if generatePath != "" {
		return generateKey(ctx, generatePath)
	}
	if output == "" {
		output = protectPath + ".ssjack.ktav"
	}
	return protectKey(ctx, protectPath, output)
}

func readSecret(prompt string) ([]byte, error) {
	return readTerminalInput(prompt, false)
}

func readTerminalInput(prompt string, allowEmpty bool) ([]byte, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, errors.New("an interactive terminal is required; secrets from arguments, environment variables, or pipes are not accepted")
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

func confirmedSecret() ([]byte, error) {
	return confirmedSecretFor("container secret")
}

func confirmedSecretFor(label string) ([]byte, error) {
	secret, err := readSecret("New " + label + ": ")
	if err != nil {
		return nil, err
	}
	confirmation, err := readSecret("Confirm " + label + ": ")
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

func requireNewPath(path string) error {
	if _, err := os.Lstat(path); err == nil {
		return errors.New("output already exists; refusing to overwrite it")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	parent, err := os.Stat(filepath.Dir(path))
	if err != nil {
		return err
	}
	if !parent.IsDir() {
		return errors.New("output parent must be a directory")
	}
	return nil
}

func writeNewFile(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	n, writeErr := file.Write(data)
	if writeErr == nil && n != len(data) {
		writeErr = io.ErrShortWrite
	}
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr != nil {
		return fmt.Errorf("output may be incomplete: %w", writeErr)
	}
	return closeErr
}

func generateKey(ctx context.Context, path string) (int, error) {
	for _, output := range []string{path, path + ".pub"} {
		if err := requireNewPath(output); err != nil {
			return 1, err
		}
	}
	fmt.Fprintln(os.Stderr, "The typed secret determines the Ed25519 key together with fresh public salts. Keep the container; the secret alone cannot recover its parameters.")
	secret, err := confirmedSecret()
	if err != nil {
		return 1, err
	}
	defer clear(secret)
	if err := ctx.Err(); err != nil {
		return 1, err
	}
	fmt.Fprintln(os.Stderr, "Deriving key: four sequential Argon2id operations at 1 GiB each, then 1000 AES-GCM layers. This can take several seconds or longer.")
	encoded, public, err := keyfile.Generate(secret)
	if err != nil {
		return 1, err
	}
	if err := ctx.Err(); err != nil {
		return 1, err
	}
	if err := writeNewFile(path, encoded, 0600); err != nil {
		return 1, err
	}
	if err := writeNewFile(path+".pub", public, 0644); err != nil {
		return 1, fmt.Errorf("private container was saved; public key could not be saved: %w", err)
	}
	fmt.Fprintln(os.Stderr, "Saved encrypted private container and OpenSSH public key. Install only the .pub file on the server.")
	return 0, nil
}

func protectKey(ctx context.Context, input, output string) (int, error) {
	if err := requireNewPath(output); err != nil {
		return 1, err
	}
	file, err := os.Open(input)
	if err != nil {
		return 1, err
	}
	data, readErr := io.ReadAll(io.LimitReader(file, 1024*1024+1))
	file.Close()
	defer clear(data)
	if readErr != nil || len(data) > 1024*1024 {
		return 1, errors.New("failed to read encrypted SSH key")
	}
	encrypted, err := keyfile.RequiresPassphrase(data)
	if err != nil {
		return 1, err
	}
	var password []byte
	if encrypted {
		password, err = readSecret("Existing key passphrase: ")
		if err != nil {
			return 1, err
		}
	} else {
		fmt.Fprintln(os.Stderr, "Source key is unencrypted; it will remain unchanged. Only the new container is protected.")
	}
	plaintext, err := keyfile.ImportSSH(data, password)
	clear(password)
	if err != nil {
		return 1, errors.New("failed to unlock input key")
	}
	defer clear(plaintext)
	secret, err := confirmedSecret()
	if err != nil {
		return 1, err
	}
	defer clear(secret)
	if err := ctx.Err(); err != nil {
		return 1, err
	}
	fmt.Fprintln(os.Stderr, "Protecting key: four sequential Argon2id operations at 1 GiB each, then 1000 AES-GCM layers.")
	encoded, err := keyfile.Seal(plaintext, secret)
	if err != nil {
		return 1, err
	}
	if err := ctx.Err(); err != nil {
		return 1, err
	}
	if err := writeNewFile(output, encoded, 0600); err != nil {
		return 1, err
	}
	fmt.Fprintln(os.Stderr, "Saved the new encrypted container. Input key and configuration were not changed. Older copies retain their original protection.")
	return 0, nil
}
