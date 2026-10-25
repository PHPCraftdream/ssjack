package main

import (
	"fmt"
	"io"

	"golang.org/x/crypto/ssh"

	"storagehost/internal/vault"
)

func writeProfileSummary(output io.Writer, name string, target vault.Target) error {
	if _, err := fmt.Fprintf(output, "Profile: %s\nAddress: %q\nUser: %q\nUsage: %s\n", name, target.Address, target.User, target.EffectiveUsage()); err != nil {
		return err
	}
	for _, encoded := range target.HostKeys {
		key, err := vault.ParseHostKey([]byte(encoded))
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintln(output, "Server key:", ssh.FingerprintSHA256(key)); err != nil {
			return err
		}
	}
	return nil
}
