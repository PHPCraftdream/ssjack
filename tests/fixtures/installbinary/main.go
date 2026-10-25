package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	executable, err := os.Executable()
	if err != nil {
		os.Exit(2)
	}
	if len(os.Args) == 2 && os.Args[1] == "--hold" {
		fmt.Println("ready")
		if _, err := io.Copy(io.Discard, os.Stdin); err != nil {
			os.Exit(2)
		}
		return
	}
	if marker := os.Getenv("SSJACK_INSTALL_TEST_MARKER"); marker != "" {
		if err := os.WriteFile(marker, []byte(executable), 0600); err != nil {
			os.Exit(2)
		}
	}
	installed := !strings.HasPrefix(filepath.Base(filepath.Dir(executable)), ".ssjack-install")
	if installed && os.Getenv("SSJACK_INSTALL_TEST_FAIL_INSTALLED") == "1" {
		fmt.Fprintln(os.Stderr, "intentional installed-path probe failure")
		os.Exit(2)
	}
	if len(os.Args) != 2 || os.Args[1] != "--help" {
		os.Exit(2)
	}
	fmt.Println("Usage: ssjack installer-test-fixture")
}
