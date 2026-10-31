package main

import (
	"os"
	"testing"
)

func TestAppstoreScopedCLI(t *testing.T) {
	if os.Getenv("SSJACK_TEST_SCOPED_KDF") != "1" {
		t.Skip("private scoped CI acceptance only")
	}
	appstoreCLIAcceptance(t)
}
