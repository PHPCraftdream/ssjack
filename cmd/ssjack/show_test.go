package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func TestShowIncludesEffectiveUsageWithoutPrivateBytes(t *testing.T) {
	for _, usage := range []string{"", "both", "human", "agent"} {
		private := []byte("private payload must never be printed")
		target := vault.Target{Address: "example.test:22", User: "user", Usage: usage, PrivateKey: private}
		var output bytes.Buffer
		if err := writeProfileSummary(&output, "main", target); err != nil {
			t.Fatal(err)
		}
		want := usage
		if want == "" {
			want = "both"
		}
		if !strings.Contains(output.String(), "Usage: "+want+"\n") || !strings.Contains(output.String(), "Profile: main\n") {
			t.Fatalf("effective usage not displayed: %q", output.String())
		}
		if bytes.Contains(output.Bytes(), private) {
			t.Fatal("show printed private key bytes")
		}
	}
}
