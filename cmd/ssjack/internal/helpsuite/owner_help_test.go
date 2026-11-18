// Package helpsuite holds help-suite tests that drive the root CLI entry
// point for owner help topics, without touching help-package internals.
package helpsuite

import (
	"context"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/cli"
	"github.com/PHPCraftdream/ssjack/internal/ownercommand"
)

// TestEveryOwnerCommandHasNoUnlockHelp verifies every owner help topic is
// registered and that rendering it never unlocks the database. The owner
// topics are the fixed "owner" and "owner rotate-key" entries plus one entry
// per ownercommand spec, mirroring the private ownerHelpEntries table in
// cmd/ssjack/internal/help.
func TestEveryOwnerCommandHasNoUnlockHelp(t *testing.T) {
	topics := [][]string{{"owner"}, {"owner", "rotate-key"}}
	for _, spec := range ownercommand.Specs() {
		topics = append(topics, append([]string{"owner"}, strings.Fields(spec.Action)...))
	}
	for _, topic := range topics {
		if code, err := cli.Run(context.Background(), append([]string{"help"}, topic...)); code != 0 || err != nil {
			t.Fatal("owner help tried to unlock")
		}
	}
}
