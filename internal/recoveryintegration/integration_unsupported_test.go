//go:build !linux

package recoveryintegration

import "testing"

func TestLinuxRecoveryJournalIntegrationSkipped(t *testing.T) {
	t.Skip("create-only durable recovery journal integration requires Linux")
}
