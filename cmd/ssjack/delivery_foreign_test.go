package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func (f *deliveryFixture) deliveryForeignAcceptance(t *testing.T, ref string, artifacts string) {
	t.Helper()
	marker := "/var/lib/ssjack/synthetic/consumer-receipt"
	before, err := os.ReadFile(marker)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal("cannot inspect consumer marker")
	}
	harness := filepath.Join(artifacts, "harness")
	answers := []deliveryAnswer{{"Exact canonical delivery reference: ", []byte(ref)}, {"Application-store master secret: ", []byte(f.anchor.master)}}
	first := f.runDeliveryCLIAs(t, 65534, answers, "appstore", "unlock", harness, ref, "export-session")
	if !strings.Contains(first, "FOREIGN_SESSION_EXPORTED") {
		t.Fatal("session export marker missing")
	}
	mid, err := os.ReadFile(marker)
	if err != nil || len(mid)-len(before) != 48 {
		t.Fatal("export session did not consume exactly once")
	}
	second := f.runDeliveryCLIAs(t, 65534, answers, "appstore", "unlock", harness, ref, "foreign-session")
	if !strings.Contains(second, "FOREIGN_SESSION_ACCEPTED") {
		t.Fatal("foreign acceptance marker missing")
	}
	after, err := os.ReadFile(marker)
	if err != nil || len(after)-len(mid) != 48 {
		t.Fatal("foreign session did not consume exactly once")
	}
	st, err := os.Stat("/var/lib/ssjack/synthetic/foreign-session.json")
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatal("foreign metadata permissions incorrect")
	}
}
