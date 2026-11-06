package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/broker"
	"github.com/PHPCraftdream/ssjack/internal/outputguard"
)

func TestOutputFilterChoiceDefaultsToOriginalGuardAndWarnsBeforeBypass(t *testing.T) {
	ctx := context.Background()
	snapshot, err := outputguard.New([][]byte{[]byte("synthetic-private-literal")})
	if err != nil {
		t.Fatal(err)
	}
	var warning bytes.Buffer
	provider, err := selectOutputGuard(fixedOutputGuard(snapshot), false, &warning)
	if err != nil || warning.Len() != 0 {
		t.Fatal("default selection emitted a bypass warning")
	}
	captured, err := provider(ctx)
	if err != nil || captured != snapshot {
		t.Fatal("default selection replaced the authenticated guard")
	}
	assertGuardMasks(t, captured, []byte("synthetic-private-literal"))
	provider, err = selectOutputGuard(fixedOutputGuard(nil), true, &warning)
	if err != nil || warning.String() != outputFilterWarning {
		t.Fatal("explicit bypass omitted its complete fixed warning")
	}
	captured, err = provider(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	writer, err := outputguard.NewWriter(captured, &output)
	if err != nil {
		t.Fatal(err)
	}
	value := []byte("synthetic-private-literal|\x00\xff")
	if n, err := writer.Write(value); n != len(value) || err != nil || writer.Close() != nil || !bytes.Equal(output.Bytes(), value) {
		t.Fatal("deliberate bypass transformed model bytes")
	}
	if provider, err := selectOutputGuard(nil, false, &bytes.Buffer{}); provider != nil || err != nil {
		t.Fatal("missing default provider became an unguarded fallback")
	}
}

type refusedWarning struct{ short bool }

func (w refusedWarning) Write(value []byte) (int, error) {
	if w.short {
		return len(value) - 1, nil
	}
	return 0, errors.New("synthetic private sink diagnostic")
}

func TestOutputFilterBypassRefusesMissingOrFailedWarning(t *testing.T) {
	for _, sink := range []io.Writer{nil, refusedWarning{}, refusedWarning{short: true}} {
		provider, err := selectOutputGuard(nil, true, sink)
		if provider != nil || err == nil || strings.Contains(err.Error(), "private sink") {
			t.Fatal("bypass ignored failed warning or exposed sink diagnostics")
		}
	}
}

func TestOutputFilterFlagRefusesOtherCommandsAndBrokerLaunchBeforeUnlock(t *testing.T) {
	old := cliLoadAgentCredentials
	t.Cleanup(func() { cliLoadAgentCredentials = old })
	called := false
	cliLoadAgentCredentials = func(context.Context, string, string) (*agentCredentials, error) {
		called = true
		return nil, errors.New("unexpected credential read")
	}
	for _, args := range [][]string{
		{"--no-output-filter", "ssh"}, {"--no-output-filter", "--interactive"},
		{"--no-output-filter", "owner", "status"}, {"--no-output-filter", "--version"},
		{"--no-output-filter", "--mode", "declarative", "run", "fixture"},
		{"--no-output-filter", "--generate-key", "unused", "run", "fixture"},
	} {
		if code, err := run(context.Background(), args); code == 0 || err == nil || !strings.Contains(err.Error(), "only available for an explicit full-mode") || called {
			t.Fatal("output-filter flag escaped its startup scope")
		}
	}
	t.Setenv(broker.EnvSession, "synthetic active session")
	if code, err := run(context.Background(), []string{"--no-output-filter", "run", "fixture"}); code == 0 || err == nil || !strings.Contains(err.Error(), "outside broker sessions") || called {
		t.Fatal("broker launch bypassed trusted terminal admission")
	}
}
