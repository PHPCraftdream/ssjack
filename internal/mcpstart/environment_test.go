package mcpstart

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/broker"
	"github.com/PHPCraftdream/ssjack/internal/launch"
)

func TestReadEnvironmentScrubFailureAttemptsEveryReservedNameAndReturnsNoCapabilities(t *testing.T) {
	items := make([]string, 0, len(reservedEnvironment))
	for _, name := range reservedEnvironment {
		items = append(items, name+"=synthetic-value")
	}
	var attempted []string
	bootstrap, descriptors, err := readEnvironment(
		func() []string { return items },
		func(name string) error {
			attempted = append(attempted, name)
			return errors.New("synthetic unset failure")
		},
		func() (string, error) { t.Fatal("config checked after scrub failure"); return "", nil },
	)
	if err == nil || err.Error() != "failed to clear reserved MCP bootstrap environment" {
		t.Fatal("scrub failure did not refuse with a fixed diagnostic")
	}
	if !reflect.DeepEqual(attempted, reservedEnvironment) {
		t.Fatal("scrubbing stopped before trying every reserved variable")
	}
	if bootstrap != (broker.Bootstrap{}) || descriptors != nil {
		t.Fatal("scrub failure returned captured capabilities")
	}
}

func TestReadEnvironmentRejectsAliasesAfterAttemptingAllScrubs(t *testing.T) {
	tests := []struct {
		name      string
		items     []string
		attempted []string
	}{
		{
			name: "mixed-case alias",
			items: []string{
				broker.EnvToken + "=synthetic-token",
				"ssjack_env_token=synthetic-alias",
				broker.EnvSession + "=synthetic-session",
				broker.EnvEndpoint + "=synthetic-endpoint",
				broker.EnvPin + "=synthetic-pin",
			},
			attempted: []string{broker.EnvToken, "ssjack_env_token", broker.EnvSession, broker.EnvEndpoint, broker.EnvPin},
		},
		{
			name: "exact-case duplicate",
			items: []string{
				broker.EnvToken + "=synthetic-token-one",
				broker.EnvToken + "=synthetic-token-two",
				broker.EnvSession + "=synthetic-session",
				broker.EnvEndpoint + "=synthetic-endpoint",
				broker.EnvPin + "=synthetic-pin",
			},
			attempted: []string{broker.EnvToken, broker.EnvToken, broker.EnvSession, broker.EnvEndpoint, broker.EnvPin},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var attempted []string
			bootstrap, descriptors, err := readEnvironment(
				func() []string { return test.items },
				func(name string) error { attempted = append(attempted, name); return nil },
				func() (string, error) { t.Fatal("config checked for ambiguous aliases"); return "", nil },
			)
			if err == nil || err.Error() != "ambiguous reserved MCP bootstrap environment" {
				t.Fatal("ambiguous alias did not refuse with a fixed diagnostic")
			}
			if !reflect.DeepEqual(attempted, test.attempted) {
				t.Fatal("scrubbing did not attempt every captured spelling")
			}
			if bootstrap != (broker.Bootstrap{}) || descriptors != nil {
				t.Fatal("ambiguous environment returned captured capabilities")
			}
		})
	}
}

func TestEnsureMCPRejectsUnsafeExistingEntry(t *testing.T) {
	for name, entry := range map[string]string{
		"env": `{"type":"stdio","command":"ssjack","args":["mcp"],"env":null}`,
		"cwd": `{"type":"stdio","command":"ssjack","args":["mcp"],"cwd":"."}`,
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			original := []byte(`{"mcpServers":{"other":{"command":"unchanged"},"ssjack":` + entry + `}}`)
			path := filepath.Join(root, ".mcp.json")
			if err := os.WriteFile(path, original, 0600); err != nil {
				t.Fatal(err)
			}
			if err := launch.EnsureMCP(root); err == nil {
				t.Fatal("unsafe existing entry accepted")
			}
			got, err := os.ReadFile(path)
			if err != nil || string(got) != string(original) {
				t.Fatal("unsafe config was not preserved byte-for-byte")
			}
		})
	}
}

func TestReadEnvironmentUsesCurrentDirectoryFixedConfig(t *testing.T) {
	root := t.TempDir()
	config := `{"mcpServers":{"ssjack":{"type":"stdio","command":"ssjack","args":["mcp"]}}}`
	if err := os.WriteFile(filepath.Join(root, ".mcp.json"), []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	items := []string{
		broker.EnvSession + "=synthetic-session",
		broker.EnvEndpoint + "=synthetic-endpoint",
		broker.EnvPin + "=synthetic-pin",
		broker.EnvToken + "=synthetic-token",
	}
	bootstrap, descriptors, err := readEnvironment(
		func() []string { return items },
		func(string) error { return nil },
		func() (string, error) { return root, nil },
	)
	if err != nil || bootstrap.Token != "synthetic-token" || len(descriptors) != 0 {
		t.Fatal("valid fixed config failed environment preflight")
	}
	bootstrap.Token = ""
}

func TestReadEnvironmentScrubsRealCaseAliasOnPOSIX(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows environment names are case-insensitive")
	}
	for _, name := range reservedEnvironment {
		t.Setenv(name, "synthetic-reserved-value")
	}
	alias := "ssjack_env_token"
	t.Setenv(alias, "synthetic-alias-token")
	bootstrap, descriptors, err := readEnvironment(os.Environ, os.Unsetenv, func() (string, error) {
		t.Fatal("mixed-case alias proceeded to config preflight")
		return "", nil
	})
	if err == nil || err.Error() != "ambiguous reserved MCP bootstrap environment" {
		t.Fatal("real case alias did not refuse")
	}
	if bootstrap != (broker.Bootstrap{}) || descriptors != nil {
		t.Fatal("real case alias returned captured capabilities")
	}
	if _, exists := os.LookupEnv(alias); exists {
		t.Fatal("real case alias survived scrub")
	}
	if _, exists := os.LookupEnv(broker.EnvToken); exists {
		t.Fatal("canonical reserved variable survived scrub")
	}
}
