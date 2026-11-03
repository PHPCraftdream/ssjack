package declarativeschemas_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/declarativeschemas"
)

func digest(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

func TestCatalogFixtures(t *testing.T) {
	tools, err := declarativeschemas.Catalog()
	if err != nil {
		t.Fatal(err)
	}
	if len(tools) != len(fixtures) {
		t.Fatalf("got %d tools, want %d", len(tools), len(fixtures))
	}
	for i, want := range fixtures {
		t.Run(want.name, func(t *testing.T) {
			got := tools[i]
			if got.Name != want.name || got.SchemaID != "ssjack.tool."+want.name+".v1" {
				t.Errorf("identity: %#v", got)
			}
			if got.InputSchema != want.input {
				t.Errorf("input\ngot  %s\nwant %s", got.InputSchema, want.input)
			}
			if got.OutputSchema != want.output {
				t.Errorf("output\ngot  %s\nwant %s", got.OutputSchema, want.output)
			}
			pair := `{"input":` + want.input + `,"output":` + want.output + `}`
			expected := digest("ssjack-tool-schema-v1\x00" + pair)
			if got.SchemaDigest != expected {
				t.Errorf("digest got %q, want %q", got.SchemaDigest, expected)
			}
			swapped := `{"input":` + want.output + `,"output":` + want.input + `}`
			for _, wrong := range []string{
				digest("ssjack-schema-v1\x00" + pair),
				digest("ssjack-tool-schema-v1" + pair),
				digest("ssjack-tool-schema-v1\x00" + swapped),
			} {
				if got.SchemaDigest == wrong {
					t.Error("digest matched an incorrect domain or pair")
				}
			}
			lookedUp, err := declarativeschemas.Lookup(want.name)
			if err != nil || lookedUp != got {
				t.Errorf("lookup got %#v, %v; want %#v", lookedUp, err, got)
			}
		})
	}
}

func TestUnknownTool(t *testing.T) {
	for _, name := range []string{"", "Driver_list", "driver_list ", " driver_list", "driver", "driver_list_extra", "remote_targets", "app_exec", "../driver_list", "*"} {
		t.Run(name, func(t *testing.T) {
			got, err := declarativeschemas.Lookup(name)
			if !errors.Is(err, declarativeschemas.ErrUnknownTool) || got != (declarativeschemas.Tool{}) {
				t.Errorf("Lookup(%q) = %#v, %v", name, got, err)
			}
		})
	}
}

func TestCatalogIsolation(t *testing.T) {
	first, err := declarativeschemas.Catalog()
	if err != nil {
		t.Fatal(err)
	}
	original := first[0]
	lookup, err := declarativeschemas.Lookup(original.Name)
	if err != nil {
		t.Fatal(err)
	}
	first[0] = declarativeschemas.Tool{Name: "changed", InputSchema: "changed"}
	first = append(first[:1], declarativeschemas.Tool{Name: "appended"})
	lookup.Name = "changed lookup"
	lookup.OutputSchema = "changed lookup schema"
	fresh, err := declarativeschemas.Catalog()
	if err != nil {
		t.Fatal(err)
	}
	again, err := declarativeschemas.Lookup(original.Name)
	if err != nil {
		t.Fatal(err)
	}
	if len(fresh) != len(fixtures) || fresh[0] != original || fresh[1].Name != fixtures[1].name || again != original {
		t.Fatalf("mutation leaked: catalog %#v, lookup %#v", fresh, again)
	}
}
