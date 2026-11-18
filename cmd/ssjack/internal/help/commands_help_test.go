package help

import (
	"bytes"
	"strings"
	"testing"
)

func TestAppstoreHelpDocumentsSecretBoundaries(t *testing.T) {
	for _, topic := range []string{"appstore", "appstore setup", "appstore put", "appstore unlock"} {
		entry := findHelp(topic)
		if entry == nil {
			t.Fatalf("missing help topic %q", topic)
		}
		var output bytes.Buffer
		printCommandHelp(&output, entry)
		text := output.String()
		if !strings.Contains(text, "ssjack appstore") {
			t.Errorf("help topic %q lacks its command syntax", topic)
		}
	}
}
