package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestAppstoreCommandRoutingAndUsage(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"no operation", nil, "usage: ssjack appstore setup DIR | put DIR | inspect DIR | unlock HARNESS [ARGS...]"},
		{"setup arity", []string{"setup"}, "usage: ssjack appstore setup DIR"},
		{"setup extra argument", []string{"setup", "dir", "extra"}, "usage: ssjack appstore setup DIR"},
		{"put arity", []string{"put"}, "usage: ssjack appstore put DIR"},
		{"put extra argument", []string{"put", "dir", "extra"}, "usage: ssjack appstore put DIR"},
		{"inspect arity", []string{"inspect"}, "usage: ssjack appstore inspect DIR"},
		{"inspect extra argument", []string{"inspect", "dir", "extra"}, "usage: ssjack appstore inspect DIR"},
		{"unlock arity", []string{"unlock"}, "usage: ssjack appstore unlock HARNESS [ARGS...]"},
		{"unknown operation", []string{"unknown"}, "usage: ssjack appstore setup DIR | put DIR | inspect DIR | unlock HARNESS [ARGS...]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, err := run(context.Background(), append([]string{"appstore"}, tc.args...))
			if code == 0 || err == nil || err.Error() != tc.want {
				t.Fatalf("runAppstore(%v) = %d, %v; want usage %q", tc.args, code, err, tc.want)
			}
		})
	}
}

func TestAppstoreHelpDocumentsSecretBoundaries(t *testing.T) {
	for _, topic := range []string{"appstore", "appstore setup", "appstore put"} {
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
