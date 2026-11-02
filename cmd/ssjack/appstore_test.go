package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestParseTextUnlockOptions(t *testing.T) {
	for _, tc := range []struct {
		name    string
		args    []string
		want    []string
		fd      int
		reverse bool
		enabled bool
		bad     bool
	}{
		{"hydrate", []string{"--text-mode", "hydrate", "--text-fd", "3", "harness", "-c"}, []string{"harness", "-c"}, 3, false, true, false},
		{"reverse", []string{"--text-mode", "reverse", "--text-fd", "1024", "harness"}, []string{"harness"}, 1024, true, true, false},
		{"ordinary", []string{"harness", "-c"}, []string{"harness", "-c"}, -1, false, false, false},
		{"no harness", []string{"--text-mode", "hydrate", "--text-fd", "3"}, nil, -1, false, true, true},
		{"bad mode", []string{"--text-mode", "other", "--text-fd", "3", "harness"}, nil, -1, false, true, true},
		{"bad descriptor", []string{"--text-mode", "hydrate", "--text-fd", "2", "harness"}, nil, -1, false, true, true},
		{"descriptor overflow", []string{"--text-mode", "reverse", "--text-fd", "1025", "harness"}, nil, -1, false, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, fd, reverse, enabled, err := parseTextUnlock(tc.args)
			if (err != nil) != tc.bad || fd != tc.fd || reverse != tc.reverse || enabled != tc.enabled || len(got) != len(tc.want) {
				t.Fatalf("parseTextUnlock = %v,%d,%t,%t,%v", got, fd, reverse, enabled, err)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("arg[%d]=%q want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestAppstoreCommandRoutingAndUsage(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"no operation", nil, "usage: ssjack appstore setup DIR | put DIR | inspect DIR | unlock [--text-mode hydrate|reverse --text-fd FD] HARNESS [ARGS...]"},
		{"setup arity", []string{"setup"}, "usage: ssjack appstore setup DIR"},
		{"setup extra argument", []string{"setup", "dir", "extra"}, "usage: ssjack appstore setup DIR"},
		{"put arity", []string{"put"}, "usage: ssjack appstore put DIR"},
		{"put extra argument", []string{"put", "dir", "extra"}, "usage: ssjack appstore put DIR"},
		{"inspect arity", []string{"inspect"}, "usage: ssjack appstore inspect DIR"},
		{"inspect extra argument", []string{"inspect", "dir", "extra"}, "usage: ssjack appstore inspect DIR"},
		{"unlock arity", []string{"unlock"}, "usage: ssjack appstore unlock [--text-mode hydrate|reverse --text-fd FD] HARNESS [ARGS...]"},
		{"unknown operation", []string{"unknown"}, "usage: ssjack appstore setup DIR | put DIR | inspect DIR | unlock [--text-mode hydrate|reverse --text-fd FD] HARNESS [ARGS...]"},
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
