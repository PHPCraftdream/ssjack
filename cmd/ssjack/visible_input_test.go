package main

import (
	"strings"
	"testing"
)

func TestVisibleInputReadsOneLineWithoutReadAhead(t *testing.T) {
	for _, ending := range []string{"\n", "\r\n"} {
		input := strings.NewReader("agent" + ending + "next secret\n")
		line, err := readVisibleLine(input, false)
		if err != nil || string(line) != "agent" {
			t.Fatalf("visible usage: %q %v", line, err)
		}
		remaining := make([]byte, input.Len())
		if _, err := input.Read(remaining); err != nil || string(remaining) != "next secret\n" {
			t.Fatal("visible input consumed the following prompt's input")
		}
	}
}

func TestVisibleInputBoundsAndDefaults(t *testing.T) {
	for _, tc := range []struct {
		text       string
		allowEmpty bool
		valid      bool
	}{
		{"\n", true, true},
		{"\r\n", true, true},
		{"\n", false, false},
		{"mcp\n", false, true},
		{"mcp", false, false},
		{strings.Repeat("x", 16384) + "\r\n", false, true},
		{strings.Repeat("x", 16385) + "\n", false, false},
	} {
		_, err := readVisibleLine(strings.NewReader(tc.text), tc.allowEmpty)
		if (err == nil) != tc.valid {
			t.Fatalf("visible input length %d allowEmpty=%t: %v", len(tc.text), tc.allowEmpty, err)
		}
	}
}
