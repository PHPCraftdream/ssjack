//go:build linux && amd64

package main

import (
	"context"
	"strings"
	"testing"
)

func TestStreamingRegistrationUsesExplicitRootInteractiveBoundary(t *testing.T) {
	for _, command := range []string{"register-stream", "register-reverse-stream"} {
		code, err := runTextAdapterCommand(context.Background(), "unused", "main", []string{command, "forbidden-caller-metadata"})
		if code != 1 || err == nil || (!strings.Contains(err.Error(), "requires root") && !strings.Contains(err.Error(), "unavailable in broker sessions") && !strings.Contains(err.Error(), "entered interactively")) {
			t.Fatal("streaming registration bypassed the existing root/terminal boundary or did not dispatch")
		}
	}
	code, err := runTextAdapterCommand(context.Background(), "unused", "main", []string{"revoke-stream"})
	if code != 1 || err == nil || (!strings.Contains(err.Error(), "requires root") && !strings.Contains(err.Error(), "unavailable in broker sessions") && !strings.Contains(err.Error(), "revoke-stream GRANT_ID")) {
		t.Fatal("streaming revocation did not use its explicit namespace")
	}
}

func TestStreamingServeRequiresHarnessBeforeUnlock(t *testing.T) {
	code, err := runTextAdapterCommand(context.Background(), "unused", "main", []string{"serve-stream", "grant"})
	if code != 1 || err == nil || !strings.Contains(err.Error(), "serve-stream") {
		t.Fatal("streaming serve reached unlock without a harness")
	}
	code, err = runTextStreamHarness(context.Background(), nil, "hydrate-stream-v2", "grant", "profile", "binding", nil, nil)
	if code != 1 || err == nil || !strings.Contains(err.Error(), "explicit harness") {
		t.Fatal("streaming harness construction accepted missing command")
	}
}

func TestNamedStartupCannotSilentlyScopeStreamRegistration(t *testing.T) {
	for _, command := range []string{"register-stream", "register-reverse-stream", "revoke-stream"} {
		if namedCommandAllowed([]string{"text-adapter", command}) {
			t.Fatal("named SSH selector was silently ignored by root registration")
		}
	}
}
