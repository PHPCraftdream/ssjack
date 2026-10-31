//go:build !linux || !amd64

package main

import "testing"

func (f *deliveryFixture) deliveryConcurrentAcceptance(t *testing.T, ref string, fields map[string]string, artifacts string) {
	t.Fatal("concurrent delivery acceptance requires Linux/amd64")
}
