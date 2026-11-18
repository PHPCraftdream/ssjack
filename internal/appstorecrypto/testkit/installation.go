// Package testkit holds non-production fixtures shared by appstorecrypto tests.
package testkit

import (
	"context"
	"crypto/sha256"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto/anchorfixture"
	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto/masterkey"
	"github.com/PHPCraftdream/ssjack/internal/appstoreentry"
	"github.com/PHPCraftdream/ssjack/internal/appstorefile"
	"github.com/PHPCraftdream/ssjack/internal/appstoreheader"
)

// InstallationDerive derives a master with a fast stand-in for the production KDF.
func InstallationDerive(ctx context.Context, h appstoreheader.Header, p []byte) (*masterkey.Master, error) {
	return masterkey.DeriveWith(ctx, h, p, func(password, salt []byte) []byte {
		input := append(append([]byte(nil), password...), salt...)
		sum := sha256.Sum256(input)
		clear(input)
		return append([]byte(nil), sum[:]...)
	})
}

// InstallationWriterFixture builds a directory, entry store and installation binding over a live anchor.
func InstallationWriterFixture(t *testing.T) (*appstorefile.Directory, *appstoreentry.Store, masterkey.Binding) {
	t.Helper()
	directory, store, parts := anchorfixture.InstallationAnchor(t)
	return directory, store, masterkey.Binding(parts)
}
