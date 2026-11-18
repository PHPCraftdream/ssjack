package core

import (
	"crypto/rand"
	"encoding/hex"
	"strings"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
)

// Staging and probe names are prefix + 16 lowercase hex chars.
const (
	StagingPrefix = ".ssjack-transfer-"
	ProbePrefix   = ".ssjack-probe-"
)

// ShellQuote single-quotes s for POSIX sh, escaping embedded single quotes.
func ShellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// CheckRemotePath validates an absolute POSIX path. GNU sha256sum escapes
// backslash and newline in names on its output wire, which would make strict
// parsing ambiguous; remote trees therefore refuse backslashes.
func CheckRemotePath(p string, l transfercore.Limits) error {
	if err := transfercore.ValidateRemotePath(p, l); err != nil {
		return err
	}
	if strings.ContainsRune(p, '\\') {
		return transfercore.Fail(transfercore.ClassRefusedPath, "remote file names may not contain a backslash")
	}
	return nil
}

// NewRandomSuffix returns 16 lowercase hex chars from crypto/rand.
func NewRandomSuffix() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", transfercore.Fail(transfercore.ClassInternal, "could not generate a random name")
	}
	return hex.EncodeToString(b[:]), nil
}

func NewStagingName() (string, error) {
	suffix, err := NewRandomSuffix()
	if err != nil {
		return "", err
	}
	return StagingPrefix + suffix, nil
}

// ValidStagingName reports whether name matches StagingPrefix + 16 hex chars.
func ValidStagingName(name string) bool {
	if len(name) != len(StagingPrefix)+16 || !strings.HasPrefix(name, StagingPrefix) {
		return false
	}
	for i := len(StagingPrefix); i < len(name); i++ {
		c := name[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
