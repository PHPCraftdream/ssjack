package transferremote

import (
	"crypto/rand"
	"encoding/hex"
	"strings"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
)

// Staging and probe names are prefix + 16 lowercase hex chars.
const (
	stagingPrefix = ".ssjack-transfer-"
	probePrefix   = ".ssjack-probe-"
)

// shellQuote single-quotes s for POSIX sh, escaping embedded single quotes.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// checkRemotePath validates an absolute POSIX path. GNU sha256sum escapes
// backslash and newline in names on its output wire, which would make strict
// parsing ambiguous; remote trees therefore refuse backslashes.
func checkRemotePath(p string, l transfercore.Limits) error {
	if err := transfercore.ValidateRemotePath(p, l); err != nil {
		return err
	}
	if strings.ContainsRune(p, '\\') {
		return transfercore.Fail(transfercore.ClassRefusedPath, "remote file names may not contain a backslash")
	}
	return nil
}

// newRandomSuffix returns 16 lowercase hex chars from crypto/rand.
func newRandomSuffix() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", transfercore.Fail(transfercore.ClassInternal, "could not generate a random name")
	}
	return hex.EncodeToString(b[:]), nil
}

func newStagingName() (string, error) {
	suffix, err := newRandomSuffix()
	if err != nil {
		return "", err
	}
	return stagingPrefix + suffix, nil
}

// validStagingName reports whether name matches stagingPrefix + 16 hex chars.
func validStagingName(name string) bool {
	if len(name) != len(stagingPrefix)+16 || !strings.HasPrefix(name, stagingPrefix) {
		return false
	}
	for i := len(stagingPrefix); i < len(name); i++ {
		c := name[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
