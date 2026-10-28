// Package immutableexec provides an isolated, bounded immutable executable binder.
// It is not integrated into production launch paths.
package immutableexec

import (
	"errors"
	"strings"
)

var ErrUnsupported = errors.New("immutable executable binding unsupported")
var ErrInvalidEnvironment = errors.New("invalid or unsafe environment")

// Environment is intentionally restricted to reviewed, non-secret locale and terminal settings.
var safeEnvironment = map[string]bool{"LANG": true, "LC_ALL": true, "LC_CTYPE": true, "TZ": true, "TERM": true}

func validateEnvironment(env []string) error {
	if env == nil {
		return ErrInvalidEnvironment
	}
	seen := make(map[string]bool, len(env))
	for _, entry := range env {
		key, value, ok := strings.Cut(entry, "=")
		if !ok || key == "" || strings.ContainsAny(key, "=\x00") || strings.ContainsRune(value, 0) || !safeEnvironment[key] || seen[key] {
			return ErrInvalidEnvironment
		}
		seen[key] = true
	}
	return nil
}
