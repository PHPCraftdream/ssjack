// Package approval models owner-side encrypted approval records for
// registered applications stored inside the vault.
package approval

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// MaxApprovals bounds one vault's application approval set.
const MaxApprovals = 32

// MaxPathBytes bounds one stored application path.
const MaxPathBytes = 512

// appNamePattern mirrors internal/application/descriptor.go appName; it is
// replicated locally so this package never edits that package.
var appNamePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

var hashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// The route patterns replicate internal/application/application.go
// containerName and userName. Importing internal/application is not possible:
// it transitively reaches internal/vault through apptransport ->
// apptransport/internal/server -> appstorecrypto/ownereditor.
var (
	containerNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	userNamePattern      = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}$`)
)

// Record is one owner approval of one application build.
type Record struct {
	Name  string
	Path  string
	Hash  string
	Route string
}

// ValidateName applies the descriptor application-name rule.
func ValidateName(name string) error {
	if !appNamePattern.MatchString(name) {
		return fmt.Errorf("application name must match %s", appNamePattern.String())
	}
	return nil
}

// ValidatePath requires a clean absolute path within the size bound and free
// of control bytes.
func ValidatePath(path string) error {
	if path == "" || len(path) > MaxPathBytes {
		return errors.New("application path must be nonempty and within 512 bytes")
	}
	if hasControlByte(path) {
		return errors.New("application path must not contain control characters")
	}
	if !filepath.IsAbs(path) {
		return errors.New("application path must be absolute")
	}
	if path != filepath.Clean(path) {
		return errors.New("application path must be clean")
	}
	return nil
}

// hasControlByte rejects NUL and other C0 control characters plus DEL. Wire
// text arrives from JSON strings, so a control byte can only be smuggled in
// as an escaped sequence; such paths are never legitimate.
func hasControlByte(text string) bool {
	for i := 0; i < len(text); i++ {
		if text[i] < 0x20 || text[i] == 0x7f {
			return true
		}
	}
	return false
}

// ValidateHash requires a 32-byte SHA-256 digest in lowercase hex.
func ValidateHash(hash string) error {
	if !hashPattern.MatchString(hash) {
		return errors.New("application hash must be 64 lowercase hex characters")
	}
	return nil
}

// ValidateRouteSpec allows an empty spec (no route) and otherwise validates
// "incus:CONTAINER:USER" with the application package's rules; the stored spec
// must already be that canonical form.
func ValidateRouteSpec(spec string) error {
	if spec == "" {
		return nil
	}
	parts := strings.Split(spec, ":")
	if len(parts) != 3 || parts[0] != "incus" ||
		!containerNamePattern.MatchString(parts[1]) || !userNamePattern.MatchString(parts[2]) {
		return errors.New("application route must be canonical incus:CONTAINER:USER")
	}
	return nil
}

// Validate applies every stored-record rule. Name and Route are already
// regex-validated and cannot contain control bytes; Path is checked inside
// ValidatePath.
func (r Record) Validate() error {
	if hasControlByte(r.Name) || hasControlByte(r.Route) {
		return errors.New("application approval must not contain control characters")
	}
	if err := ValidateName(r.Name); err != nil {
		return err
	}
	if err := ValidatePath(r.Path); err != nil {
		return err
	}
	if err := ValidateHash(r.Hash); err != nil {
		return err
	}
	return ValidateRouteSpec(r.Route)
}

// ValidateSet accepts nil and validates the whole approval set.
func ValidateSet(records map[string]Record) error {
	if records == nil {
		return nil
	}
	if len(records) > MaxApprovals {
		return errors.New("too many application approvals")
	}
	paths := make(map[string]bool, len(records))
	for name, record := range records {
		if err := ValidateName(name); err != nil {
			return err
		}
		if record.Name != name {
			return errors.New("application approval key must equal the record name")
		}
		if err := record.Validate(); err != nil {
			return err
		}
		// Duplicate detection is exact-string-after-Clean: case-insensitive path
		// aliases are deliberately NOT folded, because later-slice startup matching
		// compares the scanner's canonical real path exactly, so an alias fails to
		// match and keeps needing review instead of silently granting approval.
		clean := filepath.Clean(record.Path)
		if paths[clean] {
			return errors.New("duplicate application path in approvals")
		}
		paths[clean] = true
	}
	return nil
}

// RecordMap emits the wire form: per name a map with path and hash and an
// optional route key.
func RecordMap(records map[string]Record) map[string]any {
	result := make(map[string]any, len(records))
	for name, record := range records {
		entry := map[string]any{"path": record.Path, "hash": record.Hash}
		if record.Route != "" {
			entry["route"] = record.Route
		}
		result[name] = entry
	}
	return result
}

// ValidateFields rejects unknown wire data strictly before typed decoding.
func ValidateFields(value any) error {
	entries, ok := value.(map[string]any)
	if !ok || len(entries) > MaxApprovals {
		return errors.New("invalid application approval fields")
	}
	for name, raw := range entries {
		if err := ValidateName(name); err != nil {
			return err
		}
		entry, ok := raw.(map[string]any)
		if !ok || (len(entry) != 2 && len(entry) != 3) {
			return errors.New("invalid application approval record fields")
		}
		for key, field := range entry {
			text, ok := field.(string)
			if !ok {
				return errors.New("invalid application approval record type")
			}
			switch key {
			case "path":
				if err := ValidatePath(text); err != nil {
					return err
				}
			case "hash":
				if err := ValidateHash(text); err != nil {
					return err
				}
			case "route":
				if err := ValidateRouteSpec(text); err != nil {
					return err
				}
			default:
				return errors.New("unknown application approval record field")
			}
		}
		if _, exists := entry["path"]; !exists {
			return errors.New("missing application approval path")
		}
		if _, exists := entry["hash"]; !exists {
			return errors.New("missing application approval hash")
		}
	}
	return nil
}

// SortedNames orders approval names for deterministic listing.
func SortedNames(records map[string]Record) []string {
	names := make([]string, 0, len(records))
	for name := range records {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
