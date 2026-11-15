package transferlocal

import (
	"strings"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
)

const stagingPrefix = ".ssjack-transfer-"

// validateLocalComponent rejects a single path component under the uniform
// local rules. These rules hold on every OS so archives and destinations are
// interchangeable between platforms.
func validateLocalComponent(name string) error {
	if name == "" {
		return transfercore.Fail(transfercore.ClassRefusedPath, "path component is empty")
	}
	if name == "." || name == ".." {
		return transfercore.Fail(transfercore.ClassRefusedPath, "path contains an empty, current or parent component")
	}
	if strings.ContainsRune(name, ':') {
		return transfercore.Fail(transfercore.ClassRefusedPath, "path component contains a colon")
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return transfercore.Fail(transfercore.ClassRefusedPath, "path contains a control character")
		}
	}
	if strings.HasSuffix(name, ".") || strings.HasSuffix(name, " ") {
		return transfercore.Fail(transfercore.ClassRefusedPath, "path component ends with a dot or space")
	}
	if reservedDeviceName(name) {
		return transfercore.Fail(transfercore.ClassRefusedPath, "path component is a reserved device name")
	}
	return nil
}

// reservedDeviceName reports Windows device names such as CON, NUL and COM1,
// which must be refused on every OS so names stay portable.
func reservedDeviceName(name string) bool {
	base := name
	if i := strings.IndexByte(name, '.'); i >= 0 {
		base = name[:i]
	}
	for _, device := range []string{
		"CON", "PRN", "AUX", "NUL",
		"COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
		"LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
	} {
		if strings.EqualFold(base, device) {
			return true
		}
	}
	return false
}

// validateLocalRelPath validates a root-relative slash-separated path:
// transfercore.ValidateRelPath first, then the local component rules.
func validateLocalRelPath(p string, limits transfercore.Limits) error {
	if err := transfercore.ValidateRelPath(p, limits); err != nil {
		return err
	}
	for _, part := range strings.Split(p, "/") {
		if err := validateLocalComponent(part); err != nil {
			return err
		}
	}
	return nil
}

// forbiddenRelPath reports whether any component is a forbidden control
// directory such as .git or .ssh.
func forbiddenRelPath(p string) bool {
	for _, part := range strings.Split(p, "/") {
		if transfercore.ForbiddenLocalComponent(part) {
			return true
		}
	}
	return false
}

// splitRelName splits at the last '/'. dir is "" when there is no separator;
// dir "" means the root itself.
func splitRelName(p string) (dir, base string) {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[:i], p[i+1:]
	}
	return "", p
}

// foldKey is the case-folding key used for collision detection on every OS,
// including case-sensitive ones, so extraction cannot shadow existing names.
func foldKey(p string) string {
	return strings.ToLower(p)
}

// joinRel joins a relative prefix and a component with '/'. dir "" means the
// root itself.
func joinRel(dir, name string) string {
	if dir == "" {
		return name
	}
	return dir + "/" + name
}
