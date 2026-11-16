package application

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"unicode/utf8"
)

const (
	// DescriptorFile is the fixed descriptor name inside a registered directory.
	DescriptorFile = "ssjack-app.json"
	// DescriptorFormat is the only accepted descriptor format.
	DescriptorFormat = "ssjack-app-v1"

	maxDescriptorSize = 16 * 1024
	maxTextLength     = 1024
	maxArgs           = 16
	maxArgsSize       = 4096
	maxCommands       = 64
)

var appName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// App is one validated registered application. Every path is absolute.
type App struct {
	Name          string
	Directory     string
	Workdir       string
	Executable    string
	Args          []string
	Observational []string
	Refused       []string
}

type descriptor struct {
	name          string
	executable    string
	args          []string
	workdir       string
	observational []string
	refused       []string
}

var errDescriptorJSON = errors.New("application descriptor is not a valid JSON object")

// LoadDescriptor validates DIR and its ssjack-app.json without executing
// anything, and resolves the launch to absolute paths.
func LoadDescriptor(directory string) (App, error) {
	var zero App
	if directory == "" {
		return zero, errors.New("application directory is required")
	}
	root, err := filepath.Abs(directory)
	if err != nil {
		return zero, errors.New("invalid application directory")
	}
	info, err := os.Lstat(root)
	if err != nil {
		return zero, errors.New("application directory is unavailable")
	}
	if info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
		return zero, errors.New("application directory must not be a symlink or reparse point")
	}
	if !info.IsDir() {
		return zero, errors.New("application registration requires a directory")
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return zero, errors.New("application directory is unavailable")
	}
	data, err := readDescriptor(filepath.Join(root, DescriptorFile))
	if err != nil {
		return zero, err
	}
	parsed, err := parseDescriptor(data)
	if err != nil {
		return zero, err
	}
	executable, err := resolveExecutable(root, parsed.executable)
	if err != nil {
		return zero, err
	}
	workdir, err := resolveWorkdir(root, parsed.workdir)
	if err != nil {
		return zero, err
	}
	return App{
		Name:          parsed.name,
		Directory:     root,
		Workdir:       workdir,
		Executable:    executable,
		Args:          parsed.args,
		Observational: parsed.observational,
		Refused:       parsed.refused,
	}, nil
}

func readDescriptor(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, errors.New("application descriptor " + DescriptorFile + " is missing")
	}
	if info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
		return nil, errors.New("application descriptor must not be a symlink or reparse point")
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("application descriptor must be a regular file")
	}
	if info.Size() > maxDescriptorSize {
		return nil, errors.New("application descriptor is too large")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("application descriptor is unavailable")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, errors.New("application descriptor changed while it was opened")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxDescriptorSize+1))
	if err != nil {
		return nil, errors.New("application descriptor is unavailable")
	}
	if len(data) > maxDescriptorSize {
		return nil, errors.New("application descriptor is too large")
	}
	return data, nil
}

// exactObject splits one JSON object, refusing unknown, duplicate and
// differently cased keys, trailing data and any non-object value.
func exactObject(raw []byte, allowed ...string) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return nil, errDescriptorJSON
	}
	fields := make(map[string]json.RawMessage)
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			return nil, errDescriptorJSON
		}
		known := false
		for _, name := range allowed {
			known = known || name == key
		}
		if !known {
			return nil, fmt.Errorf("application descriptor has an unknown field %.40q", key)
		}
		if _, duplicate := fields[key]; duplicate {
			return nil, fmt.Errorf("application descriptor repeats field %q", key)
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return nil, errDescriptorJSON
		}
		fields[key] = value
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
		return nil, errDescriptorJSON
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, errors.New("application descriptor has trailing data")
	}
	return fields, nil
}

func validText(value string, limit int) bool {
	if len(value) > limit || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func textField(raw json.RawMessage, field string, limit int) (string, error) {
	var value string
	if isNull(raw) || json.Unmarshal(raw, &value) != nil || !validText(value, limit) {
		return "", fmt.Errorf("application descriptor field %s must be a bounded text string", field)
	}
	return value, nil
}

func listField(raw json.RawMessage, field string, limit, size int, valid func(string) bool) ([]string, error) {
	var items []*string
	if isNull(raw) || json.Unmarshal(raw, &items) != nil || len(items) > limit {
		return nil, fmt.Errorf("application descriptor field %s must be a bounded list of strings", field)
	}
	values := make([]string, 0, len(items))
	total := 0
	for _, item := range items {
		if item == nil || !validText(*item, maxTextLength) || !valid(*item) {
			return nil, fmt.Errorf("application descriptor field %s has an invalid entry", field)
		}
		total += len(*item)
		values = append(values, *item)
	}
	if total > size {
		return nil, fmt.Errorf("application descriptor field %s is too large", field)
	}
	return values, nil
}

func commandList(raw json.RawMessage, field string) ([]string, error) {
	values, err := listField(raw, field, maxCommands, maxCommands*64, commandName.MatchString)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		if seen[value] {
			return nil, fmt.Errorf("application descriptor field %s repeats a command", field)
		}
		seen[value] = true
	}
	return values, nil
}

func parseDescriptor(data []byte) (descriptor, error) {
	var parsed descriptor
	if !utf8.Valid(data) {
		return parsed, errors.New("application descriptor is not valid UTF-8")
	}
	top, err := exactObject(data, "format", "name", "launch", "workdir", "commands")
	if err != nil {
		return parsed, err
	}
	format, err := textField(top["format"], "format", 64)
	if top["format"] == nil || err != nil || format != DescriptorFormat {
		return parsed, errors.New("application descriptor format must be " + DescriptorFormat)
	}
	if top["name"] == nil {
		return parsed, errors.New("application descriptor requires name")
	}
	if parsed.name, err = textField(top["name"], "name", 32); err != nil || !appName.MatchString(parsed.name) {
		return parsed, errors.New("application descriptor name must match " + appName.String())
	}
	if top["launch"] == nil {
		return parsed, errors.New("application descriptor requires launch")
	}
	launch, err := exactObject(top["launch"], "executable", "args")
	if err != nil {
		return parsed, err
	}
	if launch["executable"] == nil {
		return parsed, errors.New("application descriptor requires launch.executable")
	}
	if parsed.executable, err = textField(launch["executable"], "launch.executable", maxTextLength); err != nil {
		return parsed, err
	}
	if parsed.executable == "" {
		return parsed, errors.New("application descriptor requires launch.executable")
	}
	if launch["args"] != nil {
		if parsed.args, err = listField(launch["args"], "launch.args", maxArgs, maxArgsSize, func(string) bool { return true }); err != nil {
			return parsed, err
		}
	}
	if top["workdir"] != nil {
		if parsed.workdir, err = textField(top["workdir"], "workdir", maxTextLength); err != nil {
			return parsed, err
		}
		if parsed.workdir == "" {
			return parsed, errors.New("application descriptor field workdir must not be empty")
		}
	}
	if top["commands"] != nil {
		commands, err := exactObject(top["commands"], "observational", "refused")
		if err != nil {
			return parsed, err
		}
		if commands["observational"] != nil {
			if parsed.observational, err = commandList(commands["observational"], "commands.observational"); err != nil {
				return parsed, err
			}
		}
		if commands["refused"] != nil {
			if parsed.refused, err = commandList(commands["refused"], "commands.refused"); err != nil {
				return parsed, err
			}
		}
		refused := nameSet(parsed.refused)
		for _, name := range parsed.observational {
			if refused[name] {
				return parsed, errors.New("application descriptor lists a command as both observational and refused")
			}
		}
	}
	return parsed, nil
}

func hasShimExtension(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".cmd", ".bat":
		return true
	}
	return false
}

func hasSeparator(value string) bool {
	return strings.ContainsRune(value, '/') || strings.ContainsRune(value, os.PathSeparator)
}

// resolveExecutable returns the canonical native executable. An absolute path
// is used as is, a path with a separator is relative to root, and a bare name
// is looked up once on PATH. A shell or command shim is never accepted.
func resolveExecutable(root, value string) (string, error) {
	if hasShimExtension(value) {
		return "", errors.New("application executable must be a native program, not a command shim")
	}
	var path string
	switch {
	case filepath.IsAbs(value):
		path = value
	case filepath.VolumeName(value) != "":
		return "", errors.New("application executable path is invalid")
	case !hasSeparator(value):
		found, err := exec.LookPath(value)
		if err != nil {
			return "", errors.New("application executable was not found on PATH")
		}
		path = found
	default:
		path = filepath.Join(root, filepath.FromSlash(value))
	}
	path, err := filepath.Abs(path)
	if err != nil {
		return "", errors.New("application executable path is invalid")
	}
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		return "", errors.New("application executable is unavailable")
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return "", errors.New("application executable must be a regular file")
	}
	if hasShimExtension(path) {
		return "", errors.New("application executable must be a native program, not a command shim")
	}
	if runtime.GOOS == "windows" {
		if !strings.EqualFold(filepath.Ext(path), ".exe") {
			return "", errors.New("application executable must be a native .exe")
		}
	} else if info.Mode().Perm()&0o111 == 0 {
		return "", errors.New("application executable is not executable")
	}
	return path, nil
}

// resolveWorkdir returns the canonical working directory, which must stay
// inside the application directory.
func resolveWorkdir(root, value string) (string, error) {
	if value == "" {
		return root, nil
	}
	if filepath.IsAbs(value) || filepath.VolumeName(value) != "" {
		return "", errors.New("application workdir must be relative to the application directory")
	}
	path, err := filepath.EvalSymlinks(filepath.Join(root, filepath.FromSlash(value)))
	if err != nil {
		return "", errors.New("application workdir is unavailable")
	}
	relative, err := filepath.Rel(root, path)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		return "", errors.New("application workdir must stay inside the application directory")
	}
	if !directoryExists(path) {
		return "", errors.New("application workdir must be a directory")
	}
	return path, nil
}

func isNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}
