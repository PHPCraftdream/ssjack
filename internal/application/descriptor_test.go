package application

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func exeSuffix() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}

// toolPath is the fixture executable inside every descriptor directory.
var toolPath = "bin/tool" + exeSuffix()

func quoteJSON(t *testing.T, value string) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func validDescriptor(extra string) string {
	return `{"format":"ssjack-app-v1","name":"synthetic","launch":{"executable":"` + toolPath + `"}` + extra + `}`
}

func launchDescriptor(launch string) string {
	return `{"format":"ssjack-app-v1","name":"synthetic","launch":` + launch + `}`
}

// descriptorDir creates a directory with never-executed fixture programs and
// the given descriptor bytes.
func descriptorDir(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{"bin", "work"} {
		if err := os.Mkdir(filepath.Join(dir, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for name, mode := range map[string]os.FileMode{
		"bin/tool" + exeSuffix(): 0o700,
		"bin/plain":              0o600,
		"bin/plain.txt":          0o600,
	} {
		if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(name)), []byte("fixture, never executed"), mode); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, DescriptorFile), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func canonical(t *testing.T, path string) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

func expectRefusal(t *testing.T, dir, want string) {
	t.Helper()
	app, err := LoadDescriptor(dir)
	if err == nil {
		t.Fatalf("accepted, want %q: %+v", want, app)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("refused with %q, want %q", err, want)
	}
}

func TestDescriptorRejectsOwnerRoute(t *testing.T) {
	t.Run("descriptor_rejects_route_field", func(t *testing.T) {
		dir := descriptorDir(t, validDescriptor(`,"route":"incus:c:u"`))
		if _, err := LoadDescriptor(dir); err == nil || !strings.Contains(err.Error(), "unknown field") {
			t.Fatal("descriptor-controlled route accepted")
		}
	})
}

func TestDescriptorValid(t *testing.T) {
	raw := `{"format":"ssjack-app-v1","name":"synthetic-app","launch":{"executable":"` + toolPath + `","args":["entry.js","--flag"]},"workdir":"work","commands":{"observational":["status","inspect"],"refused":["serve"]}}`
	dir := descriptorDir(t, raw)
	app, err := LoadDescriptor(dir)
	if err != nil {
		t.Fatal(err)
	}
	root := canonical(t, dir)
	want := App{
		Name:          "synthetic-app",
		Directory:     root,
		Workdir:       canonical(t, filepath.Join(root, "work")),
		Executable:    canonical(t, filepath.Join(root, "bin", "tool"+exeSuffix())),
		Args:          []string{"entry.js", "--flag"},
		Observational: []string{"status", "inspect"},
		Refused:       []string{"serve"},
	}
	if !reflect.DeepEqual(app, want) {
		t.Fatalf("descriptor resolved to %+v, want %+v", app, want)
	}
	manager, err := New(context.Background(), &Options{Apps: []App{app}, Profile: "fixed", Runner: discardRunner})
	if err != nil {
		t.Fatalf("a loaded descriptor was refused by registration: %v", err)
	}
	manager.Close()
}

func TestDescriptorMinimalAndBoundaryAccepted(t *testing.T) {
	dir := descriptorDir(t, validDescriptor(""))
	app, err := LoadDescriptor(dir)
	if err != nil {
		t.Fatal(err)
	}
	if app.Name != "synthetic" || app.Workdir != app.Directory || len(app.Args) != 0 || len(app.Observational) != 0 || len(app.Refused) != 0 {
		t.Fatalf("defaults: %+v", app)
	}
	raw := validDescriptor("")
	padded := raw + strings.Repeat(" ", maxDescriptorSize-len(raw))
	if len(padded) != maxDescriptorSize {
		t.Fatal("fixture is not exactly at the size limit")
	}
	if _, err := LoadDescriptor(descriptorDir(t, padded)); err != nil {
		t.Fatalf("descriptor at the size limit refused: %v", err)
	}
	for _, spelling := range []string{"./" + toolPath, "work/../" + toolPath} {
		app, err := LoadDescriptor(descriptorDir(t, launchDescriptor(`{"executable":"`+spelling+`"}`)))
		if err != nil || filepath.Base(app.Executable) != "tool"+exeSuffix() {
			t.Fatalf("relative executable %q: %+v %v", spelling, app, err)
		}
	}
	names := []string{"a", "z9", "a-b-c", strings.Repeat("a", 32)}
	for _, name := range names {
		raw := strings.Replace(validDescriptor(""), `"synthetic"`, `"`+name+`"`, 1)
		if app, err := LoadDescriptor(descriptorDir(t, raw)); err != nil || app.Name != name {
			t.Fatalf("name %q: %v", name, err)
		}
	}
}

func TestDescriptorRefusals(t *testing.T) {
	absolute := quoteJSON(t, t.TempDir())
	var commandsOverLimit []string
	for i := 0; i <= maxCommands; i++ {
		commandsOverLimit = append(commandsOverLimit, "c"+strings.Repeat("a", i%5)+strings.Repeat("b", i/5))
	}
	overLimit, err := json.Marshal(commandsOverLimit)
	if err != nil {
		t.Fatal(err)
	}
	oversizedArgs := `["` + strings.Repeat("a", 1000) + `","` + strings.Repeat("a", 1000) + `","` + strings.Repeat("a", 1000) + `","` + strings.Repeat("a", 1000) + `","` + strings.Repeat("a", 1000) + `"]`
	manyArgs := `[` + strings.TrimSuffix(strings.Repeat(`"a",`, maxArgs+1), ",") + `]`
	plain, plainWant := "bin/plain", "not executable"
	if runtime.GOOS == "windows" {
		plain, plainWant = "bin/plain.txt", "native .exe"
	}
	for _, tc := range []struct{ name, raw, want string }{
		{"unknown field", validDescriptor(`,"extra":1`), "unknown field"},
		{"unknown launch field", launchDescriptor(`{"executable":"` + toolPath + `","shell":true}`), "unknown field"},
		{"unknown commands field", validDescriptor(`,"commands":{"allowed":["x"]}`), "unknown field"},
		{"differently cased field", `{"format":"ssjack-app-v1","Name":"synthetic","launch":{"executable":"` + toolPath + `"}}`, "unknown field"},
		{"duplicate field", `{"format":"ssjack-app-v1","name":"a","name":"b","launch":{"executable":"` + toolPath + `"}}`, "repeats field"},
		{"trailing data", validDescriptor("") + ` {}`, "trailing data"},
		{"array", `[]`, "valid JSON object"},
		{"empty file", ``, "valid JSON object"},
		{"not JSON", `format=ssjack-app-v1`, "valid JSON object"},
		{"truncated", `{"format":"ssjack-app-v1"`, "valid JSON object"},
		{"invalid UTF-8", strings.Replace(validDescriptor(""), `"synthetic"`, "\"syn\xffthetic\"", 1), "UTF-8"},
		{"oversize", validDescriptor("") + strings.Repeat(" ", maxDescriptorSize), "too large"},
		{"wrong format", strings.Replace(validDescriptor(""), "ssjack-app-v1", "ssjack-app-v2", 1), "format must be"},
		{"missing format", `{"name":"synthetic","launch":{"executable":"` + toolPath + `"}}`, "format must be"},
		{"missing name", `{"format":"ssjack-app-v1","launch":{"executable":"` + toolPath + `"}}`, "requires name"},
		{"uppercase name", strings.Replace(validDescriptor(""), `"synthetic"`, `"Synthetic"`, 1), "name must match"},
		{"leading digit name", strings.Replace(validDescriptor(""), `"synthetic"`, `"1app"`, 1), "name must match"},
		{"name with space", strings.Replace(validDescriptor(""), `"synthetic"`, `"a b"`, 1), "name must match"},
		{"name with slash", strings.Replace(validDescriptor(""), `"synthetic"`, `"a/b"`, 1), "name must match"},
		{"empty name", strings.Replace(validDescriptor(""), `"synthetic"`, `""`, 1), "name must match"},
		{"long name", strings.Replace(validDescriptor(""), `"synthetic"`, `"`+strings.Repeat("a", 33)+`"`, 1), "name must match"},
		{"null name", strings.Replace(validDescriptor(""), `"synthetic"`, `null`, 1), "name must match"},
		{"missing launch", `{"format":"ssjack-app-v1","name":"synthetic"}`, "requires launch"},
		{"launch not an object", `{"format":"ssjack-app-v1","name":"synthetic","launch":"tool"}`, "valid JSON object"},
		{"missing executable", launchDescriptor(`{}`), "requires launch.executable"},
		{"empty executable", launchDescriptor(`{"executable":""}`), "requires launch.executable"},
		{"null executable", launchDescriptor(`{"executable":null}`), "bounded text string"},
		{"numeric executable", launchDescriptor(`{"executable":5}`), "bounded text string"},
		{"shim .cmd", launchDescriptor(`{"executable":"bin/tool.cmd"}`), "command shim"},
		{"shim .BAT", launchDescriptor(`{"executable":"bin/TOOL.BAT"}`), "command shim"},
		{"shim on PATH", launchDescriptor(`{"executable":"tool.bat"}`), "command shim"},
		{"missing executable file", launchDescriptor(`{"executable":"bin/absent` + exeSuffix() + `"}`), "unavailable"},
		{"directory executable", launchDescriptor(`{"executable":"./bin"}`), "regular file"},
		{"absolute directory executable", launchDescriptor(`{"executable":` + absolute + `}`), "regular file"},
		{"unexecutable file", launchDescriptor(`{"executable":"` + plain + `"}`), plainWant},
		{"too many args", launchDescriptor(`{"executable":"` + toolPath + `","args":` + manyArgs + `}`), "bounded list"},
		{"oversized args", launchDescriptor(`{"executable":"` + toolPath + `","args":` + oversizedArgs + `}`), "too large"},
		{"argument with NUL", launchDescriptor(`{"executable":"` + toolPath + `","args":["a\u0000b"]}`), "invalid entry"},
		{"argument with newline", launchDescriptor(`{"executable":"` + toolPath + `","args":["a\nb"]}`), "invalid entry"},
		{"null argument", launchDescriptor(`{"executable":"` + toolPath + `","args":[null]}`), "invalid entry"},
		{"numeric argument", launchDescriptor(`{"executable":"` + toolPath + `","args":[1]}`), "bounded list"},
		{"string args", launchDescriptor(`{"executable":"` + toolPath + `","args":"x"}`), "bounded list"},
		{"null args", launchDescriptor(`{"executable":"` + toolPath + `","args":null}`), "bounded list"},
		{"absolute workdir", validDescriptor(`,"workdir":` + absolute), "relative to the application directory"},
		{"parent workdir", validDescriptor(`,"workdir":".."`), "inside the application directory"},
		{"escaping workdir", validDescriptor(`,"workdir":"work/../.."`), "inside the application directory"},
		{"missing workdir", validDescriptor(`,"workdir":"absent"`), "unavailable"},
		{"file workdir", validDescriptor(`,"workdir":"` + toolPath + `"`), "must be a directory"},
		{"empty workdir", validDescriptor(`,"workdir":""`), "must not be empty"},
		{"null workdir", validDescriptor(`,"workdir":null`), "bounded text string"},
		{"numeric workdir", validDescriptor(`,"workdir":1`), "bounded text string"},
		{"commands not an object", validDescriptor(`,"commands":[]`), "valid JSON object"},
		{"null commands", validDescriptor(`,"commands":null`), "valid JSON object"},
		{"uppercase command", validDescriptor(`,"commands":{"observational":["Status"]}`), "invalid entry"},
		{"option as command", validDescriptor(`,"commands":{"refused":["--stdin"]}`), "invalid entry"},
		{"duplicate command", validDescriptor(`,"commands":{"observational":["status","status"]}`), "repeats a command"},
		{"both classes", validDescriptor(`,"commands":{"observational":["status"],"refused":["status"]}`), "both observational and refused"},
		{"too many commands", validDescriptor(`,"commands":{"refused":` + string(overLimit) + `}`), "bounded list"},
		{"commands string", validDescriptor(`,"commands":{"observational":"status"}`), "bounded list"},
		{"null command list", validDescriptor(`,"commands":{"refused":null}`), "bounded list"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			expectRefusal(t, descriptorDir(t, tc.raw), tc.want)
		})
	}
}

func TestDescriptorDirectoryRefusals(t *testing.T) {
	expectRefusal(t, "", "directory is required")
	expectRefusal(t, filepath.Join(t.TempDir(), "missing"), "unavailable")
	expectRefusal(t, t.TempDir(), "missing")
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	expectRefusal(t, file, "requires a directory")
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, DescriptorFile), 0o700); err != nil {
		t.Fatal(err)
	}
	expectRefusal(t, dir, "regular file")
}

func TestDescriptorExecutableAbsoluteAndPathLookup(t *testing.T) {
	program, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	app, err := LoadDescriptor(descriptorDir(t, launchDescriptor(`{"executable":`+quoteJSON(t, program)+`}`)))
	if err != nil || app.Executable != canonical(t, program) {
		t.Fatalf("absolute executable: %+v %v", app, err)
	}
	pathDir := t.TempDir()
	onPath := filepath.Join(pathDir, "pathtool"+exeSuffix())
	if err := os.WriteFile(onPath, []byte("fixture, never executed"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", pathDir)
	dir := descriptorDir(t, launchDescriptor(`{"executable":"pathtool"}`))
	if err := os.WriteFile(filepath.Join(dir, "pathtool"+exeSuffix()), []byte("decoy, never executed"), 0o700); err != nil {
		t.Fatal(err)
	}
	app, err = LoadDescriptor(dir)
	if err != nil || app.Executable != canonical(t, onPath) {
		t.Fatalf("a bare executable name must be resolved on PATH, not in the application directory: %+v %v", app, err)
	}
	expectRefusal(t, descriptorDir(t, launchDescriptor(`{"executable":"absent-tool"}`)), "not found on PATH")
}

func TestParseDescriptorBuffer(t *testing.T) {
	t.Run("ParseDescriptorBuffer matches LoadDescriptor", func(t *testing.T) {
		dir := descriptorDir(t, validDescriptor(`,"workdir":"work","commands":{"observational":["status"],"refused":["serve"]}`))
		app1, err := LoadDescriptor(dir)
		if err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(filepath.Join(dir, DescriptorFile))
		if err != nil {
			t.Fatal(err)
		}
		app2, err := ParseDescriptorBuffer(data, canonical(t, dir))
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(app1, app2) {
			t.Fatalf("buffer parse differs: %+v != %+v", app2, app1)
		}
	})
	t.Run("ParseDescriptorBuffer rejects oversize and invalid", func(t *testing.T) {
		dir := descriptorDir(t, validDescriptor(""))
		root := canonical(t, dir)
		valid := launchDescriptor(`{"executable":` + quoteJSON(t, mustExecutable(t)) + `}`)
		oversize := []byte(valid[:len(valid)-1] + strings.Repeat(" ", 16*1024+1-len(valid)) + "}")
		if len(oversize) != 16*1024+1 {
			t.Fatal("oversize_fixture_wrong_length")
		}
		if _, err := ParseDescriptorBuffer(oversize, root); err == nil || !strings.Contains(err.Error(), "too large") {
			t.Fatalf("oversize_buffer_error=%v", err)
		}
		if _, err := ParseDescriptorBuffer([]byte("not json"), root); err == nil {
			t.Fatal("invalid_buffer_accepted")
		}
		data := []byte(launchDescriptor(`{"executable":` + quoteJSON(t, mustExecutable(t)) + `}`))
		if _, err := ParseDescriptorBuffer(data, root); err != nil {
			t.Fatalf("valid_buffer_refused: %v", err)
		}
	})
}

func mustExecutable(t *testing.T) string {
	t.Helper()
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return path
}
