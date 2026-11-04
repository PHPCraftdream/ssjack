package main

import (
	"context"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"

	"github.com/PHPCraftdream/ssjack/internal/ownerdb"
	"github.com/PHPCraftdream/ssjack/internal/ownertui"
)

const (
	importKeyTab   = 9
	importKeyEnter = 13
	importKeyEsc   = 27
)

// importDriver feeds Bubble Tea messages straight into the owner model's
// Update (a message-level model driver). There is no tea.Program and no
// terminal here; the real terminal is covered by owner_import.py. Tick
// commands are never executed, so the model only changes through this driver.
type importDriver struct {
	t     *testing.T
	model *ownertui.Model
}

func newImportDriver(t *testing.T, ctx context.Context, manager *ownerdb.Manager) *importDriver {
	t.Helper()
	d := &importDriver{t: t, model: ownertui.New(ctx, manager)}
	// A tall window keeps every preview row visible.
	d.send(tea.WindowSizeMsg{Width: 200, Height: 100})
	d.refresh()
	return d
}

// refresh delivers one metadata and import-status snapshot.
func (d *importDriver) refresh() { d.send(d.model.Init()()) }

func (d *importDriver) send(msg tea.Msg) tea.Cmd {
	_, cmd := d.model.Update(msg)
	return cmd
}

func (d *importDriver) key(code rune) tea.Cmd { return d.send(tea.KeyPressMsg{Code: code}) }

func (d *importDriver) view() string { return d.model.View().Content }

// require names only fixed, non-secret fragments, so it may print them.
func (d *importDriver) require(texts ...string) {
	d.t.Helper()
	view := d.view()
	for _, text := range texts {
		if !strings.Contains(view, text) {
			d.t.Fatalf("owner TUI view lacks %q", text)
		}
	}
}

func (d *importDriver) absent(text string) {
	d.t.Helper()
	if strings.Contains(d.view(), text) {
		d.t.Fatalf("owner TUI still shows %q", text)
	}
}

// forbid never prints the offending text: it may be a password or a value.
func (d *importDriver) forbid(secrets []string) {
	d.t.Helper()
	view := d.view()
	for _, secret := range secrets {
		if strings.Contains(view, secret) {
			d.t.Fatal("owner TUI view exposed secret material")
		}
	}
}

// openImport moves to the Import root item and opens its form.
func (d *importDriver) openImport() {
	d.t.Helper()
	const label = "> Import credentials and values"
	for i := 0; i < 40 && !strings.Contains(d.view(), label); i++ {
		d.key(tea.KeyDown)
	}
	d.require(label)
	d.key(importKeyEnter)
	d.require("Archive file", "Archive password")
}

// submit pastes one text per field, then runs [Apply] and delivers its result.
func (d *importDriver) submit(texts ...string) {
	d.t.Helper()
	for _, text := range texts {
		d.send(tea.PasteMsg{Content: text})
		d.key(importKeyTab)
	}
	cmd := d.key(importKeyEnter)
	if cmd == nil {
		d.t.Fatal("owner TUI form did not start its operation")
	}
	d.send(cmd())
}

// requirePreview checks the staged preview: metadata and scopes, no secrets.
func (d *importDriver) requirePreview(archive string, secrets []string) {
	d.t.Helper()
	d.require("Import preview", archive, `Server "legacy"`,
		`Account "main" / login "first" / "key"`,
		`Account "second" / login "second" / "password"`,
		`Secret "initial" / scope: global`,
		`Secret "local2" / scope: server "legacy"`)
	d.forbid(secrets)
}
