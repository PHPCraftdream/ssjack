package ownertui

import (
	"context"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/PHPCraftdream/ssjack/internal/ownerdb"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

type backend interface {
	Metadata() (vault.DirectoryMetadata, error)
	Status() ownerdb.Status
	Edit(func(*vault.Vault) error) error
	Submit(vault.OwnerChange) error
	Link(string, []byte) error
	Reconcile() error
	ResumeDraft() error
	CancelDraft() error
	RetryDatabase() error
	Export(ownerdb.ExportRequest) error
	Flush(context.Context) error
	Close(context.Context) error
	InspectImport(string, []byte) error
	ImportStatus() ownerdb.ImportStatus
	ConfirmImport() error
	ResumeImport() error
	AbortImport() error
}

type refreshMsg struct {
	metadata vault.DirectoryMetadata
	status   ownerdb.Status
	imports  ownerdb.ImportStatus
	err      error
}

type operationMsg struct {
	err    error
	action string
}
type closeMsg struct{ err error }
type tickMsg time.Time

type Model struct {
	ctx      context.Context
	backend  backend
	metadata vault.DirectoryMetadata
	status   ownerdb.Status
	at       location
	stack    []location
	cursor   int
	form     *form
	message  string
	working  bool
	quitting bool
	height   int
	ready    bool
	imp      ownerdb.ImportStatus // latest import status; metadata only
	// reselect blocks activation after a refresh changed the focused item.
	reselect bool

	// connection is an owner-selected SSH request awaiting TakeConnection.
	connection *Connection
}

func New(ctx context.Context, manager *ownerdb.Manager) *Model {
	return &Model{ctx: ctx, backend: manager, at: location{screen: databaseScreen}}
}

func (m *Model) Init() tea.Cmd { return m.refresh() }

func nextTick() tea.Cmd {
	return tea.Tick(250*time.Millisecond, func(at time.Time) tea.Msg { return tickMsg(at) })
}

func (m *Model) refresh() tea.Cmd {
	return func() tea.Msg {
		metadata, err := m.backend.Metadata()
		return refreshMsg{metadata: metadata, status: m.backend.Status(), imports: m.backend.ImportStatus(), err: err}
	}
}

func (m *Model) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := message.(type) {
	case tea.WindowSizeMsg:
		m.height = msg.Height
		return m, nil
	case tickMsg:
		return m, m.refresh()
	case refreshMsg:
		if msg.err == nil {
			m.applyMetadata(msg.metadata, msg.imports)
			m.status, m.ready = msg.status, true
		} else {
			m.message = "Cannot refresh database metadata."
		}
		return m, nextTick()
	case operationMsg:
		m.working = false
		if strings.HasPrefix(msg.action, "import") {
			m.importDone(msg.action, msg.err)
			return m, nil
		}
		if msg.action == "export" {
			m.message = "Export written to the selected new file."
			if msg.err != nil {
				m.message = "Export failed; inspect the selected destination before retrying. No automatic retry."
			}
			return m, nil
		}
		if msg.err != nil {
			m.message = "Operation failed; changes may still need saving or reconciliation."
		} else {
			m.message = "Change applied. Check persistence status below."
		}
		return m, nil
	case closeMsg:
		m.working, m.quitting = false, false
		if msg.err == nil {
			return m, tea.Quit
		}
		m.message = "Exit stopped: save or reconcile pending changes, then retry."
		return m, nil
	case tea.PasteMsg:
		if !m.working && m.form != nil {
			m.form.insert(msg.Content)
		}
		return m, nil
	case tea.KeyPressMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

func (m *Model) push(target location) {
	m.stack = append(m.stack, m.at)
	m.at, m.cursor, m.message, m.reselect = target, 0, "", false
}

func (m *Model) back() {
	if m.at.screen == importScreen {
		m.abortImport() // leaving the preview always drops the staged material
	}
	if m.form != nil {
		m.form.clear()
		m.form = nil
	}
	if len(m.stack) != 0 {
		m.at = m.stack[len(m.stack)-1]
		m.stack = m.stack[:len(m.stack)-1]
		m.cursor = 0
	}
	m.reselect = false
}

func (m *Model) handleKey(key tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	if m.working {
		return m, nil
	}
	name := key.String()
	if name == "ctrl+c" {
		if m.form != nil || m.at.screen == importScreen {
			m.back()
			return m, nil
		}
		return m, m.requestClose()
	}
	if m.form != nil {
		switch name {
		case "esc", "escape":
			m.back()
		case "tab", "down":
			m.form.move(1)
		case "shift+tab", "up":
			m.form.move(-1)
		case "backspace":
			m.form.backspace()
		case "enter":
			if m.form.focus == len(m.form.fields)+1 {
				m.back()
			} else if m.form.focus == len(m.form.fields) {
				return m, m.applyForm()
			} else {
				m.form.move(1)
			}
		default:
			m.form.insert(key.Text)
		}
		return m, nil
	}
	items := m.items()
	if len(items) == 0 {
		m.cursor = 0
	} else if m.cursor >= len(items) {
		m.cursor = len(items) - 1
	}
	if m.reselect {
		switch name {
		case "up", "down", "left", "esc", "escape":
			m.clearReselect()
		case "enter", "right":
			m.message = reselectMessage
			return m, nil
		}
	}
	switch name {
	case "esc", "escape", "left":
		m.back()
	case "up":
		if len(items) != 0 {
			m.cursor = (m.cursor + len(items) - 1) % len(items)
		}
	case "down":
		if len(items) != 0 {
			m.cursor = (m.cursor + 1) % len(items)
		}
	case "enter", "right":
		if len(items) != 0 {
			return m, m.activate(items[m.cursor], name == "enter")
		}
	}
	return m, nil
}

func (m *Model) View() tea.View {
	var out strings.Builder
	out.WriteString("ssjack — owner database\n")
	description := m.describe()
	out.WriteString(description + "\n")
	if m.form != nil {
		out.WriteString(escaped(m.form.action) + "\n\n")
		if m.form.scopeLabel != "" {
			out.WriteString(m.form.scopeLabel + "\n")
		}
		for i, current := range m.form.fields {
			marker := "  "
			if m.form.focus == i {
				marker = "> "
			}
			out.WriteString(marker + current.label + ": " + m.form.display(i) + "\n")
			if m.form.focus == i {
				out.WriteString("  " + current.help + "\n")
			}
		}
		for i, label := range []string{"[Apply]", "[Cancel]"} {
			marker := "  "
			if m.form.focus == len(m.form.fields)+i {
				marker = "> "
			}
			out.WriteString(marker + label + "\n")
		}
	} else {
		items := m.items()
		rows := m.height - 12 - strings.Count(description, "\n")
		if rows < 3 {
			rows = 3
		}
		start := m.cursor - rows + 1
		if start < 0 {
			start = 0
		}
		for i := start; i < len(items) && i < start+rows; i++ {
			entry := items[i]
			marker := "  "
			if m.cursor == i {
				marker = "> "
			}
			out.WriteString(marker + entry.label + "\n")
		}
	}
	out.WriteString("\nTab/Arrows: move · Enter: select · Esc: back/cancel · Ctrl+C: cancel/exit\n")
	switch {
	case !m.ready:
		out.WriteString("Persistence: loading metadata\n")
	case m.status.Database.Err != nil || m.status.Err != nil:
		out.WriteString("Persistence: ERROR — use Pending change to retry or reconcile.\n")
	case m.status.Busy || m.status.Database.Pending:
		out.WriteString("Persistence: saving\n")
	case m.status.Pending:
		out.WriteString("Persistence: pending owner decision; no automatic replay\n")
	default:
		out.WriteString("Persistence: saved\n")
	}
	if line := m.importLine(); line != "" {
		out.WriteString(line + "\n")
	}
	if m.working {
		out.WriteString("Working; please wait.\n")
	}
	if m.message != "" {
		out.WriteString(m.message + "\n")
	}
	view := tea.NewView(out.String())
	view.AltScreen = true
	return view
}
