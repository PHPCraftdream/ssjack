package ownertui

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	tea "charm.land/bubbletea/v2"

	"github.com/PHPCraftdream/ssjack/internal/ownercommand"
	"github.com/PHPCraftdream/ssjack/internal/ownerdb"
	"github.com/PHPCraftdream/ssjack/internal/stdindrain"
	"github.com/PHPCraftdream/ssjack/internal/vault"
	"golang.org/x/term"
)

type Backend interface {
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

type backend = Backend

type refreshMsg struct {
	epoch    uint64
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
	command  *ownercommand.State
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
	epoch    uint64
	imp      ownerdb.ImportStatus // latest import status; metadata only
	// reselect blocks activation after a refresh changed the focused item.
	reselect bool

	// connection is an owner-selected SSH request awaiting TakeConnection.
	connection *Connection
	readSecret func(int) ([]byte, error)
}

func New(ctx context.Context, manager backend) *Model {
	return &Model{ctx: ctx, backend: manager, at: location{screen: databaseScreen}}
}

func (m *Model) Init() tea.Cmd { return m.refresh() }

func (m *Model) SetSecretReader(read func(int) ([]byte, error)) { m.readSecret = read }

var (
	errSecretCancelled   = errors.New("secret entry cancelled")
	errSecretDrainFailed = errors.New("failed to drain terminal input")
)

type secretReadMsg struct {
	form  *form
	index int
	value []byte
	err   error
}
type secretExec struct {
	prompt string
	limit  int
	read   func(int) ([]byte, error)
	stdout io.Writer
	stderr io.Writer
	value  []byte
}

func (c *secretExec) SetStdin(io.Reader)    {}
func (c *secretExec) SetStdout(w io.Writer) { c.stdout = w }
func (c *secretExec) SetStderr(w io.Writer) { c.stderr = w }
func (c *secretExec) Run() error {
	read := c.read
	if read == nil {
		fd := int(os.Stdin.Fd())
		state, err := term.MakeRaw(fd)
		if err != nil {
			return errors.New("failed to read secret")
		}
		defer term.Restore(fd, state)
		read = readHiddenLineRaw
	}
	output := c.stdout
	if output == nil {
		output = c.stderr
	}
	if output == nil {
		output = os.Stderr
	}
	if _, err := fmt.Fprint(output, c.prompt); err != nil {
		return errors.New("failed to read secret")
	}
	value, err := read(c.limit)
	if _, writeErr := fmt.Fprintln(output); err == nil {
		err = writeErr
	}
	if err != nil {
		clear(value)
		return err
	}
	if len(value) > c.limit {
		clear(value)
		return errors.New("secret exceeds field limit")
	}
	c.value = value
	return nil
}
func readHiddenLine(limit int) ([]byte, error) {
	if limit < 0 {
		return nil, errors.New("invalid secret limit")
	}
	fd := int(os.Stdin.Fd())
	state, err := term.MakeRaw(fd)
	if err != nil {
		return nil, errors.New("failed to read secret")
	}
	defer term.Restore(fd, state)
	return readHiddenLineRaw(limit)
}
func readHiddenLineRaw(limit int) ([]byte, error) {
	if limit < 0 {
		return nil, errors.New("invalid secret limit")
	}
	value := make([]byte, 0, limit)
	var one [1]byte
	defer clear(one[:])
	for {
		if _, err := io.ReadFull(os.Stdin, one[:]); err != nil {
			clear(value)
			return nil, errors.New("failed to read secret")
		}
		switch one[0] {
		case '\r', '\n':
			if !utf8.Valid(value) {
				clear(value)
				return failSecretDrain()
			}
			return value, nil
		case 0x1b, 0x03:
			clear(value)
			return failSecretDrain()
		case 0x08, 0x7f:
			if len(value) > 0 {
				_, size := utf8.DecodeLastRune(value)
				start := len(value) - size
				clear(value[start:])
				value = value[:start]
			}
		default:
			if one[0] < 0x20 || one[0] == 0x7f {
				clear(value)
				return failSecretDrain()
			}
			if len(value) == limit {
				clear(value)
				return failSecretDrain()
			}
			value = append(value, one[0])
		}
	}
}
func failSecretDrain() ([]byte, error) {
	if err := stdindrain.DrainStdin(); err != nil {
		return nil, errSecretDrainFailed
	}
	return nil, errSecretCancelled
}

func ReadHiddenLine(limit int) ([]byte, error) { return readHiddenLine(limit) }
func secretReadCommand(form *form, index, limit int, read func(int) ([]byte, error)) tea.Cmd {
	c := &secretExec{prompt: "Secret (hidden; Enter submits, Esc/Ctrl+C cancels): ", limit: limit, read: read}
	return tea.Exec(c, func(err error) tea.Msg {
		if err != nil {
			clear(c.value)
			return secretReadMsg{form: form, index: index, err: err}
		}
		value := c.value
		c.value = nil
		return secretReadMsg{form: form, index: index, value: value}
	})
}

var _ tea.ExecCommand = (*secretExec)(nil)

func nextTick() tea.Cmd {
	return tea.Tick(250*time.Millisecond, func(at time.Time) tea.Msg { return tickMsg(at) })
}

func (m *Model) refresh() tea.Cmd {
	epoch := m.epoch
	return func() tea.Msg {
		metadata, status, imports, err := readOwnerSnapshot(m.backend)
		return refreshMsg{epoch: epoch, metadata: metadata, status: status, imports: imports, err: err}
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
		if msg.epoch != m.epoch {
			return m, nextTick()
		}
		if msg.err == nil {
			m.applyMetadata(msg.metadata, msg.imports)
			m.status, m.ready = msg.status, true
		} else {
			m.message = "Cannot refresh database metadata."
		}
		return m, nextTick()
	case operationMsg:
		m.epoch++
		m.working = false
		if m.command != nil {
			return m, m.commandDone(msg)
		}
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
	case secretReadMsg:
		if errors.Is(msg.err, errSecretDrainFailed) {
			clear(msg.value)
			if m.form != nil {
				m.back()
			}
			m.message = "Secret input could not be safely drained; exiting."
			if m.command != nil {
				m.command.Err = ownercommand.ErrOperation
			}
			return m, tea.Quit
		}
		if m.form == nil || msg.form != m.form || msg.index < 0 || msg.index >= len(m.form.fields) || !m.form.fields[msg.index].secret {
			clear(msg.value)
			return m, nil
		}
		if msg.err == nil {
			clear(m.form.fields[msg.index].value)
			m.form.fields[msg.index].value = msg.value
		} else if errors.Is(msg.err, errSecretCancelled) {
			clear(msg.value)
			if m.command != nil {
				m.back()
				m.command.Err = ownercommand.ErrCancelled
				return m, tea.Quit
			}
			m.message = "Secret entry cancelled; the value was not changed. Press Enter to retry."
		} else {
			clear(msg.value)
			m.message = "Secret entry could not be read; the stored value was not changed."
		}
		return m, nil
	case tea.PasteMsg:
		if m.working {
			return m, nil
		}
		if m.form != nil && m.form.focus < len(m.form.fields) && m.form.fields[m.form.focus].secret {
			return m, nil
		}
		if m.form != nil {
			m.form.insert(msg.Content)
		}
		return m, nil
	case tea.KeyPressMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

func (m *Model) handleKey(key tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	if m.working {
		return m, nil
	}
	name := key.String()
	if m.command != nil && (name == "ctrl+c" || name == "esc" || name == "escape" || (name == "left" && m.form == nil) || (name == "enter" && m.form != nil && m.form.focus == len(m.form.fields)+1)) {
		m.back()
		m.command.Err = ownercommand.ErrCancelled
		return m, tea.Quit
	}
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
			if m.form.focus >= len(m.form.fields) || !m.form.fields[m.form.focus].secret {
				m.form.backspace()
			}
		case "enter":
			if m.form.focus == len(m.form.fields)+1 {
				m.back()
			} else if m.form.focus == len(m.form.fields) {
				return m, m.applyForm()
			} else if m.form.fields[m.form.focus].secret {
				return m, secretReadCommand(m.form, m.form.focus, m.form.fields[m.form.focus].limit, m.readSecret)
			} else {
				m.form.move(1)
			}
		default:
			if m.form.focus >= len(m.form.fields) || !m.form.fields[m.form.focus].secret {
				m.form.insert(key.Text)
			}
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
	description := m.describe() + m.status.Database.SSH.Display()
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
