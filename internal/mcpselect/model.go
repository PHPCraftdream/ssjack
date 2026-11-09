// Package mcpselect presents metadata choices, never credential authority.
package mcpselect

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
)

var ErrSelection = errors.New("MCP selection metadata unavailable")

type Choice struct {
	Profile  string
	Revision uint64
	Bindings []mcpdirectory.Binding
}

type item struct {
	binding                   mcpdirectory.Binding
	server, account, endpoint string
	enabled, checked          bool
}

type Model struct {
	profile   string
	revision  uint64
	items     []item
	cursor    int
	message   string
	done      bool
	confirmed bool
	valid     bool
	height    int
}

func (m *Model) Init() tea.Cmd { return nil }

func (m *Model) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	if !m.valid || m.done {
		return m, nil
	}
	if size, ok := message.(tea.WindowSizeMsg); ok {
		m.height = size.Height
		return m, nil
	}
	key, ok := message.(tea.KeyPressMsg)
	if !ok {
		return m, nil
	}
	switch key.String() {
	case "esc", "ctrl+c", "q":
		m.done = true
		return m, tea.Quit
	case "down", "j", "tab":
		m.cursor = (m.cursor + 1) % (len(m.items) + 2)
	case "up", "k", "shift+tab":
		m.cursor = (m.cursor + len(m.items) + 1) % (len(m.items) + 2)
	case "home":
		m.cursor = 0
	case "end":
		m.cursor = len(m.items) + 1
	case "space", " ":
		if m.cursor < len(m.items) {
			m.toggle()
		}
	case "enter":
		if m.cursor < len(m.items) {
			m.toggle()
		} else {
			m.done, m.confirmed = true, m.cursor == len(m.items)
			return m, tea.Quit
		}
	}
	return m, nil
}

func (m *Model) toggle() {
	selected := 0
	for _, entry := range m.items {
		if entry.checked {
			selected++
		}
	}
	entry := &m.items[m.cursor]
	if !entry.enabled {
		m.message = "This MCP account is disabled."
		return
	}
	if !entry.checked && selected == mcpdirectory.MaxSelections {
		m.message = "Select at most 16 MCP accounts."
		return
	}
	entry.checked = !entry.checked
	m.message = ""
}

// Result is owned metadata. The caller must revalidate before persistence/grants.
func (m *Model) Result() (Choice, bool) {
	if !m.valid || !m.done || !m.confirmed {
		return Choice{}, false
	}
	choice := Choice{Profile: m.profile, Revision: m.revision, Bindings: make([]mcpdirectory.Binding, 0)}
	for _, entry := range m.items {
		if entry.checked {
			choice.Bindings = append(choice.Bindings, entry.binding)
		}
	}
	return choice, true
}

func (m *Model) View() tea.View {
	if !m.valid {
		return tea.NewView("MCP selection metadata unavailable.\n")
	}
	var out strings.Builder
	fmt.Fprintf(&out, "Select MCP connections for SSH profile %s\n", strconv.Quote(m.profile))
	out.WriteString("Space toggles; choose Continue explicitly. Esc cancels without saving.\nChanged or disabled remembered choices are not preselected.\n\n")
	window := 10
	if m.height > 0 {
		window = max(1, min(window, m.height-8))
	}
	start := min(max(0, m.cursor-window+1), max(0, len(m.items)-window))
	end := min(start+window, len(m.items))
	if len(m.items) > window {
		fmt.Fprintf(&out, "Showing %d-%d of %d accounts\n", start+1, end, len(m.items))
	}
	for index := start; index < end; index++ {
		entry := m.items[index]
		mark, state := " ", ""
		if entry.checked {
			mark = "x"
		}
		if !entry.enabled {
			state = " (disabled)"
		}
		fmt.Fprintf(&out, "%s [%s] %s / %s / %s%s\n", focus(m.cursor == index), mark, strconv.Quote(entry.server), strconv.Quote(entry.account), strconv.Quote(entry.endpoint), state)
	}
	if len(m.items) == 0 {
		out.WriteString("(No remote MCP accounts configured.)\n")
	}
	fmt.Fprintf(&out, "%s Continue\n%s Cancel\n", focus(m.cursor == len(m.items)), focus(m.cursor == len(m.items)+1))
	if m.message != "" {
		fmt.Fprintf(&out, "\n%s\n", m.message)
	}
	return tea.NewView(out.String())
}

func focus(selected bool) string {
	if selected {
		return ">"
	}
	return " "
}
