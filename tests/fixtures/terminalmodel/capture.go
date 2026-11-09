// Package terminalmodel captures complete synthetic model frames independently of ANSI diffs.
package terminalmodel

import (
	"bytes"
	"sync"

	tea "charm.land/bubbletea/v2"
)

type Output struct {
	mu    sync.Mutex
	raw   bytes.Buffer
	frame string
}

func (o *Output) Write(data []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.raw.Write(data)
}

func (o *Output) String() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.frame
}

func (o *Output) Raw() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.raw.String()
}

type model struct {
	inner  tea.Model
	output *Output
}

func Capture(inner tea.Model, output *Output) tea.Model { return &model{inner: inner, output: output} }
func (m *model) Init() tea.Cmd                          { return m.inner.Init() }
func (m *model) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	next, command := m.inner.Update(message)
	m.inner = next
	return m, command
}
func (m *model) View() tea.View {
	view := m.inner.View()
	m.output.mu.Lock()
	m.output.frame = view.Content
	m.output.mu.Unlock()
	return view
}
