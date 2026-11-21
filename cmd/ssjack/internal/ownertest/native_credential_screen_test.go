package ownertest

import (
	"fmt"
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
)

const (
	nativeScreenCols = 200
	nativeScreenRows = 60
)

// nativeCredentialScreen models the native fixture's viewport, not a full VT.
// It tracks simple glyphs (not composed graphemes), with no styles or scrollback.
type nativeCredentialScreen struct {
	parser       *ansi.Parser
	seen, x, y   int
	ignored      int
	wrap, insert bool
	last         rune
	cells        [nativeScreenCols * nativeScreenRows]rune

	keepLastAlternate bool
	inAlternate       bool
	lastAlternate     string // Numbered rows, already masked.
}

func newNativeCredentialScreen() *nativeCredentialScreen {
	s := &nativeCredentialScreen{parser: ansi.NewParser()}
	s.parser.SetHandler(ansi.Handler{
		Print:     s.print,
		Execute:   s.execute,
		HandleCsi: s.csi,
		HandleEsc: s.esc,
		HandleDcs: func(ansi.Cmd, ansi.Params, []byte) { s.ignored++ },
		HandleOsc: func(int, []byte) { s.ignored++ },
		HandlePm:  func([]byte) { s.ignored++ },
		HandleApc: func([]byte) { s.ignored++ },
		HandleSos: func([]byte) { s.ignored++ },
	})
	return s
}

func (s *nativeCredentialScreen) consume(data []byte) {
	for _, b := range data[s.seen:] {
		s.parser.Advance(b)
	}
	s.seen = len(data)
}

func (s *nativeCredentialScreen) matches(data []byte, line string) bool {
	s.consume(data)
	want := []rune(line)
	for row := range nativeScreenRows {
		cells := s.cells[row*nativeScreenCols : (row+1)*nativeScreenCols]
		end := len(cells)
		for end > 0 && (cells[end-1] == 0 || cells[end-1] == ' ') {
			end--
		}
		if end != len(want) {
			continue
		}
		i := 0
		for i < end && (cells[i] == want[i] || cells[i] == 0 && want[i] == ' ') {
			i++
		}
		if i == end {
			return true
		}
	}
	return false
}

// replayNativeCredentialScreenForDiagnostics replays a complete transcript offline.
func replayNativeCredentialScreenForDiagnostics(data []byte) *nativeCredentialScreen {
	s := newNativeCredentialScreen()
	s.keepLastAlternate = true
	s.consume(data)
	return s
}

func (s *nativeCredentialScreen) diagnosticRows() string {
	current := s.maskedRows()
	if s.lastAlternate == "" {
		return current
	}
	return "Final viewport:\n" + current + "Last alternate viewport:\n" + s.lastAlternate
}

func (s *nativeCredentialScreen) credentialFieldLabel() string {
	for row := range nativeScreenRows {
		line := strings.TrimSpace(s.rowText(row))
		line = strings.TrimSpace(strings.TrimPrefix(line, "> "))
		value, ok := strings.CutPrefix(line, "Credential:")
		if !ok {
			continue
		}
		switch strings.TrimSpace(value) {
		case "<hidden; empty>":
			return "empty"
		case "<hidden; entered>":
			return "entered"
		default:
			return "other"
		}
	}
	return "other"
}

func (s *nativeCredentialScreen) rowText(row int) string {
	cells := s.cells[row*nativeScreenCols : (row+1)*nativeScreenCols]
	var text strings.Builder
	for _, r := range cells {
		switch r {
		case 0:
			text.WriteByte(' ')
		case -1:
		default:
			text.WriteRune(r)
		}
	}
	return strings.TrimRight(text.String(), " ")
}

func (s *nativeCredentialScreen) maskedRows() string {
	const label = "Credential:"
	var rows strings.Builder
	for row := range nativeScreenRows {
		line := s.rowText(row)
		if line == "" {
			continue
		}
		if prefix, _, ok := strings.Cut(line, label); ok {
			line = prefix + label + " <redacted>"
		}
		fmt.Fprintf(&rows, "%d: %s\n", row+1, line)
	}
	return rows.String()
}

func (s *nativeCredentialScreen) move(x, y int) {
	s.x, s.y = max(0, min(x, nativeScreenCols-1)), max(0, min(y, nativeScreenRows-1))
	s.wrap = false
}

func (s *nativeCredentialScreen) index() {
	s.wrap = false
	if s.y < nativeScreenRows-1 {
		s.y++
		return
	}
	// Scroll regions are not replayed; scrolling uses the full viewport.
	copy(s.cells[:], s.cells[nativeScreenCols:])
	clear(s.cells[len(s.cells)-nativeScreenCols:])
}

func (s *nativeCredentialScreen) reverseIndex() {
	s.wrap = false
	if s.y > 0 {
		s.y--
		return
	}
	copy(s.cells[nativeScreenCols:], s.cells[:])
	clear(s.cells[:nativeScreenCols])
}

func (s *nativeCredentialScreen) print(r rune) {
	w := ansi.StringWidthWc(string(r))
	if w == 0 {
		return
	}
	if s.wrap || s.x+w > nativeScreenCols {
		s.x = 0
		s.index()
	}
	start := s.y*nativeScreenCols + s.x
	row := s.cells[start : (s.y+1)*nativeScreenCols]
	if s.insert {
		copy(row[w:], row)
	}
	row[0] = r
	for i := 1; i < w; i++ {
		row[i] = -1 // Wide-glyph continuation, not a blank cell.
	}
	s.last = r
	s.wrap = s.x+w == nativeScreenCols
	s.x = min(s.x+w, nativeScreenCols-1)
}

func (s *nativeCredentialScreen) execute(b byte) {
	switch b {
	case '\r':
		s.move(0, s.y)
	case '\n', '\v', '\f':
		s.index()
	case '\b':
		s.move(s.x-1, s.y)
	case '\t':
		s.move((s.x/8+1)*8, s.y)
	case 0x00, 0x7f, 0x18, 0x1a, 0x9c: // NUL, DEL, CAN, SUB, and ST: no viewport command.
	default:
		s.ignored++
	}
}

func (s *nativeCredentialScreen) resetViewport() {
	clear(s.cells[:])
	s.move(0, 0)
	s.last = 0
}

func (s *nativeCredentialScreen) esc(cmd ansi.Cmd) {
	if cmd.Intermediate() != 0 {
		s.ignored++
		return
	}
	switch cmd.Final() {
	case 'D': // IND
		s.index()
	case 'E': // NEL
		s.x = 0
		s.index()
	case 'M': // RI
		s.reverseIndex()
	case 'c': // RIS
		s.resetViewport()
		s.insert = false
		s.inAlternate = false
	case '\\': // ESC ST can be dispatched separately after a control string.
	default:
		s.ignored++
		return
	}
	if cmd.Prefix() != 0 {
		s.ignored++
	}
}

func (s *nativeCredentialScreen) csi(cmd ansi.Cmd, params ansi.Params) {
	if cmd.Intermediate() != 0 {
		s.ignored++
		return
	}
	final := cmd.Final()
	if final == 'h' || final == 'l' {
		unsupported := len(params) == 0
		for _, p := range params {
			switch n := p.Param(0); {
			case cmd.Prefix() == '?' && (n == 47 || n == 1047 || n == 1049):
				if s.keepLastAlternate {
					if final == 'l' && s.inAlternate {
						s.lastAlternate = s.maskedRows()
					}
					s.inAlternate = final == 'h'
				}
				s.resetViewport() // Only the fixture's active viewport is observed.
			case cmd.Prefix() == 0 && n == 4:
				s.insert = final == 'h'
			default:
				unsupported = true
			}
		}
		if unsupported {
			s.ignored++
		}
		return
	}
	if cmd.Prefix() != 0 {
		s.ignored++
		return
	}
	p, _, _ := params.Param(0, 0)
	n := max(1, p)
	x, y := s.x, s.y
	switch final {
	case 'H', 'f':
		col, _, _ := params.Param(1, 1)
		s.move(max(1, col)-1, n-1)
	case 'G', '`':
		s.move(n-1, y)
	case 'd':
		s.move(x, n-1)
	case 'A':
		s.move(x, y-n)
	case 'B', 'e':
		s.move(x, y+n)
	case 'C', 'a':
		s.move(x+n, y)
	case 'D':
		s.move(x-n, y)
	case 'E':
		s.move(0, y+n)
	case 'F':
		s.move(0, y-n)
	case 'Z': // CBT
		if x > 0 {
			x = max(0, (x-1)/8-(n-1)) * 8
		}
		s.move(x, y)
	case 'J', 'K':
		lo, hi := 0, len(s.cells)
		if final == 'K' {
			lo, hi = y*nativeScreenCols, (y+1)*nativeScreenCols
		}
		pos := y*nativeScreenCols + x
		switch p {
		case 0:
			clear(s.cells[pos:hi])
		case 1:
			clear(s.cells[lo : pos+1])
		case 2:
			clear(s.cells[lo:hi])
		default:
			s.ignored++
		}
	case '@', 'P', 'X':
		row := s.cells[y*nativeScreenCols+x : (y+1)*nativeScreenCols]
		n = min(n, len(row))
		switch final {
		case '@':
			copy(row[n:], row)
			clear(row[:n])
		case 'P':
			copy(row, row[n:])
			clear(row[len(row)-n:])
		case 'X':
			clear(row[:n])
		}
	case 'b':
		if s.last != 0 {
			for range min(n, len(s.cells)) {
				s.print(s.last)
			}
		}
	default:
		s.ignored++
	}
}

func TestNativeCredentialScreenFieldLabel(t *testing.T) {
	const prefix = "\x1b[2;3H> Credential: <hidden; "
	const empty = prefix + "empty>"
	const unknown = empty + "\x1b[2;26Hentered>!"
	const entered = unknown + "\x1b[2;34H\x1b[K"
	data := []byte(entered)
	s := newNativeCredentialScreen()
	for _, step := range []struct {
		end  int
		want string
	}{
		{0, "other"},
		{len(empty), "empty"},
		{len(unknown), "other"},
		{len(entered), "entered"},
	} {
		s.consume(data[:step.end])
		if got := s.credentialFieldLabel(); got != step.want {
			t.Fatalf("offset %d: field label = %q, want %q", step.end, got, step.want)
		}
		if step.end != 0 && s.diagnosticRows() != "2:   > Credential: <redacted>\n" {
			t.Fatalf("offset %d: credential diagnostic row was not masked", step.end)
		}
	}
}

func TestNativeCredentialScreenDiagnostics(t *testing.T) {
	s := newNativeCredentialScreen()
	data := []byte("\x1b[2;17Hmmy")
	s.consume(data)
	data = append(data, "\x1b[2;1H> Credential: du\x1b[2;5r"...)
	s.consume(data)
	if !s.matches(data, "> Credential: dummy") {
		t.Fatal("cursor-assembled row did not match")
	}
	if s.diagnosticRows() != "2: > Credential: <redacted>\n" {
		t.Fatal("diagnostic row did not preserve its label and mask its value")
	}
	if s.ignored != 1 {
		t.Fatalf("ignored commands = %d, want 1", s.ignored)
	}
}

func TestNativeCredentialScreenLastAlternateDiagnostics(t *testing.T) {
	const data = "\x1b[?1049h\x1b[2;1H> Credential: synthetic-secret\x1b[?1049lreceipt\x0e\x00\x7f\x9c\x1b\\"
	s := replayNativeCredentialScreenForDiagnostics([]byte(data))
	const want = "Final viewport:\n1: receipt\nLast alternate viewport:\n2: > Credential: <redacted>\n"
	if s.diagnosticRows() != want {
		t.Fatal("diagnostics did not preserve the final row and masked alternate row")
	}
	if s.ignored != 1 {
		t.Fatalf("ignored commands = %d, want 1", s.ignored)
	}
}

func TestNativeCredentialScreenSplitInsert(t *testing.T) {
	const empty = "> Credential: <hidden; empty>"
	const entered = "> Credential: <hidden; entered>"
	s := newNativeCredentialScreen()
	data := []byte(empty)
	if !s.matches(data, empty) || s.matches(data, entered) {
		t.Fatal("initial credential row did not match only the empty state")
	}
	// Keep the original 'e', overwrite after it, then insert the missing 'n'.
	data = append(data, "\x1b[25Gtered>\x1b[Z\x1b["...)
	if s.matches(data, entered) {
		t.Fatal("incomplete update matched the entered state")
	}
	data = append(data, "@n"...)
	if !s.matches(data, entered) || s.matches(data, empty) {
		t.Fatal("completed insertion did not match only the entered state")
	}
}

func TestNativeCredentialScreenReverseIndex(t *testing.T) {
	s := newNativeCredentialScreen()
	data := []byte("top\r\nsecond\x1b")
	s.matches(data, "second")
	data = append(data, 'M')
	s.matches(data, "second")
	if s.x != 6 || s.y != 0 || s.cells[0] != 't' || s.cells[nativeScreenCols] != 's' {
		t.Fatal("reverse index did not move up without scrolling")
	}
	data = append(data, "\x1b[200G!\x1bM"...)
	s.matches(data, "top")
	if s.x != nativeScreenCols-1 || s.y != 0 || s.wrap ||
		s.cells[0] != 0 || s.cells[nativeScreenCols-1] != 0 ||
		s.cells[nativeScreenCols] != 't' || s.cells[2*nativeScreenCols-1] != '!' ||
		s.cells[2*nativeScreenCols] != 's' {
		t.Fatal("reverse index at the top did not scroll down, clear the first row, and cancel wrap")
	}
}
