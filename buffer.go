package main

import (
	"bytes"
	"io"
	"strconv"
	"strings"
)

// Style is a compact cell attribute. One byte keeps the diff hot loop a single
// integer compare, the same trick ncurses uses with chtype.
type Style byte

const (
	Normal Style = 0
	Dim    Style = 1 << iota
	Bold
	Reverse
	Green
	Yellow
	Red
	Cyan
)

func (s Style) sgr() string {
	var b strings.Builder
	b.WriteString("\x1b[0")
	add := func(code string) { b.WriteString(";"); b.WriteString(code) }
	if s&Bold != 0 {
		add("1")
	}
	if s&Dim != 0 {
		add("2")
	}
	if s&Reverse != 0 {
		add("7")
	}
	switch s & (Green | Yellow | Red | Cyan) {
	case Green:
		add("32")
	case Yellow:
		add("33")
	case Red:
		add("31")
	case Cyan:
		add("36")
	}
	b.WriteString("m")
	return b.String()
}

// Cell is one character cell. R == 0 marks the continuation half of a
// double-width rune; continuation cells are never written to the terminal.
type Cell struct {
	R     rune
	Style Style
}

func (c Cell) width() int { return runeWidth(c.R) }

// Screen is a double-buffered character grid flushed as per-cell diffs. A
// frame that changed nothing writes zero bytes; a frame that changed one cell
// writes one cursor move plus that cell. This is the ncurses technique htop
// rides on, applied to the whole screen instead of a widget region.
type Screen struct {
	W, H    int
	cur     []Cell
	prev    []Cell
	hasPrev bool
}

func NewScreen(w, h int) *Screen {
	s := &Screen{W: w, H: h}
	s.cur = make([]Cell, w*h)
	s.prev = make([]Cell, w*h)
	s.Clear()
	copy(s.prev, s.cur)
	return s
}

func (s *Screen) Resize(w, h int) {
	if w <= 0 || h <= 0 || (w == s.W && h == s.H) {
		return
	}
	s.W, s.H = w, h
	s.cur = make([]Cell, w*h)
	s.prev = make([]Cell, w*h)
	s.hasPrev = false
	s.Clear()
}

// Clear blanks the current frame. The previous frame is kept so the next flush
// still emits only what this clear actually changed.
func (s *Screen) Clear() {
	blank := Cell{' ', Normal}
	for i := range s.cur {
		s.cur[i] = blank
	}
}

func (s *Screen) Set(x, y int, r rune, st Style) {
	if x < 0 || y < 0 || x >= s.W || y >= s.H {
		return
	}
	// Remote content (node names, log payloads, CLI envelopes) is rendered
	// through this choke point; control bytes must never reach the terminal
	// raw, or a hostile name/log line could inject ANSI/OSC sequences.
	// r == 0 is the internal double-width continuation marker, not content.
	if r != 0 && (r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f)) {
		r = 0xfffd
	}
	s.cur[y*s.W+x] = Cell{r, st}
}

// Text writes a string width-aware and returns the column after its last
// occupied cell. Double-width runes also mark their continuation cell.
func (s *Screen) Text(x, y int, text string, st Style) int {
	for _, r := range text {
		if x >= s.W {
			break
		}
		s.Set(x, y, r, st)
		if runeWidth(r) == 2 {
			x++
			s.Set(x, y, 0, st)
		}
		x++
	}
	return x
}

// TextLimit truncates so the text never occupies more than width columns.
func (s *Screen) TextLimit(x, y, width int, text string, st Style) {
	for _, r := range text {
		w := runeWidth(r)
		if w > width {
			return
		}
		s.Set(x, y, r, st)
		if w == 2 {
			x++
			width--
			s.Set(x, y, 0, st)
		}
		x++
		width--
	}
}

// Row fills a whole row with one style, used for header/status bars.
func (s *Screen) Row(y int, text string, st Style) {
	for x := 0; x < s.W; x++ {
		s.Set(x, y, ' ', st)
	}
	s.Text(0, y, text, st)
}

// Flush emits the diff between prev and cur as one batched write. Runs of
// dirty cells open with a cursor-address escape; style changes emit SGR only
// when the style actually differs from the last one written.
func (s *Screen) Flush(w io.Writer) error {
	var out bytes.Buffer
	last := Style(255) // impossible value to force the first SGR
	cols := make([]int, s.W+1)
	for y := 0; y < s.H; y++ {
		base := y * s.W
		col := 0
		for x := 0; x < s.W; x++ {
			cols[x] = col
			col += s.cur[base+x].width()
		}
		cols[s.W] = col
		for x := 0; x < s.W; {
			i := base + x
			if s.hasPrev && s.cur[i] == s.prev[i] {
				x++
				continue
			}
			out.WriteString("\x1b[" + strconv.Itoa(y+1) + ";" + strconv.Itoa(cols[x]+1) + "H")
			for x < s.W {
				i := base + x
				if s.hasPrev && s.cur[i] == s.prev[i] {
					break
				}
				cell := s.cur[i]
				if cell.R != 0 {
					if cell.Style != last {
						out.WriteString(cell.Style.sgr())
						last = cell.Style
					}
					out.WriteRune(cell.R)
				}
				x++
			}
		}
	}
	if last != Normal && out.Len() > 0 {
		out.WriteString(Normal.sgr())
	}
	copy(s.prev, s.cur)
	s.hasPrev = true
	_, err := w.Write(out.Bytes())
	return err
}

// DumpPlain renders the current frame as plain text for headless verification.
func (s *Screen) DumpPlain() string {
	var b strings.Builder
	for y := 0; y < s.H; y++ {
		for x := 0; x < s.W; x++ {
			cell := s.cur[y*s.W+x]
			if cell.R != 0 {
				b.WriteRune(cell.R)
			}
		}
		b.WriteByte('\n')
	}
	return b.String()
}

// runeWidth is the minimal wcwidth the CJK-heavy UI needs: combining marks are
// zero, East Asian wide ranges are two, everything else is one.
func runeWidth(r rune) int {
	if r == 0 {
		return 0
	}
	switch {
	case r >= 0x0300 && r <= 0x036F: // combining diacritics
		return 0
	case r >= 0x1100 && r <= 0x115F,
		r >= 0x2E80 && r <= 0x303E,
		r >= 0x3041 && r <= 0x33FF,
		r >= 0x3400 && r <= 0x4DBF,
		r >= 0x4E00 && r <= 0x9FFF,
		r >= 0xA000 && r <= 0xA4CF,
		r >= 0xAC00 && r <= 0xD7A3,
		r >= 0xF900 && r <= 0xFAFF,
		r >= 0xFE30 && r <= 0xFE4F,
		r >= 0xFF00 && r <= 0xFF60,
		r >= 0xFFE0 && r <= 0xFFE6,
		r >= 0x20000 && r <= 0x3FFFD:
		return 2
	default:
		return 1
	}
}
