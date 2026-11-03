package main

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestFlushEmitsNothingWhenUnchanged(t *testing.T) {
	s := NewScreen(10, 3)
	s.Text(0, 0, "hello", Bold)
	var first bytes.Buffer
	if err := s.Flush(&first); err != nil {
		t.Fatal(err)
	}
	if first.Len() == 0 {
		t.Fatal("first flush must paint the frame")
	}
	var second bytes.Buffer
	if err := s.Flush(&second); err != nil {
		t.Fatal(err)
	}
	if second.Len() != 0 {
		t.Fatalf("unchanged frame wrote %d bytes, want 0: %q", second.Len(), second.String())
	}
}

func TestFlushEmitsOnlyChangedCells(t *testing.T) {
	s := NewScreen(10, 1)
	s.Text(0, 0, "aaaa", Normal)
	var first bytes.Buffer
	_ = s.Flush(&first)
	s.Text(2, 0, "b", Normal) // one changed cell
	var second bytes.Buffer
	if err := s.Flush(&second); err != nil {
		t.Fatal(err)
	}
	out := second.String()
	if !strings.Contains(out, "\x1b[1;3H") {
		t.Fatalf("diff must address only column 3, got %q", out)
	}
	if strings.Count(out, "a") != 0 || !strings.Contains(out, "b") {
		t.Fatalf("diff must contain only the changed rune, got %q", out)
	}
}

func TestWideRunesOccupyTwoCells(t *testing.T) {
	s := NewScreen(10, 1)
	end := s.Text(0, 0, "节点", Normal)
	if end != 4 {
		t.Fatalf("two CJK runes must advance 4 columns, got %d", end)
	}
	if s.cur[1].R != 0 || s.cur[3].R != 0 {
		t.Fatal("continuation cells must be zero runes")
	}
	var out bytes.Buffer
	_ = s.Flush(&out)
	if !strings.Contains(out.String(), "节点") {
		t.Fatalf("flush dropped the wide runes: %q", out.String())
	}
}

func TestTextLimitTruncatesByDisplayWidth(t *testing.T) {
	s := NewScreen(20, 1)
	s.TextLimit(0, 0, 5, "香港节点", Normal) // 4 wide runes = 8 columns, limit 5
	plain := s.DumpPlain()
	if strings.TrimSpace(plain) != "香港" {
		t.Fatalf("want 香港 (4 columns), got %q", plain)
	}
}

// Regression: remote content (node names, log payloads) used to reach the
// terminal raw; a hostile OSC/ANSI sequence could hijack the terminal.
func TestSetNeutralisesControlRunes(t *testing.T) {
	s := NewScreen(40, 2)
	s.Text(0, 0, "a\x1b]52;c;ZWZvdGQ=\x07b", Normal) // OSC 52 clipboard hijack
	s.Text(0, 1, "\u009bJ", Normal)                  // 8-bit CSI + erase-display 'J'
	if got := s.cur[1].R; got != 0xfffd {
		t.Fatalf("ESC must be neutralised, got %q", got)
	}
	if got := s.cur[40].R; got != 0xfffd {
		t.Fatalf("C1 CSI must be neutralised, got %q", got)
	}
	plain := s.DumpPlain()
	if strings.ContainsRune(plain, 0x1b) || strings.ContainsRune(plain, 0x07) {
		t.Fatalf("control bytes leaked into the frame: %q", plain)
	}
	var out bytes.Buffer
	_ = s.Flush(&out)
	// Structural escapes are always ESC '[' …; an OSC can only start with ESC ']'.
	if rendered := out.String(); strings.Contains(rendered, "\x1b]") || strings.Contains(rendered, "\x07") {
		t.Fatalf("OSC payload must not survive into terminal output: %q", rendered)
	}
}

func TestResizeForcesFullRepaint(t *testing.T) {
	s := NewScreen(10, 2)
	s.Text(0, 0, "x", Normal)
	var first bytes.Buffer
	_ = s.Flush(&first)
	s.Resize(8, 2)
	s.Text(0, 0, "y", Normal)
	var second bytes.Buffer
	_ = s.Flush(&second)
	// The whole frame must repaint, not a one-cell diff.
	if !strings.Contains(second.String(), "\x1b[1;1H") {
		t.Fatalf("resize must repaint from cell 1,1: %q", second.String())
	}
}

// BenchmarkFlushFullFrame measures the worst case: every cell dirty, 100x40
// grid with CJK text (the htop-style full redraw cost).
func BenchmarkFlushFullFrame(b *testing.B) {
	s := NewScreen(100, 40)
	for y := 0; y < 40; y++ {
		s.Text(0, y, "分组 香港-01 手动选择 123ms ██████████", Normal)
	}
	var out bytes.Buffer
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.hasPrev = false // force full repaint every iteration
		out.Reset()
		_ = s.Flush(&out)
	}
}

// BenchmarkFlushOneCell is the common refresh case: a counter changed.
func BenchmarkFlushOneCell(b *testing.B) {
	s := NewScreen(100, 40)
	for y := 0; y < 40; y++ {
		s.Text(0, y, "分组 香港-01 手动选择 123ms", Normal)
	}
	var out bytes.Buffer
	_ = s.Flush(&out)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Text(20, 20, fmt.Sprintf("%03d", i%1000), Normal)
		out.Reset()
		_ = s.Flush(&out)
	}
}
