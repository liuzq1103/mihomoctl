package main

import "testing"

func TestDecodeArrowsAndRunes(t *testing.T) {
	cases := []struct {
		in     string
		want   KeyType
		rune_  rune
		used   int
	}{
		{"\x1b[A", KeyUp, 0, 3},
		{"\x1b[B", KeyDown, 0, 3},
		{"\x1b[C", KeyRight, 0, 3},
		{"\x1b[D", KeyLeft, 0, 3},
		{"\x1b[5~", KeyPgUp, 0, 4},
		{"\x1b[6~", KeyPgDn, 0, 4},
		{"\x1b[3~", KeyDelete, 0, 4},
		{"\x1b[Z", KeyBackTab, 0, 3},
		{"\x1b", KeyEsc, 0, 1},
		{"q", KeyRune, 'q', 1},
		{"香", KeyRune, '香', 3},
		{"\r", KeyEnter, 0, 1},
		{"\x7f", KeyBackspace, 0, 1},
		{"\x03", KeyCtrlC, 0, 1},
	}
	for _, c := range cases {
		key, used := Decode([]byte(c.in))
		if key.Type != c.want || used != c.used || key.Rune != c.rune_ {
			t.Fatalf("Decode(%q) = {%v %d} used %d, want {%v %d} used %d",
				c.in, key.Type, key.Rune, used, c.want, c.rune_, c.used)
		}
	}
}

func TestDecodeWaitsForIncompleteEscape(t *testing.T) {
	if _, used := Decode([]byte("\x1b[")); used != 0 {
		t.Fatal("incomplete CSI sequence must report zero consumed bytes")
	}
}

func TestDecodeAltPrefixActsAsEsc(t *testing.T) {
	key, used := Decode([]byte("\x1bx"))
	if key.Type != KeyEsc || used != 1 {
		t.Fatalf("alt-prefixed input should decode as Esc consuming 1 byte, got %v used %d", key.Type, used)
	}
}
