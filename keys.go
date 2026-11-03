package main

import "unicode/utf8"

type KeyType int

const (
	KeyRune KeyType = iota
	KeyEnter
	KeyEsc
	KeyTab
	KeyBackTab
	KeyBackspace
	KeyUp
	KeyDown
	KeyLeft
	KeyRight
	KeyHome
	KeyEnd
	KeyPgUp
	KeyPgDn
	KeyDelete
	KeyCtrlC
)

type Key struct {
	Type KeyType
	Rune rune
}

// Decode turns the head of an input chunk into one key event and reports how
// many bytes it consumed. A result of zero bytes means the chunk holds an
// incomplete escape sequence and the caller should wait for more input.
func Decode(buf []byte) (Key, int) {
	if len(buf) == 0 {
		return Key{}, 0
	}
	b := buf[0]
	if b == 0x1b {
		if len(buf) == 1 {
			return Key{Type: KeyEsc}, 1
		}
		switch buf[1] {
		case '[':
			if len(buf) < 3 {
				return Key{}, 0
			}
			switch buf[2] {
			case 'A':
				return Key{Type: KeyUp}, 3
			case 'B':
				return Key{Type: KeyDown}, 3
			case 'C':
				return Key{Type: KeyRight}, 3
			case 'D':
				return Key{Type: KeyLeft}, 3
			case 'H':
				return Key{Type: KeyHome}, 3
			case 'F':
				return Key{Type: KeyEnd}, 3
			case 'Z':
				return Key{Type: KeyBackTab}, 3
			}
			// Numeric sequences end with '~': Home 1~, Delete 3~, End 4~,
			// PgUp 5~, PgDn 6~, bracketed paste 200~/201~ (swallowed).
			for i := 3; i < len(buf) && i < 8; i++ {
				if buf[i] == '~' {
					n := i + 1
					switch buf[2] {
					case '1', '7':
						return Key{Type: KeyHome}, n
					case '3':
						return Key{Type: KeyDelete}, n
					case '4', '8':
						return Key{Type: KeyEnd}, n
					case '5':
						return Key{Type: KeyPgUp}, n
					case '6':
						return Key{Type: KeyPgDn}, n
					default:
						return Key{}, n // paste markers and unknown codes
					}
				}
			}
			if len(buf) >= 8 {
				return Key{}, 1 // not a '~' sequence after all
			}
			return Key{}, 0
		case 'O':
			if len(buf) < 3 {
				return Key{}, 0
			}
			switch buf[2] {
			case 'A':
				return Key{Type: KeyUp}, 3
			case 'B':
				return Key{Type: KeyDown}, 3
			case 'C':
				return Key{Type: KeyRight}, 3
			case 'D':
				return Key{Type: KeyLeft}, 3
			case 'H':
				return Key{Type: KeyHome}, 3
			case 'F':
				return Key{Type: KeyEnd}, 3
			}
			return Key{}, 1
		default:
			return Key{Type: KeyEsc}, 1 // Alt-modified keys act as Esc here
		}
	}
	switch b {
	case 0x03:
		return Key{Type: KeyCtrlC}, 1
	case 0x0d, 0x0a:
		return Key{Type: KeyEnter}, 1
	case 0x09:
		return Key{Type: KeyTab}, 1
	case 0x7f, 0x08:
		return Key{Type: KeyBackspace}, 1
	}
	if b < 0x20 {
		return Key{}, 1 // swallow other control bytes
	}
	r, size := utf8.DecodeRune(buf)
	if r == utf8.RuneError && size <= 1 {
		if !utf8.FullRune(buf) {
			return Key{}, 0 // truncated multibyte rune; wait for continuation bytes
		}
		return Key{}, 1 // broken UTF-8; drop one byte
	}
	return Key{Type: KeyRune, Rune: r}, size
}
