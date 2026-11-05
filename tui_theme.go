package main

// Theme is the console colour scheme.
//
// The two themes differ in the ANSI accent colours they use, not in the
// layout: a dark terminal background reads the bright accents (90-97) while a
// light background reads the normal, darker ones (30-37). That is the classic
// terminal rule, and it is the whole difference between the two schemes.
type Theme string

const (
	ThemeDark  Theme = "dark"
	ThemeLight Theme = "light"
)

// valid reports whether the theme is one the console can render.
func (t Theme) valid() bool { return t == ThemeDark || t == ThemeLight }

// label is the human name shown in the options picker and the status bar.
func (t Theme) label() string {
	if t == ThemeLight {
		return "浅色"
	}
	return "深色"
}

// layout describes how much room the terminal gives the console. The Textual
// console switches between wide, narrow and compact arrangements on resize;
// this one does the same with plain column arithmetic, so a small terminal
// loses the secondary columns instead of drawing them off-screen.
type layout struct {
	width, height int
	wide          bool // >= 110 columns: every table column fits
	narrow        bool // < 80 columns: secondary columns collapse
	compact       bool // < 80 columns or < 24 rows: the chrome shrinks
	tiny          bool // < 60 columns or < 14 rows: the console says so
}

func computeLayout(width, height int) layout {
	return layout{
		width:   width,
		height:  height,
		wide:    width >= 110,
		narrow:  width < 80,
		compact: width < 80 || height < 24,
		tiny:    width < 60 || height < 14,
	}
}

// minimumSize is the smallest terminal the console can present honestly.
const (
	minimumWidth  = 60
	minimumHeight = 14
)

// tinyWarning is shown instead of a half-drawn frame when the terminal is
// below the supported size. The Textual console says the same thing and
// points at its plain engine.
func tinyWarning() string {
	return "终端至少需要 60×14；当前过小，可用数字键切换页面。"
}
