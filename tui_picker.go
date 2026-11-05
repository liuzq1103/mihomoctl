package main

// pickerItem is one choice in the options overlay. An item with a sub-list
// drills into a second level instead of being picked directly.
type pickerItem struct {
	label string
	value string
	sub   []pickerItem
}

// picker is the options overlay: a titled list of choices opened by a key or
// a command. The Textual console uses Select widgets for this; a terminal
// console needs its own, because there is no widget toolkit underneath.
type picker struct {
	title  string
	levels [][]pickerItem
	level  int
	index  int
	onPick func(app *App, value string)
}

func newPicker(title string, onPick func(app *App, value string)) *picker {
	return &picker{title: title, onPick: onPick}
}

// setLevel replaces the current level's items.
func (p *picker) setLevel(items []pickerItem) {
	if p.level < 0 || p.level >= len(p.levels) {
		p.levels = append(p.levels, items)
		p.level = len(p.levels) - 1
		return
	}
	p.levels[p.level] = items
	p.index = 0
}

// items returns the choices of the current level.
func (p *picker) items() []pickerItem {
	if p.level < 0 || p.level >= len(p.levels) {
		return nil
	}
	return p.levels[p.level]
}

// current returns the highlighted choice.
func (p *picker) current() (pickerItem, bool) {
	items := p.items()
	if len(items) == 0 {
		return pickerItem{}, false
	}
	p.index = clamp(p.index, 0, len(items)-1)
	return items[p.index], true
}

// move moves the highlight, wrapping around like the Textual option list.
func (p *picker) move(delta int) {
	items := p.items()
	if len(items) == 0 {
		return
	}
	p.index = (p.index + delta + len(items)) % len(items)
}

// open drills into the highlighted item's sub-list. It returns the item when
// the choice is final and must be applied.
func (p *picker) open() (pickerItem, bool) {
	item, ok := p.current()
	if !ok {
		return pickerItem{}, false
	}
	if len(item.sub) > 0 {
		p.levels = append(p.levels, item.sub)
		p.level = len(p.levels) - 1
		p.index = 0
		return pickerItem{}, false
	}
	return item, true
}

// back returns to the previous level and reports whether it did.
func (p *picker) back() bool {
	if p.level == 0 {
		return false
	}
	p.levels = p.levels[:p.level]
	p.level--
	p.index = 0
	return true
}

// pickerKey handles one key while the overlay owns the keyboard.
func (app *App) pickerKey(k Key) {
	p := app.picker
	if p == nil {
		return
	}
	switch k.Type {
	case KeyEsc:
		app.picker = nil
		return
	case KeyUp:
		p.move(-1)
		return
	case KeyDown:
		p.move(1)
		return
	case KeyHome:
		p.index = 0
		return
	case KeyEnd:
		if items := p.items(); len(items) > 0 {
			p.index = len(items) - 1
		}
		return
	case KeyLeft, KeyBackspace:
		if !p.back() {
			app.picker = nil
		}
		return
	case KeyEnter:
		item, final := p.open()
		if !final {
			return
		}
		app.picker = nil
		if p.onPick != nil {
			p.onPick(app, item.value)
		}
		return
	}
}

// openOptions shows the options list: theme, log level and character set.
// The Textual console reaches the same settings through its Select widgets
// and the ': theme' command; a plain terminal needs an explicit list.
func (app *App) openOptions() {
	p := newPicker("选项", app.applyOption)
	p.setLevel([]pickerItem{
		{label: "主题：" + app.theme.label(), value: "", sub: []pickerItem{
			{label: "深色（深色终端背景）", value: string(ThemeDark)},
			{label: "浅色（浅色终端背景）", value: string(ThemeLight)},
		}},
		{label: "日志级别：" + app.logLevel, value: "", sub: []pickerItem{
			{label: "debug", value: "debug"},
			{label: "info", value: "info"},
			{label: "warning", value: "warning"},
			{label: "error", value: "error"},
		}},
		{label: "字符集：" + app.charsetLabel(), value: "", sub: []pickerItem{
			{label: "Unicode（✓）", value: "unicode"},
			{label: "ASCII（*）", value: "ascii"},
		}},
		// The trusted script is set at startup, so the options list states
		// its status instead of pretending it can be changed here.
		{label: "受信脚本：" + app.scriptLabel(), value: "", sub: []pickerItem{
			{label: "用 : override 预览，确认后才写入", value: "script-help"},
		}},
	})
	app.picker = p
}

// charsetLabel names the current character set.
func (app *App) charsetLabel() string {
	if app.ascii {
		return "ASCII"
	}
	return "Unicode"
}

// applyOption applies one picked option value.
func (app *App) applyOption(_ *App, value string) {
	switch value {
	case string(ThemeDark), string(ThemeLight):
		app.SetTheme(Theme(value))
	case "debug", "info", "warning", "error":
		app.setLogLevel(value)
	case "ascii":
		app.SetASCII(true)
	case "unicode":
		app.SetASCII(false)
	case "script-help":
		app.setNotice("用 : override 预览受信脚本，确认后才会写入")
	}
}

// SetTheme switches the console palette.
func (app *App) SetTheme(theme Theme) {
	if !theme.valid() {
		return
	}
	app.theme = theme
	app.scr.SetTheme(theme)
	app.setNotice("主题：" + theme.label())
	app.dirty = true
}

// SetASCII switches between Unicode marks and plain ASCII ones, for
// terminals and fonts that cannot render the check mark.
func (app *App) SetASCII(ascii bool) {
	app.ascii = ascii
	app.setNotice("字符集：" + app.charsetLabel())
	app.dirty = true
}

// Configure applies the presentation options the command line carried: the
// theme name ("dark" or "light") and the plain character set. An unknown
// theme name is ignored, so a bad option never breaks the console. Unlike
// the interactive setters it stays quiet: at startup there is nothing to
// report yet.
//
// The main program calls this once, right after NewApp:
//
//	app.Configure(theme, ascii)
func (app *App) Configure(theme string, ascii bool) {
	if Theme(theme).valid() {
		app.theme = Theme(theme)
		app.scr.SetTheme(Theme(theme))
	}
	app.ascii = ascii
	app.dirty = true
}

// ApplyOptions is an alias of Configure, for callers that prefer the older
// name.
func (app *App) ApplyOptions(theme string, ascii bool) {
	app.Configure(theme, ascii)
}

// mark renders the "this one is selected" marker.
func (app *App) mark(selected bool) string {
	if selected {
		if app.ascii {
			return "*"
		}
		return "✓"
	}
	return " "
}
