package main

import (
	"fmt"
	"strings"
)

func (app *App) draw() {
	scr := app.scr
	scr.Clear()
	app.drawStatus()
	app.drawContent()
	app.drawNoticeRow()
	app.drawFooterRow()
	if app.picker != nil {
		app.drawPicker()
	}
	if app.pending != nil {
		app.drawModal()
	}
}

func (app *App) contentRows() (top, height int) {
	top = 1
	height = app.scr.H - 4
	if height < 1 {
		height = 1
	}
	return top, height
}

func (app *App) drawStatus() {
	updated := "--:--:--"
	if t, ok := app.lastFetch[kindFor(app.page)]; ok && !t.IsZero() {
		updated = t.Format("15:04:05")
	}
	parts := []string{"mihomoctl · " + pageNames[app.page]}
	if app.version != "" {
		parts = append(parts, app.version)
	}
	if app.mode != "" {
		parts = append(parts, "模式 "+app.mode)
	}
	if app.theme == ThemeLight {
		parts = append(parts, "浅色")
	}
	if errText := firstErr(app.errs); errText != "" {
		parts = append(parts, "错误 "+errText)
	}
	line := strings.Join(parts, " | ") + " | " + updated
	app.scr.Row(0, " "+truncByWidth(line, app.scr.W-1), Reverse|Bold)
}

func firstErr(errs map[string]string) string {
	for _, text := range errs {
		return text
	}
	return ""
}

// pageUnavailable reports the reason a page could not read its data.
//
// A page that has no rows must not keep showing a "loading" line forever:
// when the read failed, the real reason belongs on the page, so the operator
// sees why the data is missing instead of an endless placeholder.
func pageUnavailable(errs map[string]string, kinds ...string) (string, bool) {
	for _, kind := range kinds {
		if text, ok := errs[kind]; ok && text != "" {
			return text, true
		}
	}
	return "", false
}

func (app *App) drawNoticeRow() {
	row := app.scr.H - 3
	if row < 1 {
		return
	}
	if app.layout.tiny {
		// Below the supported size the console says so instead of drawing a
		// frame that cannot be read.
		app.scr.Row(row, " "+truncByWidth(tinyWarning(), app.scr.W-1), Yellow)
		return
	}
	if app.notice != "" {
		app.scr.Row(row, " "+truncByWidth(app.notice, app.scr.W-1), Yellow)
		return
	}
	hints := map[string]string{
		pageOverview:      "数字键切换页面 | i 初始化控制器 | : 命令 | o 选项 | q 退出",
		pageProxies:       "Tab 切换左右 | Enter 选择 | t 测速 | T 批量 | / 过滤 | [ ] 换组",
		pageSubscriptions: "u 输入 URL | f 选择文件 | p 切换策略 | y 保存并启动",
		pageConnections:   "/ 过滤 | p 暂停刷新 | PgUp/PgDn 滚动",
		pageLogs:          "p 暂停 | / 过滤 | PgUp/PgDn 滚动 | o 选项（改日志级别）",
		pageRules:         "/ 过滤 | : rules-check / rules-status 检查",
		pageProfile:       "只读视图；导出请在 Shell 运行 env export / integration export",
		pageProviders:     "/ 过滤 | Enter 刷新光标项 | : provider NAME",
		pageDiagnostics:   "h health | d doctor | j journal | u diagnose url | PgUp/PgDn 滚动",
		pageRuntime:       "r 刷新 | i 初始化控制器 | : start/stop/restart",
	}
	app.scr.Row(row, " "+truncByWidth(hints[app.page], app.scr.W-1), Cyan)
}

func (app *App) drawFooterRow() {
	row := app.scr.H - 2
	if row < 1 {
		return
	}
	if app.input != nil {
		app.drawInputLine()
	} else if app.filtering {
		app.scr.Row(row, " /"+app.filter, Bold)
	} else if app.cmdOpen {
		app.scr.Row(row, " :"+app.cmdline+"█", Bold)
	} else {
		footer := " 首页1 节点2 订阅3 连接4 规则5 日志6 接入7 提供商8 诊断9 服务0 | r 刷新 | : 命令 | o 选项 | q 退出"
		if app.layout.narrow {
			// The wide footer does not fit a narrow terminal; the page
			// numbers and the essential keys do.
			footer = " 1-0 页面 | r 刷新 | : 命令 | o 选项 | q 退出"
		}
		app.scr.Row(row, truncByWidth(footer, app.scr.W-1), Dim)
	}
}

// window centers the view on the cursor like htop does.
func window(index, length, height int) int {
	if length <= height {
		return 0
	}
	if index < height/2 {
		return 0
	}
	if index >= length-height/2 {
		return length - height
	}
	return index - height/2
}

func (app *App) drawContent() {
	switch app.page {
	case pageOverview:
		app.drawOverview()
	case pageProxies:
		app.drawProxies()
	case pageSubscriptions:
		app.drawSubscriptions()
	case pageConnections:
		app.drawConnections()
	case pageLogs:
		app.drawLogs()
	case pageRules:
		app.drawRules()
	case pageProfile:
		app.drawProfile()
	case pageProviders:
		app.drawProviders()
	case pageDiagnostics:
		app.drawDiagnostics()
	case pageRuntime:
		app.drawRuntime()
	}
}

func (app *App) drawOverview() {
	scr := app.scr
	// The content area ends above the notice and the footer rows, so the
	// extra facts never push the page under the footer.
	_, height := app.contentRows()
	limit := 1 + height
	row := 2
	scr.Text(2, row, "当前用户的代理服务", Bold)
	row++
	// The saved-but-not-applied state is the first fact of the page: a
	// configuration that is not in effect yet must not look effective.
	if app.overviewPendingRestart() {
		scr.TextLimit(2, row, scr.W-4, "配置：已保存，尚未生效，请点击重启生效", Yellow|Bold)
	} else {
		scr.TextLimit(2, row, scr.W-4, "配置：无本次待生效更改", Dim)
	}
	row++
	// The controller state comes from the service; when it is missing the
	// page says how to recover instead of showing an empty line.
	if line, connected := app.overviewController(); line != "" {
		style := Normal
		if !connected {
			style = Yellow | Bold
		}
		scr.TextLimit(2, row, scr.W-4, line, style)
		row++
		if !connected {
			scr.TextLimit(2, row, scr.W-4, "已有配置：点击初始化，再重启。缺少配置或核心：请先完成安装与私有配置。", Dim)
			row++
			scr.TextLimit(2, row, scr.W-4, "已有非本机监听或无效密钥不会被覆盖，请修正后重试。", Dim)
			row++
		}
	}
	for _, line := range app.overviewCapabilities() {
		if row >= limit {
			break
		}
		scr.TextLimit(2, row, scr.W-4, line, Yellow)
		row++
	}
	if row >= limit {
		return
	}
	scr.TextLimit(2, row, scr.W-4, "核心 "+valueOr(app.version, "未知")+" | 模式 "+valueOr(app.mode, "未知"), Normal)
	row++
	scr.TextLimit(2, row, scr.W-4, fmt.Sprintf("上传 %s/s | 下载 %s/s | 内存 %s | 连接数 %d",
		valueOr(humanBytes(app.traffic.Up), "0 B"),
		valueOr(humanBytes(app.traffic.Down), "0 B"), humanBytes(app.mem.Inuse), len(app.conns)), Normal)
	row += 2
	if row >= limit {
		return
	}
	scr.Text(2, row, fmt.Sprintf("当前节点选择（分组 %d 个）", len(app.groups)), Bold)
	row++
	shown := 0
	for _, name := range app.groups {
		// The connection list below needs six rows; the group list gives
		// them up rather than running under the footer.
		if shown >= 8 || row >= limit-6 {
			break
		}
		group := app.proxies[name]
		now := group.Now
		if now == "" {
			now = "自动"
		}
		// The type and the current selection share the row, so a narrow
		// terminal loses the selection first instead of drawing it off the
		// right edge.
		label := name
		if group.Type != "" {
			label = name + " [" + groupTypeNames[group.Type] + "]"
		}
		scr.TextLimit(4, row, 24, label, Dim)
		scr.TextLimit(30, row, maxInt(4, scr.W-31), "→ "+now, Green)
		row++
		shown++
	}
	if row >= limit {
		return
	}
	// v1.4.3: local view of recent connections — destination, chain, traffic.
	scr.Text(2, row, "最近连接", Bold)
	row++
	if len(app.conns) == 0 {
		if row < limit {
			scr.Text(4, row, "暂无活跃连接", Dim)
			row++
		}
	} else {
		for i := 0; i < min(5, len(app.conns)); i++ {
			if row >= limit {
				break
			}
			conn := app.conns[i]
			line := fmt.Sprintf("%s | %s | %s | ↑%s ↓%s", truncByWidth(connTarget(conn), 30),
				truncByWidth(strings.Join(conn.Chains, " > "), 20), truncByWidth(conn.Rule, 12),
				humanBytes(conn.Upload), humanBytes(conn.Download))
			scr.TextLimit(4, row, app.scr.W-6, line, Normal)
			row++
		}
	}
	if row < limit {
		scr.TextLimit(2, row, scr.W-4, "连接页查看全部连接；本地显示用，不进 CLI/日志文档。", Dim)
	}
}

// connTarget renders a connection destination for local display only:
// host wins, else bracketed destination IP, plus port and network protocol.
func connTarget(conn Conn) string {
	meta := conn.Metadata
	target := meta.Host
	if target == "" {
		target = meta.DstIP
		if strings.Contains(target, ":") {
			target = "[" + target + "]"
		}
	}
	if target == "" {
		target = "目标未知"
	}
	if meta.DstPort != "" {
		target += ":" + meta.DstPort
	}
	if meta.Network != "" {
		target += " / " + meta.Network
	}
	return target
}

func valueOr(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func (app *App) drawProxies() {
	scr := app.scr
	top, height := app.contentRows()
	rows := height - 1
	paneW := app.groupPaneWidth()
	// Group pane: name, type, current selection.
	scr.TextLimit(1, top, paneW-1, " 分组", Dim)
	gOff := window(app.groupIdx, len(app.groups), rows)
	for i := 0; i < rows && gOff+i < len(app.groups); i++ {
		name := app.groups[gOff+i]
		group := app.proxies[name]
		style := Style(0)
		if app.focus == 0 && i == app.groupIdx-gOff {
			style = Reverse
		}
		scr.TextLimit(1, top+1+i, 14, name, style)
		scr.TextLimit(16, top+1+i, 6, groupTypeNames[group.Type], style|Dim)
		scr.TextLimit(22, top+1+i, paneW-23, group.Now, style|Dim)
	}
	// Node pane: selection marker, name (+provider tag), latency.
	nOff := window(app.nodeIdx, len(app.nodes), rows)
	scr.TextLimit(paneW+2, top, scr.W-paneW-2, " 节点 · "+fmt.Sprint(len(app.nodes)), Dim)
	group := app.proxies[app.currentGroup()]
	for i := 0; i < rows && nOff+i < len(app.nodes); i++ {
		y := top + 1 + i
		node := app.nodes[nOff+i]
		style := Style(0)
		if app.focus == 1 && i == app.nodeIdx-nOff {
			style = Reverse
		}
		x := paneW + 2
		scr.Text(x, y, app.mark(group.Now == node.name), style|Green)
		key := nodeKey(node.name, node.provider)
		delay := "未测试"
		if app.testing[key] {
			delay = "测速中"
		} else if text, ok := app.delays[key]; ok {
			delay = text
		}
		label := node.name
		if node.provider != "" {
			label += " [" + node.provider + "]"
		}
		scr.TextLimit(x+2, y, scr.W-x-12, label, style)
		scr.TextLimit(scr.W-8, y, 7, delay, style|Dim)
	}
}

// groupPaneWidth is the width of the group column. A narrow terminal gives
// most of the room to the node list, the way the Textual console does.
func (app *App) groupPaneWidth() int {
	width := app.scr.W
	switch {
	case width >= 110:
		return min(34, width/3)
	case width >= 80:
		return min(28, width/3)
	default:
		return max(12, width/3)
	}
}

// connColumns is the column layout of the connections table. A narrow
// terminal drops the upload column and shrinks the rest, instead of drawing
// them past the right edge where nobody can read them.
type connColumns struct {
	targetX, targetW int
	chainX, chainW   int
	upX, upW         int
	downX, downW     int
	showUp           bool
}

func (app *App) connectionColumns() connColumns {
	width := app.scr.W
	switch {
	case width >= 110:
		return connColumns{1, 38, 40, 30, 71, 12, 84, 12, true}
	case width >= 80:
		return connColumns{1, 32, 34, 26, 61, 10, 72, 10, true}
	default:
		// Narrow: target and chain only, plus the download counter.
		down := 10
		chain := maxInt(8, width-30)
		return connColumns{1, 24, 26, chain, 0, 0, maxInt(1, width-down-1), down, false}
	}
}

func (app *App) drawConnections() {
	scr := app.scr
	top, height := app.contentRows()
	columns := app.connectionColumns()
	scr.Text(columns.targetX, top, "目标 / 协议", Bold)
	scr.Text(columns.chainX, top, "链路 / 规则", Bold)
	if columns.showUp {
		scr.Text(columns.upX, top, "上传", Bold)
	}
	scr.Text(columns.downX, top, "下载", Bold)
	off := clamp(app.connOff, 0, maxInt(0, len(app.conns)-height+1))
	app.connOff = off
	needle := strings.ToLower(app.filter)
	shown := 0
	for i := off; i < len(app.conns) && shown < height-1; i++ {
		conn := app.conns[i]
		if needle != "" {
			blob := strings.ToLower(strings.Join(conn.Chains, " ") + " " + connTarget(conn) + " " + conn.Rule)
			if !strings.Contains(blob, needle) {
				continue
			}
		}
		y := top + 1 + shown
		scr.TextLimit(columns.targetX, y, columns.targetW, connTarget(conn), 0)
		chain := strings.Join(conn.Chains, " > ") + " | " + conn.Rule
		if app.details && conn.RulePayload != "" {
			// The rule payload is sensitive: it only appears when the
			// operator asked for the details.
			chain += " | " + conn.RulePayload
		}
		scr.TextLimit(columns.chainX, y, columns.chainW, chain, 0)
		if columns.showUp {
			scr.TextLimit(columns.upX, y, columns.upW, humanBytes(conn.Upload), 0)
		}
		scr.TextLimit(columns.downX, y, columns.downW, humanBytes(conn.Download), Green)
		shown++
	}
	if shown == 0 && off > 0 {
		// The filter shrank the match set above the window; re-anchor to the
		// top so matches are visible instead of an empty table. The recursive
		// call terminates: the second pass runs with off == 0.
		app.connOff = 0
		app.drawConnections()
	}
}

func (app *App) drawLogs() {
	scr := app.scr
	top, height := app.contentRows()
	// The level is part of the stream request, so it is shown: a log page
	// that silently filters at another level would read as a bug.
	scr.TextLimit(1, top, scr.W-2, "日志级别："+app.logLevel+"（o 选项可切换；离开本页会停止日志流）", Dim)
	top++
	height--
	if height < 1 {
		height = 1
	}
	needle := strings.ToLower(app.filter)
	rows := make([]LogLine, 0, height)
	for i := len(app.logs) - 1; i >= 0 && len(rows) < height+app.logOff; i-- {
		line := app.logs[i]
		if needle != "" && !strings.Contains(strings.ToLower(line.Payload), needle) {
			continue
		}
		rows = append(rows, line)
	}
	// Draw-time clamp: a stale offset (the filter shrank the match set after
	// the last scroll) must never blank the page.
	app.logOff = min(app.logOff, maxInt(0, len(rows)-1))
	// rows[0] is the newest line; logOff rows are skipped from the top, so
	// PgUp (larger logOff) reveals older history instead of re-showing the
	// newest window.
	start := min(app.logOff, len(rows))
	end := min(start+height, len(rows))
	shown := rows[start:end]
	for i, line := range shown {
		y := top + height - 1 - i
		style := Style(0)
		switch line.Type {
		case "error":
			style = Red
		case "warning":
			style = Yellow
		}
		scr.TextLimit(1, y, 9, strings.ToUpper(line.Type), style|Dim)
		scr.TextLimit(11, y, scr.W-12, line.Payload, style)
	}
	if len(app.logs) == 0 {
		scr.Text(2, top, "等待日志流…", Dim)
	} else if len(rows) == 0 {
		scr.Text(2, top, "没有匹配当前过滤词的日志行", Dim)
	}
}

func (app *App) drawRules() {
	scr := app.scr
	top, height := app.contentRows()
	scr.Text(1, top, "类型", Bold)
	scr.Text(30, top, "数量", Bold)
	needle := strings.ToLower(app.filter)
	y := top + 1
	for _, rc := range app.ruleCounts {
		if y >= top+height {
			break
		}
		if needle != "" && !strings.Contains(strings.ToLower(rc.kind), needle) {
			continue
		}
		scr.TextLimit(1, y, 28, rc.kind, 0)
		scr.Text(30, y, fmt.Sprintf("%d", rc.count), 0)
		y++
	}
	if y < top+height && len(app.ruleProv) > 0 {
		scr.Text(1, y, "提供商", Bold)
		y++
	}
	for _, provider := range app.ruleProv {
		if y >= top+height {
			break
		}
		if needle != "" && !strings.Contains(strings.ToLower(provider.Name), needle) {
			continue
		}
		scr.TextLimit(1, y, 28, provider.Name, Cyan)
		scr.TextLimit(30, y, 40, fmt.Sprintf("%d · %s", provider.RuleCount, provider.Behavior), Cyan)
		y++
	}
	if len(app.ruleCounts) == 0 && len(app.ruleProv) == 0 {
		if text, ok := pageUnavailable(app.errs, "rules", "providers"); ok {
			scr.TextLimit(2, top+1, scr.W-4, "不可用："+text, Yellow)
			return
		}
		scr.Text(2, top+1, "正在读取规则…", Dim)
	}
}

func (app *App) drawModal() {
	scr := app.scr
	lines := strings.Split(app.pending.text, "\n")
	boxW := min(scr.W-4, 64)
	boxH := min(scr.H-4, len(lines)+2)
	x0 := (scr.W - boxW) / 2
	y0 := (scr.H - boxH) / 2
	vertical, horizontal := "│", "─"
	tl, tr, bl, br := "┌", "┐", "└", "┘"
	if app.ascii {
		vertical, horizontal = "|", "-"
		tl, tr, bl, br = "+", "+", "+", "+"
	}
	for y := y0; y < y0+boxH; y++ {
		for x := x0; x < x0+boxW; x++ {
			scr.Set(x, y, ' ', 0)
		}
		scr.Set(x0, y, []rune(vertical)[0], Dim)
		scr.Set(x0+boxW-1, y, []rune(vertical)[0], Dim)
	}
	for x := x0; x < x0+boxW; x++ {
		scr.Set(x, y0, []rune(horizontal)[0], Dim)
		scr.Set(x, y0+boxH-1, []rune(horizontal)[0], Dim)
	}
	scr.Set(x0, y0, []rune(tl)[0], Dim)
	scr.Set(x0+boxW-1, y0, []rune(tr)[0], Dim)
	scr.Set(x0, y0+boxH-1, []rune(bl)[0], Dim)
	scr.Set(x0+boxW-1, y0+boxH-1, []rune(br)[0], Dim)
	for i, line := range lines {
		scr.TextLimit(x0+2, y0+1+i, boxW-4, line, Bold)
	}
}

// drawPicker renders the options overlay: a titled list with the highlight
// on the current choice.
func (app *App) drawPicker() {
	scr := app.scr
	picker := app.picker
	items := picker.items()
	boxW := min(scr.W-4, 56)
	boxH := len(items) + 3
	if boxH > scr.H-2 {
		boxH = scr.H - 2
	}
	if boxH < 3 {
		boxH = 3
	}
	x0 := (scr.W - boxW) / 2
	y0 := (scr.H - boxH) / 2
	vertical, horizontal := "│", "─"
	tl, tr, bl, br := "┌", "┐", "└", "┘"
	if app.ascii {
		vertical, horizontal = "|", "-"
		tl, tr, bl, br = "+", "+", "+", "+"
	}
	for y := y0; y < y0+boxH; y++ {
		for x := x0; x < x0+boxW; x++ {
			scr.Set(x, y, ' ', 0)
		}
		scr.Set(x0, y, []rune(vertical)[0], Dim)
		scr.Set(x0+boxW-1, y, []rune(vertical)[0], Dim)
	}
	for x := x0; x < x0+boxW; x++ {
		scr.Set(x, y0, []rune(horizontal)[0], Dim)
		scr.Set(x, y0+boxH-1, []rune(horizontal)[0], Dim)
	}
	scr.Set(x0, y0, []rune(tl)[0], Dim)
	scr.Set(x0+boxW-1, y0, []rune(tr)[0], Dim)
	scr.Set(x0, y0+boxH-1, []rune(bl)[0], Dim)
	scr.Set(x0+boxW-1, y0+boxH-1, []rune(br)[0], Dim)
	title := picker.title
	if picker.level > 0 {
		title += "（返回：←）"
	}
	scr.TextLimit(x0+2, y0+1, boxW-4, title, Bold)
	for i, item := range items {
		if i+2 >= boxH-1 {
			break
		}
		marker := "  "
		style := Style(0)
		if i == picker.index {
			marker = "> "
			style = Reverse
		}
		scr.Text(x0+2, y0+2+i, marker, style)
		scr.TextLimit(x0+4, y0+2+i, boxW-6, item.label, style)
	}
}
