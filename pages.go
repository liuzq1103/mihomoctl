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

func (app *App) drawNoticeRow() {
	row := app.scr.H - 3
	if row < 1 {
		return
	}
	if app.notice != "" {
		app.scr.Row(row, " "+truncByWidth(app.notice, app.scr.W-1), Yellow)
	} else {
		hints := map[string]string{
			pageOverview:      "数字键切换页面 | i 初始化控制器 | : 命令 | q 退出",
			pageProxies:       "Tab 切换左右 | Enter 选择 | t 测速 | T 批量 | / 过滤 | [ ] 换组",
			pageSubscriptions: "u 输入 URL | f 选择文件 | p 切换策略 | y 保存并启动",
			pageConnections:   "/ 过滤 | PgUp/PgDn 滚动",
			pageLogs:          "p 暂停 | / 过滤 | PgUp/PgDn 滚动",
			pageRules:         ": rules-check / rules-status 检查",
			pageProfile:       "只读视图；导出请在 Shell 运行 env export / integration export",
			pageProviders:     "Enter 刷新光标项 | : provider NAME",
			pageDiagnostics:   "h health | d doctor | j journal | u diagnose url | PgUp/PgDn 滚动",
			pageRuntime:       "r 刷新 | i 初始化控制器 | : start/stop/restart",
		}
		app.scr.Row(row, " "+truncByWidth(hints[app.page], app.scr.W-1), Cyan)
	}
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
		app.scr.Row(row, " 首页1 节点2 订阅3 连接4 规则5 日志6 接入7 提供商8 诊断9 服务0 | r 刷新 | : 命令 | q 退出", Dim)
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
	row := 2
	scr.Text(2, row, "当前用户的代理服务", Bold)
	row++
	scr.Text(2, row, "核心 "+valueOr(app.version, "未知")+" | 模式 "+valueOr(app.mode, "未知"), Normal)
	row++
	scr.Text(2, row, fmt.Sprintf("上传 %s/s | 下载 %s/s | 内存 %s | 连接数 %d",
		valueOr(humanBytes(app.traffic.Up), "0 B"),
		valueOr(humanBytes(app.traffic.Down), "0 B"), humanBytes(app.mem.Inuse), len(app.conns)), Normal)
	row += 2
	scr.Text(2, row, fmt.Sprintf("分组（%d 个）", len(app.groups)), Bold)
	row++
	shown := 0
	for _, name := range app.groups {
		if shown >= 8 {
			break
		}
		group := app.proxies[name]
		now := group.Now
		if now == "" {
			now = "自动"
		}
		scr.TextLimit(4, row, 8, groupTypeNames[group.Type], Dim)
		scr.Text(14, row, name, 0)
		scr.Text(38, row, "→ "+now, Green)
		row++
		shown++
	}
	// v1.4.3: local view of recent connections — destination, chain, traffic.
	scr.Text(2, row, "最近连接", Bold)
	row++
	if len(app.conns) == 0 {
		scr.Text(4, row, "暂无活跃连接", Dim)
		row++
	} else {
		for i := 0; i < min(5, len(app.conns)); i++ {
			conn := app.conns[i]
			line := fmt.Sprintf("%s | %s | %s | ↑%s ↓%s", truncByWidth(connTarget(conn), 30),
				truncByWidth(strings.Join(conn.Chains, " > "), 20), truncByWidth(conn.Rule, 12),
				humanBytes(conn.Upload), humanBytes(conn.Download))
			scr.TextLimit(4, row, app.scr.W-6, line, Normal)
			row++
		}
	}
	if row < app.scr.H-3 {
		scr.TextLimit(2, row, app.scr.W-4, "连接页查看全部连接；本地显示用，不进 CLI/日志文档。", Dim)
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
	paneW := maxInt(14, min(34, scr.W/3))
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
		if group.Now == node.name {
			scr.Text(x, y, "✓", style|Green)
		} else {
			scr.Text(x, y, " ", style)
		}
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

func (app *App) drawConnections() {
	scr := app.scr
	top, height := app.contentRows()
	x := 1
	for _, h := range []struct {
		text  string
		width int
	}{
		{"目标 / 协议", 34}, {"链路 / 规则", 30}, {"上传", 10}, {"下载", 10},
	} {
		scr.Text(x, top, h.text, Bold)
		x += h.width + 1
	}
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
		scr.TextLimit(1, y, 34, connTarget(conn), 0)
		scr.TextLimit(36, y, 30, strings.Join(conn.Chains, " > ")+" | "+conn.Rule, 0)
		scr.TextLimit(67, y, 10, humanBytes(conn.Upload), 0)
		scr.TextLimit(78, y, 10, humanBytes(conn.Download), Green)
		shown++
	}
}

func (app *App) drawLogs() {
	scr := app.scr
	top, height := app.contentRows()
	needle := strings.ToLower(app.filter)
	rows := make([]LogLine, 0, height)
	for i := len(app.logs) - 1; i >= 0 && len(rows) < height+app.logOff; i-- {
		line := app.logs[i]
		if needle != "" && !strings.Contains(strings.ToLower(line.Payload), needle) {
			continue
		}
		rows = append(rows, line)
	}
	// rows[0] is newest; show the window ending at len(rows)-logOff.
	end := maxInt(0, len(rows)-app.logOff)
	start := maxInt(0, end-height)
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
	}
}

func (app *App) drawRules() {
	scr := app.scr
	top, height := app.contentRows()
	scr.Text(1, top, "类型", Bold)
	scr.Text(30, top, "数量", Bold)
	y := top + 1
	for _, rc := range app.ruleCounts {
		if y >= top+height {
			break
		}
		scr.Text(1, y, rc.kind, 0)
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
		scr.Text(1, y, provider.Name, Cyan)
		scr.Text(30, y, fmt.Sprintf("%d · %s", provider.RuleCount, provider.Behavior), Cyan)
		y++
	}
	if len(app.ruleCounts) == 0 && len(app.ruleProv) == 0 {
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
	for y := y0; y < y0+boxH; y++ {
		for x := x0; x < x0+boxW; x++ {
			scr.Set(x, y, ' ', 0)
		}
		scr.Set(x0, y, '│', Dim)
		scr.Set(x0+boxW-1, y, '│', Dim)
	}
	for x := x0; x < x0+boxW; x++ {
		scr.Set(x, y0, '─', Dim)
		scr.Set(x, y0+boxH-1, '─', Dim)
	}
	scr.Set(x0, y0, '┌', Dim)
	scr.Set(x0+boxW-1, y0, '┐', Dim)
	scr.Set(x0, y0+boxH-1, '└', Dim)
	scr.Set(x0+boxW-1, y0+boxH-1, '┘', Dim)
	for i, line := range lines {
		scr.TextLimit(x0+2, y0+1+i, boxW-4, line, Bold)
	}
}
