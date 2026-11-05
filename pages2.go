package main

import (
	"fmt"
	"strings"
)

// ---------------------------------------------------------------------------
// Subscriptions page: the preview → confirm → save flow of the Textual
// console, with the URL never leaving memory.
// ---------------------------------------------------------------------------

func (app *App) drawSubscriptions() {
	scr := app.scr
	top, _ := app.contentRows()
	row := top
	scr.TextLimit(2, row, scr.W-4, "订阅：u 输入 URL → 预览 → y 保存并启动｜f 使用 YAML 文件｜p 切换策略", Bold)
	row++
	policy := policyNames[app.subPolicy]
	scr.TextLimit(4, row, scr.W-8, "策略："+policy, Cyan)
	row++
	// What the chosen policy actually does. "simple" is a guided import,
	// not another name for "auto", so the page says which one it is.
	scr.TextLimit(4, row, scr.W-8, policyHelp[app.subPolicy], Dim)
	row++
	kind := "订阅 URL（内存）"
	if app.subKind == "file" {
		kind = "YAML 文件"
	}
	scr.TextLimit(4, row, scr.W-8, "来源："+kind+" ｜ 本机端口、控制器、密钥、DNS、TUN 始终保留", Dim)
	row++
	if app.subPolicyNote != "" {
		scr.TextLimit(4, row, scr.W-8, app.subPolicyNote, Yellow)
		row++
	}
	row++
	if app.subPreview == nil {
		scr.TextLimit(2, row, scr.W-4, "尚无预览。粘贴订阅 URL（u）或选择私有 YAML 文件（f）后自动生成预览。", Normal)
		row++
		scr.TextLimit(2, row, scr.W-4, "提供商策略＝订阅自带的节点/分组/规则，缺少的字段会清空；仅合并节点＝只按同名替换 proxies。", Normal)
		row++
		scr.TextLimit(2, row, scr.W-4, "标准输入导入：mihomoctl tui --stdin < 私有订阅.yaml（本原型暂用 URL/文件输入）", Normal)
		return
	}
	// The backend may answer with a different policy than the one that was
	// requested: the guided import resolves against the local configuration.
	// Both are shown, so the operator sees what will actually be written.
	if app.subEffective != "" && app.subEffective != app.subPolicy {
		requested := app.subSent
		if requested == "" {
			requested = app.subPolicy
		}
		line := "实际导入策略：" + policyLabel(app.subEffective)
		if requested != app.subEffective {
			line += "（请求：" + policyLabel(requested) + "）"
		}
		scr.TextLimit(2, row, scr.W-4, line, Cyan)
		row++
	}
	for _, line := range previewSummary(app.subPreview) {
		scr.TextLimit(2, row, scr.W-4, line, Normal)
		row++
	}
	for _, line := range clearingWarnings(app.subPreview) {
		scr.TextLimit(2, row, scr.W-4, line, Yellow|Bold)
		row++
	}
	if ignored := renderDoc(app.subPreview["ignored_fields"], "  ", 0); len(ignored) > 0 {
		scr.Text(2, row, "忽略的运行设置：", Normal)
		row++
		for _, line := range ignored {
			scr.TextLimit(4, row, scr.W-8, line, Dim)
			row++
		}
	}
	if overwrites, ok := app.subPreview["probe_overwrites"].([]any); ok && len(overwrites) > 0 {
		scr.TextLimit(2, row, scr.W-4, fmt.Sprintf("订阅将覆盖 %d 项现有探测设置；v 查看修改前后。", len(overwrites)), Yellow)
		row++
	}
	scr.TextLimit(2, row, scr.W-4, "保存将写入此预览（y）；v 查看完整变化。", Green)
	row++
	if app.subBusy {
		scr.Text(2, row, "正在保存并启动…", Bold)
	}
}

// ---------------------------------------------------------------------------
// Providers page: proxy providers from the controller, then rule providers.
// ---------------------------------------------------------------------------

func (app *App) drawProviders() {
	scr := app.scr
	top, height := app.contentRows()
	scr.Text(1, top, "提供商", Bold)
	scr.Text(30, top, "类型", Bold)
	scr.Text(42, top, "节点", Bold)
	scr.Text(52, top, "更新时间", Bold)
	needle := strings.ToLower(app.filter)
	y := top + 1
	for i, provider := range app.proxyProv {
		if y >= top+height {
			break
		}
		if needle != "" && !strings.Contains(strings.ToLower(provider.Name), needle) {
			continue
		}
		style := Style(0)
		if i == app.provIdx {
			style = Reverse
		}
		scr.TextLimit(1, y, 28, provider.Name, style)
		scr.TextLimit(30, y, 11, provider.VehicleType, style)
		scr.TextLimit(42, y, 9, fmt.Sprintf("%d", provider.NodeCount()), style)
		scr.TextLimit(52, y, 24, provider.UpdatedAt, style|Dim)
		y++
	}
	if y < top+height && len(app.ruleProv) > 0 {
		scr.Text(1, y, "规则提供商", Bold)
		y++
	}
	for _, provider := range app.ruleProv {
		if y >= top+height {
			break
		}
		if needle != "" && !strings.Contains(strings.ToLower(provider.Name), needle) {
			continue
		}
		scr.TextLimit(1, y, 28, provider.Name, 0)
		scr.TextLimit(30, y, 11, provider.Behavior, 0)
		scr.TextLimit(42, y, 9, fmt.Sprintf("%d", provider.RuleCount), 0)
		scr.TextLimit(52, y, 24, provider.UpdatedAt, Dim)
		y++
	}
	if len(app.proxyProv) == 0 && len(app.ruleProv) == 0 {
		if text, ok := pageUnavailable(app.errs, "proxy-providers", "providers"); ok {
			scr.TextLimit(2, top+1, scr.W-4, "不可用："+text, Yellow)
			return
		}
		scr.Text(2, top+1, "正在读取提供商…", Dim)
	}
}

// ---------------------------------------------------------------------------
// Profile (接入) page: profiles, bindings, redacted environment.
// ---------------------------------------------------------------------------

func (app *App) drawProfile() {
	scr := app.scr
	top, height := app.contentRows()
	if len(app.profileRows) == 0 {
		if text, ok := pageUnavailable(app.errs, "cli:profile"); ok {
			scr.TextLimit(2, top, scr.W-4, "不可用："+text, Yellow)
			return
		}
		scr.Text(2, top, "正在读取代理档案与接入声明…", Dim)
		return
	}
	drawLines(scr, top, height, app.profileRows, 0)
}

// ---------------------------------------------------------------------------
// Diagnostics page: health/doctor/journal results with explicit actions.
// ---------------------------------------------------------------------------

func (app *App) drawDiagnostics() {
	scr := app.scr
	top, height := app.contentRows()
	scr.Text(2, top, "诊断", Bold)
	scr.Text(12, top, "h health check | d doctor | j journal | u diagnose url | : diagnose process PID", Dim)
	// The evidence legend stays visible with results — that is exactly when a
	// reader needs the confirmed/inferred/unavailable vocabulary explained.
	scr.TextLimit(2, top+height-1, scr.W-4,
		"证据等级：confirmed 直接观测；inferred 间接推导；unavailable 无法观察；就绪≠模型端到端成功。", Dim)
	if len(app.diagRows) == 0 {
		scr.Text(2, top+2, "尚无结果。运行 h（健康检查）或 d（doctor）开始；结果保留到下一次运行。", Normal)
		return
	}
	scr.Text(2, top+1, "最近结果："+app.diagTitle, Cyan)
	drawLines(scr, top+3, height-4, app.diagRows, app.diagOff)
}

// ---------------------------------------------------------------------------
// Runtime (服务) page: the CLI status envelope, rendered as evidence lines.
// ---------------------------------------------------------------------------

func (app *App) drawRuntime() {
	scr := app.scr
	top, height := app.contentRows()
	rows := app.runtimeRows()
	if len(rows) == 0 {
		if text, ok := pageUnavailable(app.errs, "cli:status"); ok {
			scr.TextLimit(2, top, scr.W-4, "不可用："+text, Yellow)
			return
		}
		scr.Text(2, top, "正在读取运行时事实（mihomoctl status）…", Dim)
		return
	}
	visible := height - 1
	drawLines(scr, top, visible, rows, app.rtOff)
	hint := "七项运行时事实：核心、控制器、监听、生效配置、代理模式、TUN、错误"
	if len(rows) > visible {
		first, last := app.rtOff+1, min(app.rtOff+visible, len(rows))
		hint = fmt.Sprintf("↑↓/PgUp 滚动 · 行 %d-%d/%d｜", first, last, len(rows)) + hint
	}
	scr.TextLimit(2, top+height-1, scr.W-4, hint, Dim)
}

// runtimeRows renders the seven V1 runtime facts when the raw status
// document is available, and the envelope lines otherwise. Every fact is
// printed even when it is unknown, so a partial payload cannot read as a
// complete one.
func (app *App) runtimeRows() []string {
	if len(app.runtimeData) == 0 {
		return app.runtimeDoc
	}
	rows := runtimeFacts(app.runtimeData)
	if len(app.runtimeDoc) > 0 {
		// The evidence checks of the status envelope belong with the facts.
		for _, line := range app.runtimeDoc {
			if strings.Contains(line, "[") && strings.Contains(line, "]") {
				rows = append(rows, line)
			}
		}
	}
	return rows
}

// drawLines renders a document with clipping; callers own the title rows.
func drawLines(scr *Screen, top, height int, rows []string, offset int) {
	for i := 0; i < height; i++ {
		index := offset + i
		if index >= len(rows) {
			break
		}
		scr.TextLimit(2, top+i, scr.W-3, rows[index], 0)
	}
}

// drawInputLine renders the active text input on the footer row.
func (app *App) drawInputLine() {
	row := app.scr.H - 2
	if row < 1 {
		return
	}
	if app.input == nil {
		return
	}
	value := app.input.value
	if app.input.masked {
		value = strings.Repeat("*", len([]rune(value)))
	}
	line := " " + app.input.prompt + "：" + value + "█"
	app.scr.Row(row, truncByWidth(line, app.scr.W-1), Bold)
	if app.input.hint != "" && app.scr.H > 6 {
		app.scr.Row(app.scr.H-3, " "+truncByWidth(app.input.hint+"｜Esc 取消", app.scr.W-1), Dim)
	}
}
