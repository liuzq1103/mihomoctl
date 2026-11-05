package main

import (
	"fmt"
	"sort"
	"strings"
)

// LABELS and VALUES are ported from controller_textual.py so the Go console
// renders the same vocabulary. Node, group and provider names are user data
// and never pass through translation.
var LABELS = map[string]string{
	"state": "状态", "nodes": "节点数", "groups": "分组数", "rules": "规则数",
	"policy": "导入策略", "ignored_fields": "忽略的运行设置", "fields": "替换字段",
	"backup": "恢复备份", "service": "服务", "configuration": "配置", "added": "新增节点",
	"replaced": "替换节点", "removed": "移除节点", "removed_groups": "移除分组", "removed_rules": "移除规则",
	"group_changes": "提供商分组", "changes": "节点变化", "name": "名称", "type": "类型",
	"action": "操作", "selected": "当前选择", "error": "原因", "providers": "提供商",
	"controller": "控制器", "core": "核心", "mode": "模式", "connections": "连接数",
	"capabilities": "不可用功能", "pending_restart": "待重启", "endpoint": "端点",
	"up": "上传", "down": "下载", "inuse": "已用", "oslimit": "上限", "delay_ms": "延迟毫秒",
	"warning": "警告", "listener": "监听", "authentication": "身份验证",
	"scope_kind": "作用域", "backend": "后端", "listeners": "监听项", "proxy_mode": "代理模式",
	"tun": "TUN", "checks": "检查项", "evidence": "证据等级", "bindings": "接入",
	"profiles": "代理档案", "selected_profile": "已选用", "limits": "证据边界",
	"overall": "结论", "health": "健康检查",
	"before": "修改前", "after": "修改后", "scope": "对象类型", "kind": "操作类型",
	"affected_groups": "受影响的分组", "provider_settings": "引用提供商的探测设置",
	"probe_overwrites": "订阅覆盖的现有探测设置", "requested_policy": "请求的导入模式",
	"guid": "编号", "sha256": "摘要", "id": "编号", "message": "消息", "detail": "详情",
	"remediation": "处理建议", "code": "代码", "unit": "单元", "entries": "条目",
	"running": "运行中", "binary": "二进制", "config": "配置文件", "enabled": "已启用",
	"port": "端口", "address": "地址", "authenticated": "已认证", "current": "当前版本",
	"latest": "最新版本", "up_to_date": "已是最新", "installed": "已安装", "active": "生效",
	"mihomoctl": "mihomoctl", "schema": "架构", "proxy": "代理", "profile": "档案",
	"http": "HTTP", "socks": "SOCKS", "adapter": "适配器", "target": "目标",
	"runtime": "运行时", "errors": "错误", "active_config": "生效配置", "note": "备注",
	"outputs": "输出", "artifacts": "工件", "written": "已写入", "priority": "优先级",
	"time_us": "时间", "answers": "应答", "query": "查询", "record": "记录类型",
	"system_dns": "系统 DNS", "ttl": "TTL", "data": "数据", "process": "进程",
}

var VALUES = map[string]string{
	"preview":          "预览（尚未保存）",
	"restart-required": "已保存，尚未生效，请重启",
	"ready":            "已就绪",
	"unchanged":        "未改变",
	"auto":             "按内容自动判断",
	"provider":         "提供商节点、分组和规则",
	"nodes":            "仅合并节点",
	"policy":           "仅叠加策略（保留节点和 provider）",
	"confirmed":        "已完成",
	"add":              "新增", "replace": "替换", "remove": "移除",
	"start": "启动", "stop": "停止", "restart": "重启",
	"user": "用户", "system": "系统",
	"PASS": "通过", "FAIL": "失败", "UNVERIFIED": "未确认", "SKIPPED": "跳过",
	"records": "有记录", "no-records-in-window": "时间窗口内无记录",
}

// evidenceNames translates the evidence grade wherever it appears — checks
// lines and data rows alike — so the legend and the values agree.
var evidenceNames = map[string]string{
	"confirmed": "直接观测", "inferred": "间接推导", "unavailable": "无法观察",
}

// statusKeys carry our own enums; everything else is user data shown verbatim.
var statusKeys = map[string]bool{"state": true, "service": true, "policy": true, "action": true}

var valueKeys = map[string]bool{"overall": true, "status": true, "evidence": true, "backend": true, "scope": true}

// renderDoc walks a safe DTO into readable prose lines, never raw JSON keys —
// the Go port of report_lines. Depth-bounded like the original.
func renderDoc(value any, prefix string, depth int) []string {
	if depth > 5 {
		return nil
	}
	switch typed := value.(type) {
	case map[string]any:
		rows := []string{}
		for _, key := range sortedKeys(typed) {
			child := typed[key]
			title := LABELS[key]
			if title == "" {
				title = strings.ReplaceAll(key, "_", " ")
			}
			switch child.(type) {
			case map[string]any, []any:
				rows = append(rows, prefix+title)
				rows = append(rows, renderDoc(child, prefix+"  ", depth+1)...)
			default:
				rows = append(rows, prefix+title+": "+scalarLine(key, child))
			}
		}
		return rows
	case []any:
		rows := []string{}
		for _, child := range typed {
			rows = append(rows, renderDoc(child, prefix, depth+1)...)
		}
		return rows
	default:
		return []string{prefix + scalarLine("", value)}
	}
}

func scalarLine(key string, value any) string {
	text := fmt.Sprintf("%v", value)
	if key == "error" {
		text = "（详见 errors）"
	}
	if key == "evidence" {
		if translated, ok := evidenceNames[text]; ok {
			return translated
		}
	}
	if key != "" && (statusKeys[key] || valueKeys[key]) {
		if translated, ok := VALUES[text]; ok {
			return translated
		}
	}
	if text == "" {
		return "—"
	}
	return text
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// envelopeLines renders one CLI envelope: checks first (they carry the
// evidence model), then data rows, then errors.
func envelopeLines(env Envelope) []string {
	rows := []string{fmt.Sprintf("%s · %s · 结论 %s", env.Command, scopeLabel(env.Scope), VALUES[env.Overall])}
	for _, check := range env.Checks {
		status := check.Status
		if translated, ok := VALUES[status]; ok {
			status = translated
		}
		evidence := check.Evidence
		if translated, ok := evidenceNames[evidence]; ok {
			evidence = translated
		}
		line := fmt.Sprintf("  %s %s [%s]", status, check.Name, evidence)
		if check.Detail != "" {
			line += " " + check.Detail
		}
		rows = append(rows, line)
	}
	rows = append(rows, renderDoc(env.Data, "  ", 0)...)
	for _, err := range env.Errors {
		rows = append(rows, "  错误 "+err.Code)
		if err.Detail != "" {
			rows = append(rows, "    "+err.Detail)
		}
		if err.Remediation != "" {
			rows = append(rows, "    建议 "+err.Remediation)
		}
	}
	return rows
}

func scopeLabel(scope string) string {
	if scope == "system" {
		return "system"
	}
	return "user"
}

// previewSummary mirrors preview_summary(): the two leading lines of a
// subscription preview.
func previewSummary(preview map[string]any) []string {
	state := scalarLine("state", preview["state"])
	policy := preview["policy"]
	policyText := scalarLine("policy", policy)
	if policy == nil {
		policyText = "提供商节点、分组和规则"
	}
	count := func(key string) int {
		if v, ok := preview[key].(float64); ok {
			return int(v)
		}
		return 0
	}
	return []string{
		"状态 " + state + "｜策略 " + policyText,
		fmt.Sprintf("节点 %d（新增 %d、替换 %d、移除 %d）｜分组 %d（移除 %d）｜规则 %d（移除 %d）",
			count("nodes"), count("added"), count("replaced"), count("removed"),
			count("groups"), count("removed_groups"), count("rules"), count("removed_rules")),
	}
}

// clearingWarnings mirrors clearing_warnings(): what a provider import erases.
func clearingWarnings(preview map[string]any) []string {
	units := []string{}
	if v, ok := preview["removed_groups"].(float64); ok && v > 0 {
		units = append(units, fmt.Sprintf("%d 个本地分组", int(v)))
	}
	if v, ok := preview["removed_rules"].(float64); ok && v > 0 {
		units = append(units, fmt.Sprintf("%d 条本地规则", int(v)))
	}
	if len(units) == 0 {
		return nil
	}
	return []string{"警告：此预览会移除本地的" + strings.Join(units, "、") +
		"；提供商策略按订阅内容整体替换，不自动降级，确认后再保存；不保留历史备份。"}
}

// policyLabel names an import policy, falling back to the raw value for a
// policy this console does not know.
func policyLabel(policy string) string {
	if name, ok := policyNames[policy]; ok {
		return name
	}
	return policy
}

// guidedNote explains which of the two guided outcomes the service chose.
// The guided import is not an alias of "auto": the service looks at the
// local configuration and either keeps its routing (nodes only) or replaces
// it with a single Proxy group.
func guidedNote(effective string) string {
	if effective == "nodes" {
		return "引导导入：本地已有路由策略 → 只合并节点，保留现有分组与规则。"
	}
	return "引导导入：本地仍是简单结构 → 导入节点并生成单一 Proxy 分组，不导入远端规则。"
}

// policyNote states, in one line, how the policy that will be applied
// relates to the one the operator chose. Every deviation is reported: the
// console never lets a preview look like the requested policy was honoured
// when it was not.
func (app *App) policyNote() string {
	if app.subFallback != "" {
		return app.subFallback
	}
	if app.subSent == "" {
		return ""
	}
	if app.subSent != app.subPolicy {
		// The service refused the guided policy and the console fell back.
		return "本机服务不支持引导导入（" + policyLabel(app.subPolicy) +
			"），本次改按 " + policyLabel(app.subSent) + " 预览；请核对预览内容。"
	}
	if app.subPolicy == "simple" {
		switch {
		case app.subGuided && app.subEffective == "provider":
			return guidedNote("provider")
		case app.subEffective == "nodes":
			// The service mapped the guided request to a nodes-only merge
			// because the local configuration already carries routing.
			return guidedNote("nodes")
		}
	}
	if app.subEffective != "" && app.subEffective != app.subSent {
		return "本机服务返回的导入策略为 " + policyLabel(app.subEffective) +
			"（请求：" + policyLabel(app.subSent) + "）；请核对预览内容。"
	}
	return ""
}

// labelFor names a field, falling back to the raw key.
func labelFor(key string) string {
	if title, ok := LABELS[key]; ok {
		return title
	}
	return key
}

// summarizeItem renders one observation as a short value. A missing
// observation prints "unknown" rather than nothing, so a partial payload can
// never read as a complete one. This is presentation only: no verdict is
// decided here.
func summarizeItem(value any) string {
	switch typed := value.(type) {
	case nil:
		return "unknown"
	case bool:
		if typed {
			return "yes"
		}
		return "no"
	case float64:
		if typed == float64(int64(typed)) {
			return fmt.Sprintf("%d", int64(typed))
		}
		return fmt.Sprintf("%g", typed)
	case string:
		return typed
	case map[string]any:
		parts := []string{}
		for _, name := range sortedKeys(typed) {
			if typed[name] == nil {
				continue
			}
			parts = append(parts, labelFor(name)+"="+summarizeItem(typed[name]))
		}
		if len(parts) == 0 {
			return "unknown"
		}
		return strings.Join(parts, " ")
	case []any:
		parts := []string{}
		for index, item := range typed {
			if index >= 8 {
				break
			}
			parts = append(parts, summarizeItem(item))
		}
		return strings.Join(parts, " | ")
	default:
		return fmt.Sprintf("%v", value)
	}
}

// stringOr reads a string field, falling back to a default.
func stringOr(data map[string]any, key, fallback string) string {
	if text, ok := data[key].(string); ok && text != "" {
		return text
	}
	return fallback
}

// overviewController renders the controller state the service reported. The
// status document and the overview document describe the controller
// differently, so both shapes are accepted.
//
// The second result is false when the controller is not connected: the page
// then explains how to recover instead of printing an empty state.
func (app *App) overviewController() (string, bool) {
	data := app.overviewData
	if data == nil {
		if app.overviewErr != "" {
			return "控制器尚未连接：" + app.overviewErr, false
		}
		return "", true
	}
	if text, ok := data["controller"].(string); ok && text == "unavailable" {
		code := stringOr(data, "error", "unknown")
		return "控制器尚未连接：" + code, false
	}
	if controller, ok := data["controller"].(map[string]any); ok {
		return "控制器：" + summarizeItem(controller), true
	}
	if endpoint := stringOr(data, "endpoint", ""); endpoint != "" {
		return "控制器：" + endpoint + " | 身份验证：" + stringOr(data, "authentication", "unknown") +
			" | 监听：" + stringOr(data, "listener", "unknown"), true
	}
	return "", true
}

// overviewPendingRestart reports whether a saved change is not in effect yet.
// The service states it in the status document; the console knows it for the
// operations that only wrote a file.
func (app *App) overviewPendingRestart() bool {
	return app.pendingRestart || boolValue(app.overviewData["pending_restart"])
}

// overviewCapabilities lists the features the overview could not read. The
// service reports them in the status document; the console adds the ones its
// own controller reads could not deliver, so a partial page never reads as a
// complete one.
func (app *App) overviewCapabilities() []string {
	lines := []string{}
	if capabilities, ok := app.overviewData["capabilities"].(map[string]any); ok {
		for _, name := range sortedKeys(capabilities) {
			lines = append(lines, fmt.Sprintf("功能 %s 暂不可用：%s", name, summarizeItem(capabilities[name])))
		}
	}
	for _, feature := range []struct{ name, key string }{
		{"groups", "proxies"},
		{"connections", "connections"},
		{"mode", "configs"},
	} {
		if code, ok := app.errs[feature.key]; ok {
			lines = append(lines, fmt.Sprintf("功能 %s 暂不可用：%s", feature.name, code))
		}
	}
	return lines
}

// runtimeFacts renders the V1 runtime contract: core, controller, listeners,
// effective config, proxy mode, TUN and error.
//
// Every row is printed even when the observation is unknown, so the page
// cannot imply a healthy runtime from partial data.
func runtimeFacts(data map[string]any) []string {
	rows := []string{fmt.Sprintf("运行时 · 作用域 %s · 后端 %s · 结论 %s",
		stringOr(data, "scope", "unknown"), stringOr(data, "backend", "unknown"),
		stringOr(data, "overall", "UNVERIFIED"))}
	if reason := stringOr(data, "reason", ""); reason != "" {
		rows = append(rows, "原因："+reason)
	}
	rows = append(rows, "核心："+summarizeItem(data["core"]))
	rows = append(rows, "控制器："+summarizeItem(data["controller"]))
	rows = append(rows, "监听："+summarizeItem(data["listeners"]))
	config := data["config"]
	if config == nil {
		config = data["active_config"]
	}
	rows = append(rows, "生效配置："+summarizeItem(config))
	rows = append(rows, "代理模式："+stringOr(data, "proxy_mode", "unknown"))
	rows = append(rows, "核心路由模式："+stringOr(data, "routing_mode", "unknown"))
	tun := summarizeItem(data["tun"])
	rows = append(rows, "TUN："+tun+"（V1 默认关闭；仅管理员显式 --system 可开启）")
	if errValue := data["error"]; errValue != nil {
		rows = append(rows, "错误："+summarizeItem(errValue))
	}
	return rows
}
