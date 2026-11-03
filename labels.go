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
