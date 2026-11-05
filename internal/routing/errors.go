// Package routing implements the native controller/routing backend: the
// bridged controller grammar (nodes, groups, select, latency, connections,
// traffic, providers, provider refresh, dns, mode, subscription, manual,
// override, health-check, controller, ui/dashboard) and the read-only custom
// rules contract, reproducing the mihomo-userctl v1.5.1 controller behavior
// without any Python involvement.
package routing

import (
	"fmt"
	"strings"
)

// exit codes mirror the original controller: 1 observed failure, 2 usage /
// permission / unverified.
const (
	exitFail     = 1
	exitUnverify = 2
)

// ControllerSchema is the legacy wire schema retained as part of the original
// contract; every bridged payload is emitted under it inside the envelope.
const ControllerSchema = "mihomo-userctl.controller/v1"

// RulesSchema is the custom-rules report schema from the original checker.
const RulesSchema = "mihomo-userctl.rules/v1"

// errorLabels are the exact public labels the original controller attached to
// its stable error codes (controller_types.ERROR_LABELS).
var errorLabels = map[string]string{
	"cross-level-selection-refused":                    "聚合组禁止直接选择叶子；先切子组再切入口。明确授权后才可使用 --allow-cross-level",
	"selection-target-unverified":                      "目标身份尚未确认；刷新节点与分组后重试",
	"validation-inputs-changed":                        "校验后核心或依赖资源已变化；请重新预览并保存",
	"probe-unverified":                                 "测速结果未确认",
	"controller-capability-unsupported":                "当前核心不支持此控制器接口",
	"subscription-cleanup-incomplete":                  "预览临时材料清理失败；请检查私有目录并重新预览",
	"ambiguous-node":                                   "节点名称有多个来源；请指定 --provider 或在界面选择来源",
	"node-disappeared":                                 "节点在 provider 刷新后已消失；请刷新列表",
	"node-not-in-core":                                 "节点不在核心代理表中",
	"node-unreachable":                                 "节点存在但探测失败",
	"delay-timeout":                                    "探测超时",
	"unknown-node":                                     "未知节点；请与 mihomoctl nodes --json 中的完整名称核对",
	"invalid-health-check-options":                     "必须以 group 或 provider 开头，例如 group \"Ai+\" 或 provider \"名称\"",
	"textual-environment-incomplete-use-engine-curses": "当前解释器无法导入 textual/rich；使用 mihomoctl tui --engine curses（无需安装，t 测速），或用户私有安装：bash install.sh --user --python <python> --wheelhouse <wheelhouse-dir> --extras tui; Python installs: add [tui] using the original uv/pipx/pip environment（无需 sudo 或系统 pip）",
}

// controlError is the controller error contract: a stable code, an exit code
// in {1,2} and an optional safe detail that may leave controller internals.
type controlError struct {
	code       string
	rc         int
	detail     string
	safeDetail string
}

func (e *controlError) Error() string {
	text := e.code
	if label, ok := errorLabels[e.code]; ok {
		text += "（" + label + "）"
	}
	if e.detail != "" {
		text += ": " + e.detail
	}
	return text
}

// control raises a controller error with the given exit class.
func control(code string, rc int) error { return &controlError{code: code, rc: rc} }

// controlDetail raises a controller error carrying a detail string.
func controlDetail(code, detail string, rc int) error {
	return &controlError{code: code, rc: rc, detail: detail}
}

// errorDetail joins the public label and the safe detail exactly like the
// original error_detail(): only explicitly safe projections are included.
func errorDetail(code, detail string) string {
	parts := make([]string, 0, 2)
	if label, ok := errorLabels[code]; ok && label != "" {
		parts = append(parts, label)
	}
	if detail != "" {
		parts = append(parts, detail)
	}
	return strings.Join(parts, ": ")
}

// safeFailure projects only an explicitly safe detail, bounded like the
// original safe_failure().
func safeFailure(err error) string {
	if e, ok := err.(*controlError); ok && e.safeDetail != "" && len(e.safeDetail) <= 2048 {
		return e.safeDetail
	}
	return ""
}

// detailOf returns an error's detail with the same safe-failure preference the
// bridge applied (safe detail first, plain detail only when the error carried
// one).
func detailOf(err error) string {
	if e, ok := err.(*controlError); ok {
		if safe := safeFailure(err); safe != "" {
			return errorDetail(e.code, safe)
		}
		return errorDetail(e.code, e.detail)
	}
	return ""
}

var _ = fmt.Sprintf
