package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
)

// runCLI is the single funnel into the audited Python CLI. Results render as
// envelope lines; errors carry the CLI's own diagnostic text.
func (app *App) runCLI(kind string, verb string, args []string, display string) apiMsg {
	full := append([]string{verb}, args...)
	env, err := app.cli.Run(full...)
	if err != nil {
		return apiMsg{kind: kind, cliKind: display, err: err}
	}
	// The raw document travels with the lines: pages that present a fixed
	// contract (the seven runtime facts) read the document, not the prose.
	return apiMsg{kind: kind, cliKind: display, lines: envelopeLines(env), data: env.Data, overall: env.Overall}
}

func (app *App) runLifecycleCLI(verb string) apiMsg {
	env, err := app.cli.Run(verb)
	if err != nil {
		return apiMsg{kind: "op:" + verb, opName: verb, err: err}
	}
	// A FAIL envelope is a failed op even when the CLI exits 0 with JSON on
	// stdout; announcing it as 完成 would lie to the operator.
	if env.Overall != "PASS" {
		detail := "overall-" + env.Overall
		if len(env.Errors) > 0 && env.Errors[0].Detail != "" {
			detail = env.Errors[0].Detail
		}
		return apiMsg{kind: "op:" + verb, opName: verb, err: errors.New(detail)}
	}
	// Envelope length varies with the verb's output; slicing [1:4] unguarded
	// panics on short envelopes (which would kill the whole TUI).
	lines := envelopeLines(env)
	if len(lines) > 4 {
		lines = lines[1:4]
	} else if len(lines) > 1 {
		lines = lines[1:]
	} else {
		lines = nil
	}
	return apiMsg{kind: "op:" + verb, opName: verb, text: strings.Join(lines, " · "), data: env.Data, overall: env.Overall}
}

// readStatusCLI reads the runtime facts. The raw document is kept next to the
// rendered lines, because the runtime page presents the seven V1 facts
// (core, controller, listeners, config, mode, TUN, error) explicitly instead
// of dumping whatever the envelope happens to carry.
func (app *App) readStatusCLI() apiMsg {
	env, err := app.cli.Run("status")
	if err != nil {
		return apiMsg{kind: "cli:status", cliKind: "status", err: err}
	}
	return apiMsg{kind: "cli:status", cliKind: "status", lines: envelopeLines(env), data: env.Data, overall: env.Overall}
}

// loadProfile fills the 接入 page: profiles, bindings and the redacted proxy
// environment, all through read-only CLI verbs.
func (app *App) loadProfile() apiMsg {
	rows := []string{}
	profiles, err := app.cli.Run("profiles")
	if err != nil {
		rows = append(rows, "代理档案：不可用 — "+err.Error())
	} else if failure := serviceError(profiles, nil); failure != nil {
		rows = append(rows, "代理档案：不可用 — "+failure.Error())
	} else {
		rows = append(rows, app.renderProfileRows(profiles.Data)...)
	}
	// The verbs take separate tokens: "integration list" as one argument is
	// not a command the service knows.
	bindings, err := app.cli.Run("integration", "list")
	if err != nil {
		rows = append(rows, "接入声明：不可用 — "+err.Error())
	} else if failure := serviceError(bindings, nil); failure != nil {
		rows = append(rows, "接入声明：不可用 — "+failure.Error())
	} else {
		rows = append(rows, app.renderBindingRows(bindings.Data)...)
	}
	environment, err := app.cli.Run("env", "show")
	if err != nil {
		rows = append(rows, "环境变量：不可用 — "+err.Error())
	} else if failure := serviceError(environment, nil); failure != nil {
		rows = append(rows, "环境变量：不可用 — "+failure.Error())
	} else {
		rows = append(rows, "环境变量（已脱敏）")
		rows = append(rows, renderDoc(environment.Data, "  ", 0)...)
	}
	rows = append(rows,
		"边界：环境变量只在进程创建时继承，不是网络强制策略；已运行的进程需要重启。",
		"导出：mihomoctl env export / integration export NAME（写 0600 文件，不自动部署）")
	return apiMsg{kind: "cli:profile", cliKind: "profile", lines: rows}
}

// profileRows renders the proxy profiles the way the Textual console does:
// a marker for the selected profile, then its listeners, credentials and
// bypass list. A document that does not carry the expected shape falls back
// to the generic rendering, so a newer service still shows something.
func (app *App) renderProfileRows(data map[string]any) []string {
	items, ok := data["profiles"].([]any)
	if !ok {
		fallback := []string{"代理档案"}
		return append(fallback, renderDoc(data, "  ", 0)...)
	}
	rows := []string{"代理档案 · 作用域 " + stringOr(data, "scope", "user")}
	if len(items) == 0 {
		rows = append(rows, "尚无代理档案。运行 mihomoctl init 创建默认档案。")
	}
	selected := ""
	for _, item := range items {
		row, ok := item.(map[string]any)
		if !ok {
			continue
		}
		flag, _ := row["selected"].(bool)
		name := stringOr(row, "name", "未命名")
		listeners := ""
		if items, ok := row["listeners"].([]any); ok {
			listeners = stringList(items)
		}
		if listeners == "" {
			listeners = stringList([]any{row["http"], row["socks"]})
		}
		if listeners == "" {
			listeners = "未声明"
		}
		bypass := ""
		if items, ok := row["no_proxy"].([]any); ok {
			bypass = stringList(items)
		}
		if bypass == "" {
			bypass = "未声明"
		}
		rows = append(rows, fmt.Sprintf("%s %s | 监听 %s | 凭据 %s | 绕过 %s",
			app.mark(flag), name, listeners, stringOr(row, "credentials", "external"), bypass))
		if flag {
			selected = name
		}
	}
	if selected == "" {
		rows = append(rows, "当前档案：未选择")
	} else {
		rows = append(rows, "当前档案："+selected)
	}
	return rows
}

// bindingRows renders the declared integrations. They only write
// configuration; the console never manages a third-party lifecycle.
func (app *App) renderBindingRows(data map[string]any) []string {
	rows := []string{"接入（只写配置，不管理第三方生命周期）"}
	items, ok := data["bindings"].([]any)
	if !ok {
		if table, isMap := data["bindings"].(map[string]any); isMap {
			for _, name := range sortedKeys(table) {
				row, _ := table[name].(map[string]any)
				items = append(items, map[string]any{"name": name, "adapter": row["adapter"],
					"profile": row["profile"], "target": row["target"]})
			}
		}
	}
	if len(items) == 0 {
		return append(rows, "尚无接入声明。先在 manager.yaml 定义 binding，再使用 mihomoctl integration export NAME 导出。")
	}
	for _, item := range items {
		row, ok := item.(map[string]any)
		if !ok {
			continue
		}
		target := stringOr(row, "target", "—")
		rows = append(rows, fmt.Sprintf("  %s → %s · %s · 目标 %s", stringOr(row, "name", "未命名"),
			stringOr(row, "adapter", "unknown"), stringOr(row, "profile", "default"), target))
	}
	return rows
}

// stringList renders a list of strings, skipping the empty ones.
func stringList(values []any) string {
	parts := []string{}
	for _, value := range values {
		if text, ok := value.(string); ok && text != "" {
			parts = append(parts, text)
		}
	}
	return strings.Join(parts, ", ")
}

// requestQuit leaves the console. A confirmed operation that is still
// running is not cut in half: the exit waits for it, exactly like the
// Textual console, which defers the exit until the queued work ends.
func (app *App) requestQuit() {
	if app.batchRunning {
		if app.probeCancel != nil {
			app.probeCancel()
		}
		app.exitRequested = true
		app.setNotice("正在取消排队测速；等待当前操作结束后退出")
		return
	}
	if app.opInFlight() {
		app.exitRequested = true
		app.setNotice("等待当前操作结束后退出")
		return
	}
	app.quit = true
}

// cancelAction is the Esc key: it cancels the current editing state, the
// pending preview and the running batch, in that order. The Textual console
// clears a seeded preview here too, so a half-reviewed import is never left
// on screen as if it were still pending.
func (app *App) cancelAction() {
	if app.input != nil {
		app.input = nil
		app.dirty = true
		return
	}
	if app.filtering {
		app.filtering = false
		app.filter = ""
		app.connOff, app.logOff = 0, 0
		app.rebuildNodes()
		app.dirty = true
		return
	}
	if app.cmdOpen {
		app.cmdOpen = false
		app.dirty = true
		return
	}
	cancelled := false
	if app.subPreview != nil {
		app.discardPreview()
		app.subPreview, app.subID, app.subSHA = nil, "", ""
		app.resetSubPolicy()
		app.setNotice("已取消当前预览；重新预览后才能保存")
		cancelled = true
	}
	if app.probeCancel != nil {
		app.probeCancel()
		app.setNotice("已请求取消；进行中的测速完成后停止")
		cancelled = true
	}
	if !cancelled {
		app.setNotice("")
	}
	app.dirty = true
}

// SetInitialPreview seeds a review that was prepared outside the console,
// for example a piped subscription preview. The console opens on the
// subscription page and keeps the review, exactly like the Textual console's
// initial_preview: the seeded policy is the one that was requested, so the
// page never contradicts the review the operator just prepared.
func (app *App) SetInitialPreview(preview map[string]any) {
	if preview == nil {
		return
	}
	app.subPreview = preview
	app.subID = stringValue(preview["id"])
	app.subSHA = stringValue(preview["sha256"])
	app.subEffective = stringValue(preview["policy"])
	app.subRequested = stringValue(preview["requested_policy"])
	app.subGuided = boolValue(preview["guided"])
	seeded := app.subRequested
	if seeded == "" {
		seeded = app.subEffective
	}
	if _, ok := policyNames[seeded]; ok {
		app.subPolicy = seeded
	}
	app.changePage(pageSubscriptions)
}

// discardPreview releases a private preview the user abandoned, so the
// backend can drop its temporary candidate file. It is best effort: the
// release runs in the background, and a preview also has a bounded lifetime
// of its own, so a failure here is never a console error.
func (app *App) discardPreview() {
	if app.subID == "" {
		return
	}
	discarder, ok := app.cli.(SubscriptionDiscardCli)
	if !ok {
		return
	}
	identifier := app.subID
	app.post("discard:"+identifier, func() apiMsg {
		_, err := discarder.SubscriptionDiscard(identifier)
		return apiMsg{kind: "discard:" + identifier, cliKind: "subscription-discard", err: err}
	})
}

// ---------------------------------------------------------------------------
// Node actions
// ---------------------------------------------------------------------------

func (app *App) askSelectNode() {
	groupName := app.currentGroup()
	group, ok := app.proxies[groupName]
	if !ok {
		return
	}
	if group.Type != "Selector" {
		app.setNotice("自动组由核心选择节点，可用 t 测速")
		return
	}
	if app.nodeIdx >= len(app.nodes) {
		return
	}
	node := app.nodes[app.nodeIdx]
	if node.provider != "" {
		app.setNotice("提供商节点按名称选择；同名节点无法区分来源，请使用唯一名称")
	}
	if node.name == group.Now {
		app.setNotice("已是当前选择")
		return
	}
	app.pending = &pendingAction{
		text: "将 " + groupName + " 切换为 " + node.name + "？（y 确认 / n 取消；已有连接保持打开）",
		run: func(app *App) {
			app.post("select", func() apiMsg {
				err := app.src.Select(groupName, node.name)
				return apiMsg{kind: "select", err: err, opName: "切换 " + node.name}
			})
		},
	}
}

func (app *App) probeNode() {
	if app.nodeIdx >= len(app.nodes) {
		return
	}
	node := app.nodes[app.nodeIdx]
	key := nodeKey(node.name, node.provider)
	app.testing[key] = true
	app.post("delay:"+key, func() apiMsg {
		ms, err := app.src.DelayFor(node.provider, node.name, 5000)
		return apiMsg{kind: "delay:" + key, delayNode: node.name, delayProvider: node.provider, delayMS: ms, err: err}
	})
}

// probeAll runs one delay test per visible node, four at a time, under a
// cancellable context; ': cancel' stops the queue.
func (app *App) probeAll() {
	nodes := make([]nodeEntry, len(app.nodes))
	copy(nodes, app.nodes)
	if len(nodes) == 0 {
		return
	}
	if len(nodes) > 1000 {
		nodes = nodes[:1000] // v1.4.3 batch bound
	}
	if app.batchRunning {
		app.setNotice("已有批量测速在进行；: cancel 停止")
		return
	}
	ctx, cancel := context.WithCancel(app.streamCtx)
	app.batchRunning = true
	app.probeCancel = cancel
	for _, node := range nodes {
		app.testing[nodeKey(node.name, node.provider)] = true
	}
	app.setNotice(fmt.Sprintf("批量测速 %d 个节点，最多 8 个并发；: cancel 停止", len(nodes)))
	go func() {
		// v1.4.3: at most eight probes, results displayed as they finish.
		sem := make(chan struct{}, 8)
		var wg sync.WaitGroup
		dispatched := make([]bool, len(nodes))
		var finished int32
		for i, node := range nodes {
			select {
			case <-ctx.Done():
				wg.Wait()
				// Nodes never dispatched must not stay "测速中" forever.
				skipped := []string{}
				for j, wasDispatched := range dispatched {
					if !wasDispatched {
						skipped = append(skipped, nodeKey(nodes[j].name, nodes[j].provider))
					}
				}
				app.apiCh <- apiMsg{kind: "batch-done", cancelled: true, skipped: skipped,
					batchDone: int(atomic.LoadInt32(&finished)), batchTotal: len(nodes)}
				return
			case sem <- struct{}{}:
			}
			dispatched[i] = true
			wg.Add(1)
			go func(node nodeEntry) {
				defer wg.Done()
				defer func() { <-sem }()
				ms, err := app.src.DelayFor(node.provider, node.name, 5000)
				atomic.AddInt32(&finished, 1)
				key := nodeKey(node.name, node.provider)
				app.apiCh <- apiMsg{kind: "delay:" + key, delayNode: node.name, delayProvider: node.provider, delayMS: ms, err: err}
			}(node)
		}
		wg.Wait()
		app.apiCh <- apiMsg{kind: "batch-done", batchDone: int(atomic.LoadInt32(&finished)), batchTotal: len(nodes)}
	}()
}

// ---------------------------------------------------------------------------
// Subscription flow: private input → CLI preview → explicit save.
// ---------------------------------------------------------------------------

func (app *App) askSubscriptionURL() {
	app.input = &inputState{
		prompt: "订阅 URL（粘贴后回车，仅保存在内存）",
		masked: true,
		hint:   "u 输入 URL | f 选择文件 | p 策略 | y 保存",
		submit: func(app *App, value string) { app.subscriptionPreview("url", value) },
	}
}

func (app *App) askSubscriptionFile() {
	app.input = &inputState{
		prompt: "订阅 YAML 文件路径（0600 私有文件）",
		masked: false,
		hint:   "u 输入 URL | f 选择文件 | p 策略 | y 保存",
		submit: func(app *App, value string) { app.subscriptionPreview("file", value) },
	}
}

func (app *App) cyclePolicy() {
	for index, policy := range policyOrder {
		if policy == app.subPolicy {
			app.discardPreview()
			app.subPolicy = policyOrder[(index+1)%len(policyOrder)]
			app.subPreview = nil
			app.subID, app.subSHA = "", ""
			app.resetSubPolicy()
			app.subSeq++ // any in-flight preview was made for the old policy
			app.setNotice("策略已切换为 " + policyNames[app.subPolicy] + "，请重新预览")
			return
		}
	}
}

// subscriptionPreview keeps the private URL out of argv and disk: for URLs the
// UI downloads directly (proxy-free) and pipes content through stdin; files
// pass their path only.
//
// The guided import ("simple") is a service-level operation: the CLI preview
// verb only accepts auto/nodes/provider/policy, because the guided import has
// to look at the local configuration to decide between a full provider import
// and a nodes-only merge. When the local service offers that route it is
// used; when the service refuses the policy, the console falls back to "auto"
// and says so, instead of quietly pretending that "simple" and "auto" mean
// the same thing.
func (app *App) subscriptionPreview(kind, value string) {
	policy, key, seq := app.beginPreview(kind)
	app.post(key, func() apiMsg {
		return app.previewJob(kind, value, policy, seq, key)
	})
}

// subscriptionURLFile previews the subscription whose URL is kept in a
// private file. The file is read in the worker, so the console never blocks
// on it and the URL itself stays in memory.
func (app *App) subscriptionURLFile(path string) {
	policy, key, seq := app.beginPreview("url")
	app.post(key, func() apiMsg {
		raw, err := os.ReadFile(path)
		if err != nil {
			return apiMsg{kind: key, cliKind: "subscription-preview", err: err, subSeq: seq}
		}
		value := strings.TrimSpace(string(raw))
		if value == "" {
			return apiMsg{kind: key, cliKind: "subscription-preview",
				err: errors.New("URL 文件为空"), subSeq: seq}
		}
		return app.previewJob("url", value, policy, seq, key)
	})
}

// beginPreview clears the previous preview and reserves the request
// identity that the result has to carry.
func (app *App) beginPreview(kind string) (policy, key string, seq int) {
	app.subKind = kind
	app.discardPreview()
	app.subPreview = nil
	app.subID, app.subSHA = "", ""
	app.resetSubPolicy()
	app.setNotice("正在生成预览…")
	policy = app.subPolicy // snapshot: the goroutine must not race 'p'
	// The seq in the key lets a re-preview (new URL or policy) launch while
	// an older request is still in flight; the stale result is discarded.
	app.subSeq++
	key = fmt.Sprintf("cli:subscription-preview:%d", app.subSeq)
	return policy, key, app.subSeq
}

// previewJob performs one preview request: it fetches the private payload
// once, asks the service for a preview under the chosen policy, and falls
// back to the automatic judgement when the service does not know the guided
// policy.
func (app *App) previewJob(kind, value, policy string, seq int, key string) apiMsg {
	guided, hasGuided := app.cli.(SubscriptionInputCli)
	var env Envelope
	var err error
	fallback := ""
	// The private payload is fetched once: a policy fallback must not
	// download the subscription twice.
	var raw []byte
	if kind == "url" && !hasGuided {
		raw, err = app.src.Download(value)
		if err != nil {
			return apiMsg{kind: key, cliKind: "subscription-preview", err: err, subSeq: seq}
		}
	}
	preview := func(effective string) (Envelope, error) {
		switch {
		case hasGuided:
			return guided.SubscriptionInput(value, kind, effective)
		case kind == "url":
			return app.cli.RunWithStdin(raw, "subscription", "preview", "--stdin", "--policy", effective)
		default:
			return app.cli.Run("subscription", "preview", "--source-file", value, "--policy", effective)
		}
	}
	env, err = preview(policy)
	sent := policy
	if policy == "simple" && policyRefused(env, err) {
		// The service does not know the guided policy. Fall back to the
		// automatic judgement and report it.
		sent = "auto"
		env, err = preview("auto")
		fallback = "本机服务未提供引导导入（simple），本次按自动判断预览；" +
			"引导导入会在本地仍是简单结构时导入完整节点，在本地已有路由策略时只合并节点。"
	}
	resolved := false
	if env.Data != nil {
		resolved = boolValue(env.Data["guided"])
	}
	if err != nil {
		return apiMsg{kind: key, cliKind: "subscription-preview", err: err, subSeq: seq,
			policyFallback: fallback, policySent: sent}
	}
	if env.Overall == "PASS" && env.Data != nil {
		return apiMsg{kind: key, cliKind: "subscription-preview",
			lines: envelopeLines(env), preview: env.Data, subSeq: seq,
			policyFallback: fallback, policySent: sent, guided: resolved}
	}
	return apiMsg{kind: key, cliKind: "subscription-preview", lines: envelopeLines(env),
		subSeq: seq, policyFallback: fallback, policySent: sent, guided: resolved}
}

// policyRefused reports whether the service refused the requested import
// policy, as opposed to failing for another reason.
func policyRefused(env Envelope, err error) bool {
	if err != nil {
		return strings.Contains(err.Error(), "policy")
	}
	if env.Overall == "PASS" {
		return false
	}
	for _, failure := range env.Errors {
		if strings.Contains(failure.Code, "policy") {
			return true
		}
	}
	return false
}

func (app *App) askApplySubscription() {
	if app.subPreview == nil {
		app.setNotice("请先预览（u 输入 URL 或 f 选择文件），再保存")
		return
	}
	summary := strings.Join(previewSummary(app.subPreview), "\n")
	warnings := strings.Join(clearingWarnings(app.subPreview), "\n")
	message := "保存订阅并启动或重启当前用户的代理？不保留历史备份。\n" + summary
	// The confirmed policy is part of the confirmation: the guided import
	// can resolve to another policy, and the operator confirms what will
	// actually be written.
	if app.subEffective != "" {
		message += "\n实际导入策略：" + policyLabel(app.subEffective)
	}
	if warnings != "" {
		message += "\n\n" + warnings
	}
	identifier, digest := app.subID, app.subSHA
	app.pending = &pendingAction{
		text: message,
		run: func(app *App) {
			app.subBusy = true
			app.post("cli:subscription-apply", func() apiMsg {
				return app.saveSubscription(identifier, digest)
			})
		},
	}
}

// saveSubscription applies the previewed subscription and brings the runtime
// up with it.
//
// The service owns that sequence, so the console asks for it through the
// optional capability. Without that capability the console performs the two
// steps itself — inside a confirmed action only, and it checks every
// envelope: a result that still waits for a restart is never announced as a
// started runtime.
//
// The full-screen console and the plain one share it, so both report the
// same outcome.
func saveSubscription(cli CliSource, identifier, digest string) (Envelope, []string, error) {
	if saver, ok := cli.(SubscriptionSaveAndStartCli); ok {
		env, err := saver.SubscriptionSaveAndStart(identifier, digest)
		if err != nil {
			return env, nil, err
		}
		if failure := serviceError(env, nil); failure != nil {
			return env, nil, failure
		}
		return env, envelopeLines(env), nil
	}
	env, err := cli.Run("subscription", "apply", identifier, "--sha256", digest)
	if err != nil {
		return env, nil, err
	}
	if failure := serviceError(env, nil); failure != nil {
		return env, nil, failure
	}
	lines := envelopeLines(env)
	if stringValue(env.Data["state"]) != "restart-required" {
		return env, lines, nil
	}
	// The subscription is saved, but the runtime still serves the old
	// configuration. The operator confirmed "save and start or restart", so
	// the restart belongs to this action — but its own envelope decides
	// whether it worked.
	restart, failure := cli.Run("restart")
	if failure != nil {
		return env, nil, fmt.Errorf("subscription-saved-restart-failed: %w", failure)
	}
	if failure = serviceError(restart, nil); failure != nil {
		return env, nil, fmt.Errorf("subscription-saved-restart-failed: %w", failure)
	}
	lines = append(lines, envelopeLines(restart)...)
	if env.Data == nil {
		env.Data = map[string]any{}
	}
	env.Data["state"] = "restarted"
	return env, lines, nil
}

// saveSubscription applies the previewed subscription in the full-screen
// console.
func (app *App) saveSubscription(identifier, digest string) apiMsg {
	const kind = "cli:subscription-apply"
	env, lines, err := saveSubscription(app.cli, identifier, digest)
	if err != nil {
		return apiMsg{kind: kind, cliKind: "subscription-apply", err: err, data: env.Data}
	}
	return apiMsg{kind: kind, cliKind: "subscription-apply", lines: lines, applyOK: true,
		data: env.Data, overall: env.Overall}
}

// ---------------------------------------------------------------------------
// Controller init, providers, diagnostics, chain.
// ---------------------------------------------------------------------------

func (app *App) askInitController() {
	app.pending = &pendingAction{
		text: "为当前用户创建本机控制器和随机密钥？已有安全配置将保留。保存后需重启。（y 确认 / n 取消）",
		run: func(app *App) {
			app.post("cli:controller-initialize", func() apiMsg {
				return app.runCLI("cli:controller-initialize", "controller", []string{"initialize"}, "controller-initialize")
			})
		},
	}
}

func (app *App) askRefreshProvider() {
	name := app.providerAtCursor()
	if name == "" {
		return
	}
	app.askRefreshProviderNamed(name)
}

func (app *App) providerAtCursor() string {
	if app.provIdx < len(app.proxyProv) {
		return app.proxyProv[app.provIdx].Name
	}
	return ""
}

func (app *App) askRefreshProviderNamed(name string) {
	app.pending = &pendingAction{
		text: "下载/刷新提供商 " + name + "？（y 确认 / n 取消）",
		run: func(app *App) {
			app.post("op:provider "+name, func() apiMsg {
				return apiMsg{kind: "op:provider " + name, opName: "provider " + name, err: app.src.RefreshProvider(name)}
			})
		},
	}
}

func (app *App) runHealth() {
	app.post("cli:health", func() apiMsg {
		msg := app.runCLI("cli:health", "health", []string{"check"}, "health")
		msg.userCmd = true
		return msg
	})
	app.diagTitle = "health check"
	app.setNotice("正在运行健康检查…")
}

func (app *App) runDoctor() {
	app.post("cli:doctor", func() apiMsg {
		msg := app.runCLI("cli:doctor", "doctor", nil, "doctor")
		msg.userCmd = true
		return msg
	})
	app.diagTitle = "doctor"
	app.setNotice("正在运行 doctor…")
}

func (app *App) runJournal(since, until string) {
	app.post("cli:journal", func() apiMsg {
		reader, ok := app.cli.(JournalCli)
		if !ok {
			// The journal belongs to the runtime this scope manages. A
			// console that guesses a unit name would read an unrelated
			// service's log and present it as this runtime's history, so
			// it says that the journal is not available instead.
			return apiMsg{kind: "cli:journal", cliKind: "journal",
				err: errors.New("journal-not-supported")}
		}
		env, err := reader.Journal(since, until, 200)
		if err != nil {
			return apiMsg{kind: "cli:journal", cliKind: "journal", err: err}
		}
		if failure := serviceError(env, nil); failure != nil {
			return apiMsg{kind: "cli:journal", cliKind: "journal", err: failure}
		}
		return apiMsg{kind: "cli:journal", cliKind: "journal", lines: envelopeLines(env),
			userCmd: true, data: env.Data}
	})
	app.diagTitle = "journal"
	app.setNotice("正在读取 journal…")
}

// ---------------------------------------------------------------------------
// Override script: preview, then an explicit confirmation before writing.
// ---------------------------------------------------------------------------

// ConfigureScript records the trusted override script and the explicit
// FlClash compatibility mode. The script is only ever previewed; writing it
// needs a separate confirmation.
//
// The main program calls this once, right after NewApp:
//
//	app.ConfigureScript(script, flclash)
func (app *App) ConfigureScript(script string, flclash bool) {
	app.script = strings.TrimSpace(script)
	app.flclash = flclash
	app.dirty = true
}

// scriptLabel names the trusted script in the interface.
func (app *App) scriptLabel() string {
	if app.script == "" {
		return "未设置"
	}
	if app.flclash {
		return app.script + "（FlClash 兼容）"
	}
	return app.script
}

// overrideArgs are the arguments of the override verb.
func (app *App) overrideArgs() []string {
	args := []string{"override", "--script", app.script}
	if app.flclash {
		args = append(args, "--flclash-compat")
	}
	return args
}

// askOverride previews the trusted script. The preview never writes: the
// operator confirms it separately, exactly like the original curses console,
// where the script ran for the preview and the save was its own action.
func (app *App) askOverride() {
	if app.script == "" {
		app.setNotice("未设置受信脚本（--script 路径）")
		return
	}
	app.post("cli:override", func() apiMsg {
		args := app.overrideArgs()
		env, err := app.cli.Run(args...)
		if err != nil {
			return apiMsg{kind: "cli:override", cliKind: "override", err: err}
		}
		if failure := serviceError(env, nil); failure != nil {
			return apiMsg{kind: "cli:override", cliKind: "override", err: failure,
				data: env.Data}
		}
		return apiMsg{kind: "cli:override", cliKind: "override", lines: envelopeLines(env),
			data: env.Data, overall: env.Overall}
	})
	app.setNotice("正在预览脚本…")
}

// applyOverride writes the reviewed script result. It runs only after the
// operator confirmed the preview.
func (app *App) applyOverride() {
	if app.script == "" {
		app.setNotice("未设置受信脚本（--script 路径）")
		return
	}
	app.pending = &pendingAction{
		text: "保存脚本预览得到的配置？不会保留历史备份，需要单独重启生效。（y 确认 / n 取消）",
		run: func(app *App) {
			app.post("op:override", func() apiMsg {
				args := append(app.overrideArgs(), "--apply")
				env, err := app.cli.Run(args...)
				if err != nil {
					return apiMsg{kind: "op:override", opName: "override", err: err}
				}
				if failure := serviceError(env, nil); failure != nil {
					return apiMsg{kind: "op:override", opName: "override", err: failure,
						data: env.Data}
				}
				lines := envelopeLines(env)
				if len(lines) > 4 {
					lines = lines[1:4]
				}
				return apiMsg{kind: "op:override", opName: "override",
					text: strings.Join(lines, " · "), data: env.Data, overall: env.Overall}
			})
		},
	}
}

func (app *App) askDiagnoseURL() {
	app.input = &inputState{
		prompt: "诊断 URL（公网 HTTPS，无凭据无查询串）",
		masked: false,
		hint:   "经本机代理出站，验证出口；不泄露凭据",
		submit: func(app *App, value string) { app.diagnoseURL(value) },
	}
}

func (app *App) diagnoseURL(target string) {
	app.post("cli:diagnose-url", func() apiMsg {
		msg := app.runCLI("cli:diagnose-url", "health", []string{"check", "--egress-url", target}, "diagnose url")
		msg.userCmd = true
		return msg
	})
	app.diagTitle = "diagnose url"
	app.setNotice("正在探测出口…")
}

func (app *App) diagnoseProcess(pid string) {
	port := app.listenerPort() // snapshot: the goroutine must not race onAPI
	app.post("cli:diagnose-process", func() apiMsg {
		rows, err := inspectProcess(pid, port)
		if err != nil {
			return apiMsg{kind: "cli:diagnose-process", cliKind: "diagnose process", err: err}
		}
		return apiMsg{kind: "cli:diagnose-process", cliKind: "diagnose process", lines: rows, userCmd: true}
	})
	app.diagTitle = "diagnose process"
	app.setNotice("正在读取 /proc…")
}

// showChain follows the current group's selection through nested groups, the
// read-only view behind the Textual console's : chain.
func (app *App) showChain() {
	start := app.currentGroup()
	if start == "" {
		return
	}
	chain := []string{}
	seen := map[string]bool{}
	for name := start; name != ""; {
		if seen[name] {
			chain = append(chain, name+"（循环！）")
			break
		}
		seen[name] = true
		group, ok := app.proxies[name]
		if !ok {
			break
		}
		if group.Now == "" {
			chain = append(chain, name+" → 自动")
			break
		}
		chain = append(chain, name)
		next := group.Now
		if _, isGroup := app.proxies[next]; !isGroup {
			chain = append(chain, next)
			break
		}
		name = next
	}
	app.pending = &pendingAction{
		text: "当前链路：\n" + strings.Join(chain, " → ") +
			"\n\n同名节点无法区分来源；共享入口的修改会影响引用它的所有分组。",
		run: func(app *App) {},
	}
}
