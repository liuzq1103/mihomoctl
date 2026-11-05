package main

import (
	"context"
	"errors"
	"fmt"
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
	return apiMsg{kind: kind, cliKind: display, lines: envelopeLines(env)}
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
	return apiMsg{kind: "op:" + verb, opName: verb, text: strings.Join(lines, " · ")}
}

// loadProfile fills the 接入 page: profiles, bindings and the redacted proxy
// environment, all through read-only CLI verbs.
func (app *App) loadProfile() apiMsg {
	rows := []string{}
	for _, call := range []struct{ title, line string }{
		{"代理档案", "profiles"},
		{"接入声明", "integration list"},
		{"环境变量（已脱敏）", "env show"},
	} {
		env, err := app.cli.Run(strings.Fields(call.line)...)
		if err != nil {
			rows = append(rows, call.title+"：不可用 — "+err.Error())
			continue
		}
		rows = append(rows, call.title)
		rows = append(rows, renderDoc(env.Data, "  ", 0)...)
	}
	rows = append(rows,
		"边界：环境变量只在进程创建时继承，不是网络强制策略；已运行的进程需要重启。",
		"导出：mihomoctl env export / integration export NAME（写 0600 文件，不自动部署）")
	return apiMsg{kind: "cli:profile", cliKind: "profile", lines: rows}
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
			app.subPolicy = policyOrder[(index+1)%len(policyOrder)]
			app.subPreview = nil
			app.subID, app.subSHA = "", ""
			app.subSeq++ // any in-flight preview was made for the old policy
			app.setNotice("策略已切换为 " + policyNames[app.subPolicy] + "，请重新预览")
			return
		}
	}
}

// subscriptionPreview keeps the private URL out of argv and disk: for URLs the
// UI downloads directly (proxy-free) and pipes content through stdin; files
// pass their path only.
func (app *App) subscriptionPreview(kind, value string) {
	app.subKind = kind
	app.subPreview = nil
	app.subID, app.subSHA = "", ""
	app.setNotice("正在生成预览…")
	policy := app.subPolicy // snapshot: the goroutine must not race 'p'
	// The seq in the key lets a re-preview (new URL or policy) launch while
	// an older request is still in flight; the stale result is discarded.
	app.subSeq++
	key := fmt.Sprintf("cli:subscription-preview:%d", app.subSeq)
	seq := app.subSeq
	app.post(key, func() apiMsg {
		var env Envelope
		var err error
		if kind == "url" {
			var raw []byte
			raw, err = app.src.Download(value)
			if err != nil {
				return apiMsg{kind: key, cliKind: "subscription-preview", err: err, subSeq: seq}
			}
			env, err = app.cli.RunWithStdin(raw, "subscription", "preview", "--stdin", "--policy", policy)
		} else {
			env, err = app.cli.Run("subscription", "preview", "--source-file", value, "--policy", policy)
		}
		if err != nil {
			return apiMsg{kind: key, cliKind: "subscription-preview", err: err, subSeq: seq}
		}
		if env.Overall == "PASS" && env.Data != nil {
			return apiMsg{kind: key, cliKind: "subscription-preview",
				lines: envelopeLines(env), preview: env.Data, subSeq: seq}
		}
		return apiMsg{kind: key, cliKind: "subscription-preview", lines: envelopeLines(env), subSeq: seq}
	})
}

func (app *App) askApplySubscription() {
	if app.subPreview == nil {
		app.setNotice("请先预览（u 输入 URL 或 f 选择文件），再保存")
		return
	}
	summary := strings.Join(previewSummary(app.subPreview), "\n")
	warnings := strings.Join(clearingWarnings(app.subPreview), "\n")
	message := "保存订阅并启动或重启当前用户的代理？不保留历史备份。\n" + summary
	if warnings != "" {
		message += "\n\n" + warnings
	}
	identifier, digest := app.subID, app.subSHA
	app.pending = &pendingAction{
		text: message,
		run: func(app *App) {
			app.subBusy = true
			app.post("cli:subscription-apply", func() apiMsg {
				env, err := app.cli.Run("subscription", "apply", identifier, "--sha256", digest)
				if err != nil {
					return apiMsg{kind: "cli:subscription-apply", cliKind: "subscription-apply", err: err}
				}
				return apiMsg{kind: "cli:subscription-apply", cliKind: "subscription-apply",
					lines: envelopeLines(env), applyOK: env.Overall == "PASS"}
			})
		},
	}
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
		rows, err := readJournal("mihomo", since, until, 200)
		if err != nil {
			return apiMsg{kind: "cli:journal", cliKind: "journal", err: err}
		}
		return apiMsg{kind: "cli:journal", cliKind: "journal", lines: rows, userCmd: true}
	})
	app.diagTitle = "journal"
	app.setNotice("正在读取 journal…")
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
