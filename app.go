package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	pageOverview      = "overview"
	pageProxies       = "proxies"
	pageSubscriptions = "subscriptions"
	pageConnections   = "connections"
	pageRules         = "rules"
	pageLogs          = "logs"
	pageProfile       = "profile"
	pageProviders     = "providers"
	pageDiagnostics   = "diagnostics"
	pageRuntime       = "runtime"
)

// The V1 page set, matching the Textual console one to one.
var pageOrder = []string{
	pageOverview, pageProxies, pageSubscriptions, pageConnections, pageRules,
	pageLogs, pageProfile, pageProviders, pageDiagnostics, pageRuntime,
}

// pageAliases keeps the retained identifiers working. "profiles" is the old
// name of the subscription page; the profile page (代理档案与接入声明) is a
// genuinely different destination and keeps its own name.
var pageAliases = map[string]string{
	"profiles": pageSubscriptions,
}

// resolvePage maps a retained page identifier onto the canonical one.
func resolvePage(page string) string {
	if alias, ok := pageAliases[page]; ok {
		return alias
	}
	return page
}

var pageNames = map[string]string{
	pageOverview: "首页", pageProxies: "节点", pageSubscriptions: "订阅", pageConnections: "连接",
	pageRules: "规则", pageLogs: "日志", pageProfile: "接入", pageProviders: "提供商",
	pageDiagnostics: "诊断", pageRuntime: "服务",
}

// groupTypeNames matches the Textual console's group vocabulary.
var groupTypeNames = map[string]string{
	"Selector": "手动选择", "URLTest": "自动测速", "Fallback": "故障转移",
	"LoadBalance": "负载均衡", "Relay": "链式",
}

var policyOrder = []string{"simple", "provider", "nodes", "policy", "auto"}
var policyNames = map[string]string{
	"simple": "简单节点选择", "provider": "订阅完整策略", "nodes": "仅合并节点",
	"policy": "仅叠加策略", "auto": "自动判断（按内容）",
}

// policyHelp explains what each import policy actually does. "simple" is not
// an alias of "auto": it is the guided import that decides between a full
// provider import and a nodes-only merge by looking at the local config.
var policyHelp = map[string]string{
	"simple":   "引导导入：本地仍是简单结构时导入节点并生成单一 Proxy 分组；本地已有路由策略时只合并节点，保留现有分组与规则。",
	"provider": "采用订阅自带的节点、分组和规则；缺少的策略字段会被清空（预览下方显示移除数量）。",
	"nodes":    "只按同名替换 proxies，分组与规则保留；订阅只含顶层 proxies 时使用。",
	"policy":   "只叠加订阅的策略（分组、规则），保留本地节点与 provider。",
	"auto":     "按订阅内容自动判断：含路由字段则整份导入，否则只合并节点。",
}

// logLevels are the levels the log stream can be opened at.
var logLevels = []string{"debug", "info", "warning", "error"}

// refresh intervals per page, in seconds; streamed or manual pages are absent.
var pageInterval = map[string]float64{
	pageOverview: 2, pageProxies: 5, pageConnections: 2, pageRules: 10, pageRuntime: 5,
}

type apiMsg struct {
	kind string
	err  error

	proxies       *ProxiesDoc
	conns         *ConnectionsDoc
	rules         *RulesDoc
	providers     *RuleProvidersDoc
	pProv         *ProxyProvidersDoc
	version       *VersionDoc
	configs       *ConfigsDoc
	memory        *MemoryDoc
	delayNode     string
	delayProvider string
	delayMS       int
	opName        string
	text          string
	traffic       <-chan Traffic
	logs          <-chan LogLine

	// CLI results carry rendered lines; preview also carries the raw doc.
	cliKind string
	lines   []string
	preview map[string]any
	data    map[string]any
	overall string
	applyOK bool

	// Batch probe completion: which nodes never started, how many finished.
	cancelled  bool
	skipped    []string
	batchDone  int
	batchTotal int

	// userCmd marks a CLI call the operator typed, so its completion deserves
	// a notice; page auto-refreshes must stay silent.
	userCmd bool
	// silent marks automatic page refreshes: their failures show in the
	// status bar only, never as a notice or a clobbered lastResult.
	silent bool
	// subSeq ties a subscription preview to the request that launched it,
	// so a stale result never installs after the user re-previews.
	subSeq int
	// generation ties a stream open to the stream generation that asked
	// for it, so a late result from a closed stream is never adopted.
	generation int
	// policyFallback explains a preview that ran with another import
	// policy than the one that was requested.
	policyFallback string
	// policySent is the import policy the console actually sent, which is
	// not always the chosen one: a service that does not know the guided
	// policy gets "auto" instead.
	policySent string
	// guided reports that the service resolved the guided import itself.
	guided bool
}

// pendingAction is a modal confirm; destructive verbs need one explicit key.
type pendingAction struct {
	text string
	run  func(app *App)
}

// inputState is the one text-entry widget: prompt line, optional masking,
// submit callback. Private values never reach argv or disk.
type inputState struct {
	prompt string
	masked bool
	value  string
	hint   string
	submit func(app *App, value string)
}

// App holds the whole console. One goroutine owns every field: input, timers,
// network results, CLI results and streams all arrive as events through the
// Run select, so a key press is answered by the very next draw and never
// queued behind I/O.
type App struct {
	src   Source
	cli   CliSource
	scr   *Screen
	out   *os.File
	demo  bool
	page  string
	quit  bool
	dirty bool

	// theme and ascii are the presentation switches the Textual console
	// exposes as --theme and --ascii.
	theme  Theme
	ascii  bool
	layout layout

	// details includes the sensitive connection details (the rule payload).
	// They stay hidden unless the operator asks for them.
	details bool

	// script is the trusted override script (--script) and flclash is the
	// explicit FlClash compatibility mode for it (--flclash-compat).
	script  string
	flclash bool

	apiCh     chan apiMsg
	inflight  map[string]bool
	lastFetch map[string]time.Time
	errs      map[string]string

	proxies  map[string]Proxy
	groups   []string
	groupIdx int
	nodes    []nodeEntry
	nodeIdx  int
	reverse  bool
	focus    int // 0 groups pane, 1 nodes pane

	// nodeProvider maps a node name to its provider (v1.4.3 node directory);
	// empty means a global node. Used for provider-scoped healthcheck routes
	// and duplicate-name disambiguation.
	nodeProvider map[string]string

	filter    string
	filtering bool

	delays  map[string]string
	testing map[string]bool

	conns   []Conn
	connOff int

	logs   []LogLine
	logOff int

	ruleCounts []ruleCount
	ruleProv   []RuleProvider

	version     string
	mode        string
	configsPort int
	traffic     Traffic
	mem         MemoryDoc

	trafficCh <-chan Traffic
	logCh     <-chan LogLine
	streamCtx context.Context
	cancelAll context.CancelFunc

	// Each stream owns its own cancel: leaving the logs page must not stop
	// the traffic stream, and vice versa.
	trafficCtx    context.Context
	trafficCancel context.CancelFunc
	logCtx        context.Context
	logCancel     context.CancelFunc

	// logLevel is the level the log stream is opened at. Changing it
	// restarts the stream, because the level is part of the request.
	logLevel string

	// logGen and trafficGen number the stream opens, so a late result from
	// a stream that was closed in the meantime is never adopted. Each
	// stream has its own counter, so opening one never invalidates the
	// other.
	logGen     int
	trafficGen int

	// Reconnect backoff for dropped streams (controller restart, suspend):
	// a closed stream nils its channel in Run, onTick reopens it after this
	// cooldown so a down controller is not hammered.
	trafficRetryAt time.Time
	logsRetryAt    time.Time
	// logsOpened gates global log-stream reconnect to sessions that ever
	// opened the stream (visiting the logs page).
	logsOpened bool

	pending  *pendingAction
	input    *inputState
	cmdOpen  bool
	cmdline  string
	notice   string
	noticeAt time.Time

	// picker is the options overlay (theme, log level, character set).
	picker *picker

	// paused freezes the page's automatic refresh, like the Textual
	// console's p binding on the logs and connections pages.
	paused bool

	// exitRequested defers the exit until the running operation finishes,
	// so a confirmed action is never cut in half by the quit key.
	exitRequested bool

	// overviewData is the service status the overview page shows: the
	// controller state, the pending restart and the unavailable features.
	// It arrives asynchronously, so the page never waits for it.
	overviewData map[string]any
	// overviewErr is the last status failure; the overview shows it in
	// place of the status instead of the status bar.
	overviewErr string
	// pendingRestart records that a change was saved but is not in effect
	// yet. The service reports it in the status document as well; the
	// console keeps it for the operations that only write the file.
	pendingRestart bool

	// Subscription flow: source selection, policy, current preview.
	subKind    string // "url" or "file"
	subPolicy  string
	subPath    string
	subPreview map[string]any
	subID      string
	subSHA     string
	subBusy    bool
	// subEffective is the policy the backend actually applied, which can
	// differ from the requested one (the guided "simple" import resolves
	// against the local configuration).
	subEffective string
	// subRequested is the policy the console asked for.
	subRequested string
	// subSent is the policy the console really sent: a service that does
	// not know the guided policy receives "auto" instead of "simple".
	subSent string
	// subGuided reports that the service resolved the guided import, so
	// the page can say which of the two guided outcomes it was.
	subGuided bool
	// subFallback carries the loud report of a guided import that the
	// local service could not perform.
	subFallback string
	// subPolicyNote explains a fallback: the guided import was requested
	// but the local service cannot perform it.
	subPolicyNote string
	// subSeq invalidates in-flight previews: any result whose seq does not
	// match was launched for an older URL/policy and must be discarded.
	subSeq int

	// CLI-backed pages.
	runtimeDoc  []string
	runtimeData map[string]any
	rtOff       int
	profileRows []string
	diagRows    []string
	diagTitle   string
	diagOff     int

	proxyProv []ProxyProvider
	provIdx   int

	// Last operation result, shown by v.
	lastResult []string
	lastTitle  string

	probeCancel  context.CancelFunc
	batchRunning bool
}

type ruleCount struct {
	kind  string
	count int
}

// nodeEntry is one visible node with its provider identity ("" = global).
type nodeEntry struct {
	name     string
	provider string
}

func NewApp(src Source, cli CliSource, w, h int, page string, demo bool) *App {
	app := &App{
		src: src, cli: cli, scr: NewScreen(w, h), out: os.Stdout, demo: demo,
		page: page, apiCh: make(chan apiMsg, 64),
		inflight: map[string]bool{}, lastFetch: map[string]time.Time{},
		errs: map[string]string{}, delays: map[string]string{}, testing: map[string]bool{},
		focus: 1, subKind: "url", subPolicy: "simple", nodeProvider: map[string]string{},
		theme: ThemeDark, logLevel: "info",
	}
	app.layout = computeLayout(w, h)
	app.streamCtx, app.cancelAll = context.WithCancel(context.Background())
	app.page = resolvePage(app.page)
	if _, ok := pageNames[app.page]; !ok {
		app.page = pageOverview
	}
	return app
}

// SetDetails includes the sensitive connection details in the connections
// view.
//
// The console hides them by default: the source projects every connection
// down to the fields a human may read, and only an explicit request adds
// the rule payload back. The setting reaches the source through its
// optional capability, so a source that cannot show the details simply
// keeps hiding them.
//
// The main program calls this once, right after NewApp:
//
//	app.SetDetails(details)
func (app *App) SetDetails(enabled bool) {
	app.details = enabled
	if source, ok := app.src.(ConnectionDetailsSource); ok {
		source.SetConnectionDetails(enabled)
	}
	app.dirty = true
}

// post launches one fetch; the kind doubles as the dedupe key so a slow
// request can never pile up behind itself.
func (app *App) post(kind string, fetch func() apiMsg) {
	if app.inflight[kind] {
		return
	}
	app.inflight[kind] = true
	app.lastFetch[kind] = time.Now()
	go func() { app.apiCh <- fetch() }()
}

func (app *App) refresh(page string) {
	switch page {
	case pageOverview:
		app.post("version", func() apiMsg { v, err := app.src.Version(); return apiMsg{kind: "version", err: err, version: &v} })
		app.post("configs", func() apiMsg { c, err := app.src.Configs(); return apiMsg{kind: "configs", err: err, configs: &c} })
		app.post("memory", func() apiMsg { m, err := app.src.Memory(); return apiMsg{kind: "memory", err: err, memory: &m} })
		app.post("proxies", func() apiMsg { p, err := app.src.Proxies(); return apiMsg{kind: "proxies", err: err, proxies: &p} })
		app.post("connections", func() apiMsg {
			c, err := app.src.Connections()
			return apiMsg{kind: "connections", err: err, conns: &c}
		})
		app.refreshOverviewStatus()
	case pageProxies:
		app.post("proxies", func() apiMsg { p, err := app.src.Proxies(); return apiMsg{kind: "proxies", err: err, proxies: &p} })
		app.post("proxy-providers", func() apiMsg {
			p, err := app.src.ProxyProviders()
			return apiMsg{kind: "proxy-providers", err: err, pProv: &p}
		})
	case pageConnections:
		app.post("connections", func() apiMsg {
			c, err := app.src.Connections()
			return apiMsg{kind: "connections", err: err, conns: &c}
		})
	case pageRules:
		app.post("rules", func() apiMsg { r, err := app.src.Rules(); return apiMsg{kind: "rules", err: err, rules: &r} })
		app.post("providers", func() apiMsg {
			p, err := app.src.RuleProviders()
			return apiMsg{kind: "providers", err: err, providers: &p}
		})
	case pageProviders:
		app.post("proxy-providers", func() apiMsg {
			p, err := app.src.ProxyProviders()
			return apiMsg{kind: "proxy-providers", err: err, pProv: &p}
		})
		app.post("providers", func() apiMsg {
			p, err := app.src.RuleProviders()
			return apiMsg{kind: "providers", err: err, providers: &p}
		})
	case pageLogs:
		// Mark intent at request time: a failed first open must also be
		// retried by onTick, not only drops of an established stream.
		app.logsOpened = true
		app.openLogStream()
	case pageRuntime:
		app.post("cli:status", func() apiMsg {
			msg := app.readStatusCLI()
			msg.silent = true // auto refresh: errors stay in the status bar
			return msg
		})
	case pageProfile:
		app.post("cli:profile", func() apiMsg {
			msg := app.loadProfile()
			msg.silent = true
			return msg
		})
	}
}

// openLogStream opens the log stream at the current level. An established
// stream is never opened twice: the level is part of the request, so a level
// change closes the stream first and then reopens it.
//
// Every open carries its own key and generation: a stream that was closed
// while its open was still in flight must not block the new open, and its
// late result must never be adopted.
func (app *App) openLogStream() {
	if app.logCh != nil {
		return
	}
	if app.logCancel != nil {
		app.logCancel()
		app.logCancel = nil
	}
	ctx, cancel := context.WithCancel(app.streamCtx)
	app.logCtx, app.logCancel = ctx, cancel
	// A failed open waits for the backoff instead of retrying every tick.
	app.logsRetryAt = time.Now().Add(5 * time.Second)
	level := app.logLevel
	app.logGen++
	generation := app.logGen
	kind := fmt.Sprintf("logs-open:%d", generation)
	app.lastFetch["logs-open"] = time.Now()
	app.post(kind, func() apiMsg {
		ch, err := app.startLogs(ctx, level)
		return apiMsg{kind: kind, err: err, logs: ch, generation: generation}
	})
}

// startLogs opens the log stream, using the level-aware route when the
// source supports it and the plain one otherwise.
func (app *App) startLogs(ctx context.Context, level string) (<-chan LogLine, error) {
	if leveled, ok := app.src.(LogLevelSource); ok {
		return leveled.StartLogsAt(ctx, level)
	}
	return app.src.StartLogs(ctx)
}

// closeLogStream stops the log stream. The logs page owns the stream: it
// runs only while the page is open, exactly like the Textual console.
// Closing also invalidates a pending open, so a result that arrives after
// the page was left is never adopted.
func (app *App) closeLogStream() {
	app.logGen++
	if app.logCancel != nil {
		app.logCancel()
		app.logCancel = nil
	}
	app.logCh = nil
	app.logsOpened = false
}

// setLogLevel changes the level the log stream runs at and restarts the
// stream, because the level is part of the stream request.
func (app *App) setLogLevel(level string) {
	if !slices.Contains(logLevels, level) {
		app.setNotice("日志级别必须是 debug|info|warning|error")
		return
	}
	if level == app.logLevel {
		app.setNotice("日志级别：" + level + "（未变化）")
		return
	}
	app.logLevel = level
	app.closeLogStream()
	if app.page == pageLogs {
		app.refresh(pageLogs) // reopen at the new level
	}
	app.setNotice("日志级别：" + level)
	app.dirty = true
}

// openTraffic opens the traffic stream. Only the overview page shows
// traffic, so the stream belongs to that page and stops with it.
func (app *App) openTraffic() {
	if app.trafficCh != nil {
		return
	}
	if app.trafficCancel != nil {
		app.trafficCancel()
		app.trafficCancel = nil
	}
	ctx, cancel := context.WithCancel(app.streamCtx)
	app.trafficCtx, app.trafficCancel = ctx, cancel
	// A failed open waits for the backoff instead of retrying every tick.
	app.trafficRetryAt = time.Now().Add(5 * time.Second)
	app.trafficGen++
	generation := app.trafficGen
	kind := fmt.Sprintf("traffic-open:%d", generation)
	app.post(kind, func() apiMsg {
		ch, err := app.src.StartTraffic(ctx)
		return apiMsg{kind: kind, err: err, traffic: ch, generation: generation}
	})
}

// closeTrafficStream stops the traffic stream. Like the log stream, closing
// invalidates a pending open.
func (app *App) closeTrafficStream() {
	app.trafficGen++
	if app.trafficCancel != nil {
		app.trafficCancel()
		app.trafficCancel = nil
	}
	app.trafficCh = nil
}

func (app *App) Run() error {
	defer app.cancelAll()
	keys := make(chan Key, 32)
	go readKeys(keys)
	resize := watchResize()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	app.refresh(app.page)
	if app.page == pageOverview {
		app.openTraffic()
	}
	app.dirty = true
	for !app.quit {
		select {
		case k, ok := <-keys:
			if !ok {
				app.quit = true
				break
			}
			app.onKey(k)
			app.dirty = true
		case msg := <-app.apiCh:
			app.onAPI(msg)
			app.dirty = true
		case tr, ok := <-app.trafficCh:
			if ok {
				app.traffic = tr
				app.dirty = true
			} else {
				// Stream ended (closed channel stays ready forever in select);
				// nil it to stop a busy-spin and let onTick reconnect.
				app.trafficCh = nil
				app.setNotice("流量数据流中断，自动重连中…")
			}
		case line, ok := <-app.logCh:
			if !ok {
				app.logCh = nil
				app.setNotice("日志流中断，自动重连中…")
			} else if !app.paused || line.Type == "error" {
				// Pausing holds back the firehose, never stream-break markers.
				app.logs = append(app.logs, line)
				if len(app.logs) > 1000 {
					app.logs = app.logs[len(app.logs)-1000:]
				}
				app.dirty = true
			}
		case <-resize:
			w, h := termSize()
			app.scr.Resize(w, h)
			app.layout = computeLayout(w, h)
			app.dirty = true
		case <-tick.C:
			app.onTick()
		}
		if app.dirty && !app.quit {
			app.draw()
			_ = app.scr.Flush(app.out)
			app.dirty = false
		}
	}
	return nil
}

func (app *App) onTick() {
	now := time.Now()
	if interval := pageInterval[app.page]; interval > 0 && !app.paused {
		if now.Sub(app.lastFetch[kindFor(app.page)]) > time.Duration(interval*float64(time.Second)) {
			app.refresh(app.page)
		}
	}
	if app.notice != "" && time.Since(app.noticeAt) > 8*time.Second {
		app.notice = ""
		app.dirty = true
	}
	// Reopen dropped streams with a cooldown; inflight dedupe in post()
	// keeps a slow attempt from piling up. Only the page that owns a stream
	// reconnects it: the logs stream belongs to the logs page, the traffic
	// stream to the overview page.
	if app.page == pageOverview && app.trafficCh == nil && now.After(app.trafficRetryAt) {
		app.trafficRetryAt = now.Add(5 * time.Second)
		app.openTraffic()
	}
	if app.page == pageLogs && app.logsOpened && app.logCh == nil && now.After(app.logsRetryAt) {
		app.logsRetryAt = now.Add(5 * time.Second)
		app.openLogStream()
	}
}

func kindFor(page string) string {
	switch page {
	case pageOverview:
		return "version"
	case pageConnections:
		return "connections"
	case pageRules:
		return "rules"
	case pageLogs:
		return "logs-open"
	case pageRuntime:
		return "cli:status"
	case pageProfile:
		return "cli:profile"
	case pageProviders:
		return "proxy-providers"
	default:
		return "proxies"
	}
}

// refreshOverviewStatus fetches the service status the overview shows: the
// controller state, the pending restart and the unavailable features. It is
// a service read, not a controller read, so it runs less often than the
// traffic and connection snapshots.
func (app *App) refreshOverviewStatus() {
	if time.Since(app.lastFetch["cli:status:overview"]) < 5*time.Second {
		return
	}
	app.post("cli:status:overview", func() apiMsg {
		env, err := app.cli.Run("status")
		if err != nil {
			return apiMsg{kind: "cli:status:overview", cliKind: "status", err: err, silent: true}
		}
		return apiMsg{kind: "cli:status:overview", cliKind: "status", data: env.Data, overall: env.Overall}
	})
}

func (app *App) onAPI(msg apiMsg) {
	delete(app.inflight, msg.kind)
	if msg.kind == "cli:status:overview" {
		// The overview shows this status itself, so a failure belongs on the
		// page and not in the status bar.
		if msg.err != nil {
			app.overviewErr = msg.err.Error()
			app.overviewData = nil
		} else {
			app.overviewErr = ""
			app.overviewData = msg.data
		}
		return
	}
	if msg.err != nil {
		// Releasing an abandoned preview is best effort: a failure must not
		// surface as a console error, so it is dropped instead of recorded.
		if strings.HasPrefix(msg.kind, "discard:") {
			return
		}
		app.errs[msg.kind] = msg.err.Error()
		// CLI ops surface as a notice plus a failed result, not a stuck page —
		// except automatic page refreshes, which stay status-bar-only.
		if strings.HasPrefix(msg.kind, "cli:") && !msg.silent {
			app.lastTitle, app.lastResult = msg.cliKind, []string{"操作未完成：" + msg.err.Error()}
			app.setNotice(msg.cliKind + " 失败：" + truncByWidth(msg.err.Error(), 80))
		}
		if strings.HasPrefix(msg.kind, "op") {
			app.setNotice(msg.opName + " 失败：" + truncByWidth(msg.err.Error(), 80))
		}
		if msg.kind == "cli:subscription-apply" {
			app.subBusy = false // a failed apply must not strand the page in "saving…"
			// A saved subscription whose restart failed still waits for a
			// restart, so the overview has to say so.
			if stringValue(msg.data["state"]) == "restart-required" {
				app.pendingRestart = true
			}
		}
		if strings.HasPrefix(msg.kind, "delay:") {
			delete(app.testing, nodeKey(msg.delayNode, msg.delayProvider))
			app.delays[nodeKey(msg.delayNode, msg.delayProvider)] = "失败"
		}
		return
	}
	delete(app.errs, msg.kind)
	// Operator actions announce completion and refresh the page. Each op
	// carries its own key (op:start, op:mode x, op:provider n) so one slow op
	// can never swallow a different, user-confirmed one.
	if msg.kind == "op" || strings.HasPrefix(msg.kind, "op:") {
		// A change that was saved but is not in effect yet must be visible
		// on the overview; a restart brings it into effect.
		if stringValue(msg.data["state"]) == "restart-required" {
			app.pendingRestart = true
		}
		if msg.opName == "start" || msg.opName == "restart" {
			app.pendingRestart = false
		}
		if msg.text != "" {
			app.setNotice(msg.opName + " 完成：" + msg.text)
		} else {
			app.setNotice(msg.opName + " 完成")
		}
		app.refresh(app.page)
	}
	// Stream opens carry their own key and generation. A stream whose page
	// was left, or whose generation was superseded, is dropped: its context
	// is cancelled, so the producer goroutine ends on its own.
	if strings.HasPrefix(msg.kind, "traffic-open") {
		if msg.traffic != nil && app.page == pageOverview && app.trafficCh == nil &&
			msg.generation == app.trafficGen {
			app.trafficCh = msg.traffic
		}
	}
	if strings.HasPrefix(msg.kind, "logs-open") {
		if msg.logs != nil && app.page == pageLogs && app.logCh == nil &&
			msg.generation == app.logGen {
			app.logCh = msg.logs
		}
	}
	switch msg.kind {
	case "proxies":
		if msg.proxies != nil {
			app.setProxies(msg.proxies.Proxies)
		}
	case "connections":
		if msg.conns != nil {
			app.conns = msg.conns.Connections
			app.sortConns()
		}
	case "rules":
		if msg.rules != nil {
			counts, order := map[string]int{}, []string{}
			for _, rule := range msg.rules.Rules {
				if _, seen := counts[rule.Type]; !seen {
					order = append(order, rule.Type)
				}
				counts[rule.Type]++
			}
			app.ruleCounts = nil
			for _, kind := range order {
				app.ruleCounts = append(app.ruleCounts, ruleCount{kind, counts[kind]})
			}
		}
	case "providers":
		if msg.providers != nil {
			app.ruleProv = nil
			for _, provider := range msg.providers.Providers {
				app.ruleProv = append(app.ruleProv, provider)
			}
			sort.Slice(app.ruleProv, func(i, j int) bool { return app.ruleProv[i].Name < app.ruleProv[j].Name })
		}
	case "proxy-providers":
		if msg.pProv != nil {
			app.proxyProv = nil
			// The node directory (v1.4.3): provider-owned names get provider
			// identity; the core's implicit Compatible provider mirrors the
			// global table and is skipped.
			directory := map[string]string{}
			for _, provider := range msg.pProv.Providers {
				app.proxyProv = append(app.proxyProv, provider)
				if provider.VehicleType == "Compatible" {
					continue
				}
				for _, raw := range provider.Proxies {
					var node struct {
						Name string `json:"name"`
					}
					if json.Unmarshal(raw, &node) == nil && node.Name != "" {
						if _, clash := directory[node.Name]; !clash {
							directory[node.Name] = provider.Name
						}
					}
				}
			}
			app.nodeProvider = directory
			sort.Slice(app.proxyProv, func(i, j int) bool { return app.proxyProv[i].Name < app.proxyProv[j].Name })
			app.provIdx = clamp(app.provIdx, 0, len(app.proxyProv)-1)
			app.rebuildNodes() // late directory arrivals must re-tag visible nodes
		}
	case "version":
		if msg.version != nil {
			app.version = msg.version.Version
		}
	case "configs":
		if msg.configs != nil {
			app.mode = msg.configs.Mode
			app.configsPort = firstPositive(msg.configs.MixedPort, msg.configs.Port, msg.configs.SocksPort)
		}
	case "memory":
		if msg.memory != nil {
			app.mem = *msg.memory
		}
	case "select":
		app.refresh(pageProxies)
		app.refresh(pageOverview)
	case "batch-done":
		app.batchRunning = false
		app.probeCancel = nil
		for _, node := range msg.skipped {
			delete(app.testing, node)
			app.delays[node] = "已取消"
		}
		if msg.cancelled {
			app.setNotice(fmt.Sprintf("批量测速已取消（完成 %d/%d）", msg.batchDone, msg.batchTotal))
		} else if app.page == pageProxies {
			app.setNotice("批量测速完成")
		}
	}
	// Silent auto-refreshes update their page state below but must not touch
	// the operator's last result ('v') or fire notices.
	if msg.cliKind != "" {
		if !msg.silent {
			app.lastTitle, app.lastResult = msg.cliKind, msg.lines
			if msg.userCmd {
				app.setNotice(msg.cliKind + " 完成，按 v 查看结果")
			}
		}
		switch msg.cliKind {
		case "status":
			app.runtimeDoc = msg.lines
			if msg.data != nil {
				app.runtimeData = msg.data
				if _, ok := app.runtimeData["overall"]; !ok && msg.overall != "" {
					// The conclusion belongs to the envelope, not to the
					// data document: copy before adding it, so the envelope
					// stays untouched for everyone else.
					copied := make(map[string]any, len(app.runtimeData)+1)
					for key, value := range app.runtimeData {
						copied[key] = value
					}
					copied["overall"] = msg.overall
					app.runtimeData = copied
				}
			}
		case "profile":
			app.profileRows = msg.lines
		case "health", "doctor", "journal", "diagnose url", "diagnose process":
			app.diagRows = msg.lines
			app.diagOff = 0
			app.diagTitle = msg.cliKind
		}
	}
	if strings.HasPrefix(msg.kind, "delay:") {
		key := nodeKey(msg.delayNode, msg.delayProvider)
		delete(app.testing, key)
		app.delays[key] = fmt.Sprintf("%d", msg.delayMS)
	}
	// Subscription preview/apply results drive the subscription page state.
	// Stale previews (the user changed URL or policy after the request
	// launched) must never install: each result carries its request's seq.
	if strings.HasPrefix(msg.kind, "cli:subscription-preview") {
		switch {
		case msg.subSeq != app.subSeq:
			app.setNotice("预览已过期（来源或策略已变更），请重新预览")
		case msg.preview != nil:
			app.subPreview = msg.preview
			app.subID = stringValue(msg.preview["id"])
			app.subSHA = stringValue(msg.preview["sha256"])
			// The backend may answer with a different policy than the one
			// that was requested: the guided import resolves against the
			// local configuration. Everything that is known about the
			// policy is kept, so the page can state what will be written.
			app.subEffective = stringValue(msg.preview["policy"])
			app.subRequested = stringValue(msg.preview["requested_policy"])
			app.subSent = msg.policySent
			app.subGuided = msg.guided
			app.subFallback = msg.policyFallback
			app.subPolicyNote = app.policyNote()
			app.setNotice("预览就绪：y 保存并启动（会先确认）")
		default:
			app.setNotice("预览被拒绝，按 v 查看原因")
		}
	}
	if msg.kind == "cli:subscription-apply" {
		app.subBusy = false
		// A saved subscription that only waits for a restart is pending
		// until the runtime is restarted.
		state := stringValue(msg.data["state"])
		if state == "restart-required" {
			app.pendingRestart = true
		}
		if msg.applyOK {
			app.subPreview, app.subID, app.subSHA = nil, "", ""
			app.resetSubPolicy()
			if state == "restart-required" {
				// The file is written, but the runtime still serves the old
				// configuration: announcing "saved and started" here would
				// be a lie.
				app.setNotice("订阅已保存，尚未生效，请重启")
			} else {
				if state == "restarted" {
					app.pendingRestart = false
				}
				app.setNotice("订阅已保存并启动")
			}
			app.changePage(pageProxies)
		}
	}
	// The script preview never writes: it opens the confirmation that does.
	if msg.kind == "cli:override" {
		app.applyOverride()
	}
	// A deferred exit waits for the confirmed operation that is still
	// running, so quitting never cuts a started action in half.
	if app.exitRequested && !app.opInFlight() && !app.batchRunning {
		app.quit = true
	}
}

// opInFlight reports whether a confirmed operation is still running.
func (app *App) opInFlight() bool {
	for key := range app.inflight {
		switch {
		case key == "op", key == "select", key == "cli:subscription-apply":
			return true
		case strings.HasPrefix(key, "op:"):
			return true
		}
	}
	return false
}

func stringValue(value any) string {
	if text, ok := value.(string); ok {
		return text
	}
	return ""
}

// boolValue reads a boolean observation out of a service payload.
func boolValue(value any) bool {
	if flag, ok := value.(bool); ok {
		return flag
	}
	return false
}

// resetSubPolicy clears everything that is known about the import policy of
// the last preview, so a new request never shows the previous one's
// provenance.
func (app *App) resetSubPolicy() {
	app.subEffective, app.subRequested, app.subSent = "", "", ""
	app.subGuided, app.subFallback = false, ""
	app.subPolicyNote = ""
}

func (app *App) setProxies(proxies map[string]Proxy) {
	app.proxies = proxies
	names := make([]string, 0, len(proxies))
	for name, proxy := range proxies {
		switch proxy.Type {
		case "Selector", "URLTest", "Fallback", "LoadBalance", "Relay":
			names = append(names, name)
		}
	}
	sort.Strings(names)
	app.groups = names
	if app.groupIdx >= len(names) {
		app.groupIdx = 0
	}
	app.rebuildNodes()
}

func (app *App) currentGroup() string {
	if app.groupIdx < len(app.groups) {
		return app.groups[app.groupIdx]
	}
	return ""
}

// nodeKey identifies a latency result: same-name nodes from different
// providers must not overwrite each other (v1.4.3 duplicate disambiguation).
func nodeKey(name, provider string) string {
	if provider == "" {
		return name
	}
	return provider + "/" + name
}

func (app *App) rebuildNodes() {
	app.nodes = app.nodes[:0]
	group := app.proxies[app.currentGroup()]
	if group.All == nil {
		return
	}
	needle := strings.ToLower(app.filter)
	for _, name := range group.All {
		if needle == "" || strings.Contains(strings.ToLower(name), needle) {
			app.nodes = append(app.nodes, nodeEntry{name: name, provider: app.nodeProvider[name]})
		}
	}
	sort.SliceStable(app.nodes, func(i, j int) bool {
		a, b := strings.ToLower(app.nodes[i].name), strings.ToLower(app.nodes[j].name)
		if app.reverse {
			return a > b
		}
		return a < b
	})
	app.nodeIdx = clamp(app.nodeIdx, 0, len(app.nodes)-1)
}

func (app *App) sortConns() {
	sort.SliceStable(app.conns, func(i, j int) bool {
		return app.conns[i].Download > app.conns[j].Download
	})
}

func (app *App) setNotice(text string) {
	app.notice = text
	app.noticeAt = time.Now()
}

// changePage switches pages. It accepts the retained "profiles" identifier
// for the subscription page, and moves the streams that belong to a page:
// the log stream belongs to the logs page, the traffic stream to the
// overview page.
func (app *App) changePage(page string) {
	page = resolvePage(page)
	if _, ok := pageNames[page]; !ok {
		return
	}
	leaving := app.page
	app.page = page
	app.connOff, app.logOff, app.diagOff, app.rtOff = 0, 0, 0, 0
	// A filter is page-scoped intent; never let a stale one silently hide
	// content on the next page (there is no always-visible filter indicator).
	app.filter, app.filtering = "", false
	app.rebuildNodes() // drop the previously filtered node list immediately
	app.paused = false
	if leaving == pageLogs && page != pageLogs {
		app.closeLogStream()
	}
	if leaving == pageOverview && page != pageOverview {
		app.closeTrafficStream()
	}
	if page == pageOverview {
		// The service status belongs to the overview; fetch it again as
		// soon as the page is open instead of waiting for the cooldown.
		delete(app.lastFetch, "cli:status:overview")
	}
	app.refresh(page)
	if page == pageOverview {
		app.openTraffic()
	}
}

func (app *App) onKey(k Key) {
	if app.pending != nil {
		app.onModalKey(k)
		return
	}
	if app.picker != nil {
		app.pickerKey(k)
		return
	}
	if app.input != nil {
		app.onInputKey(k)
		return
	}
	if app.cmdOpen {
		app.onCmdKey(k)
		return
	}
	if app.filtering {
		app.onFilterKey(k)
		return
	}
	switch k.Type {
	case KeyCtrlC:
		app.requestQuit()
		return
	case KeyEsc:
		app.cancelAction()
		return
	case KeyTab:
		if app.page == pageProxies {
			app.focus = 1 - app.focus
		} else {
			app.changePage(nextPage(app.page, 1))
		}
		return
	case KeyBackTab:
		if app.page == pageProxies {
			app.focus = 1 - app.focus
		} else {
			app.changePage(nextPage(app.page, -1))
		}
		return
	case KeyEnter:
		app.onEnter()
		return
	case KeyLeft:
		if app.page == pageProxies {
			app.focus = 0
		}
		return
	case KeyRight:
		if app.page == pageProxies {
			app.focus = 1
		}
		return
	case KeyUp:
		app.moveCursor(-1)
		return
	case KeyDown:
		app.moveCursor(1)
		return
	case KeyHome:
		app.cursorTo(0)
		return
	case KeyEnd:
		app.cursorTo(app.listLen() - 1)
		return
	case KeyPgUp:
		app.scroll(-1)
		return
	case KeyPgDn:
		app.scroll(1)
		return
	}
	if k.Type != KeyRune {
		return
	}
	switch k.Rune {
	case 'q':
		app.requestQuit()
	case 'r':
		// No inflight wipe: post() already dedupes, and clearing the map
		// mid-flight lets a second stream open strand the first's goroutine.
		app.refresh(app.page)
		if app.page != pageOverview {
			app.refresh(pageOverview)
		}
		app.setNotice("已刷新")
	case '1', '2', '3', '4', '5', '6', '7', '8', '9', '0':
		index := int(k.Rune - '1')
		if k.Rune == '0' {
			index = 9
		}
		if index < len(pageOrder) {
			app.changePage(pageOrder[index])
		}
	case '/':
		// Only pages that actually consume the filter open filter mode;
		// elsewhere '/' would be a dead editing state.
		switch app.page {
		case pageProxies, pageConnections, pageLogs, pageProviders, pageRules:
			app.filtering = true
		}
	case ':':
		app.cmdOpen = true
		app.cmdline = ""
	case '?':
		app.pending = &pendingAction{text: helpText, run: func(app *App) {}}
	case 'o':
		app.openOptions()
	case 's':
		app.onKeySort()
	case 't':
		if app.page == pageProxies {
			app.probeNode()
		}
	case 'T':
		if app.page == pageProxies {
			app.probeAll()
		}
	case 'p':
		switch app.page {
		case pageLogs:
			app.paused = !app.paused
			app.setNotice(map[bool]string{true: "已暂停", false: "已继续"}[app.paused])
		case pageConnections:
			app.paused = !app.paused
			app.setNotice(map[bool]string{true: "已暂停刷新", false: "已继续刷新"}[app.paused])
		case pageSubscriptions:
			app.cyclePolicy()
		}
	case 'v':
		if len(app.lastResult) > 0 {
			app.pending = &pendingAction{text: app.lastTitle + "\n" + strings.Join(app.lastResult, "\n"), run: func(app *App) {}}
		}
	case '[':
		if app.page == pageProxies && app.groupIdx > 0 {
			app.groupIdx--
			app.rebuildNodes()
		}
	case ']':
		if app.page == pageProxies && app.groupIdx < len(app.groups)-1 {
			app.groupIdx++
			app.rebuildNodes()
		}
	case 'g':
		app.cursorTo(0)
	case 'G':
		app.cursorTo(app.listLen() - 1)
	case 'u':
		app.onKeyU()
	case 'f':
		if app.page == pageSubscriptions {
			app.askSubscriptionFile()
		}
	case 'y':
		if app.page == pageSubscriptions {
			app.askApplySubscription()
		}
	case 'h':
		if app.page == pageDiagnostics {
			app.runHealth()
		}
	case 'd':
		if app.page == pageDiagnostics {
			app.runDoctor()
		}
	case 'j':
		if app.page == pageDiagnostics {
			app.runJournal("", "")
		}
	case 'i':
		if app.page == pageOverview || app.page == pageRuntime {
			app.askInitController()
		}
	}
}

func (app *App) onKeySort() {
	switch app.page {
	case pageProxies:
		app.reverse = !app.reverse
		app.rebuildNodes()
		app.setNotice("排序：" + map[bool]string{true: "降序", false: "升序"}[app.reverse])
	case pageProviders:
		app.setNotice(": provider NAME 手动刷新；Enter 刷新光标项")
	}
}

func (app *App) onKeyU() {
	switch app.page {
	case pageSubscriptions:
		app.askSubscriptionURL()
	case pageDiagnostics:
		app.askDiagnoseURL()
	}
}

func (app *App) nextPageHandler(delta int) string { return nextPage(app.page, delta) }

func nextPage(page string, delta int) string {
	for i, name := range pageOrder {
		if name == page {
			return pageOrder[(i+delta+len(pageOrder))%len(pageOrder)]
		}
	}
	return pageOrder[0]
}

func (app *App) listLen() int {
	switch app.page {
	case pageProxies:
		if app.focus == 0 {
			return len(app.groups)
		}
		return len(app.nodes)
	case pageLogs:
		return len(app.logs)
	case pageRuntime:
		return app.runtimeMaxScroll() + 1
	case pageProviders:
		return len(app.proxyProv) + len(app.ruleProv)
	case pageRules:
		return len(app.ruleCounts) + len(app.ruleProv)
	}
	return 0
}

func (app *App) cursorIndex() int {
	switch app.page {
	case pageProxies:
		if app.focus == 0 {
			return app.groupIdx
		}
		return app.nodeIdx
	case pageLogs:
		return maxInt(0, len(app.logs)-1-app.logOff)
	case pageProviders:
		return app.provIdx
	case pageRuntime:
		return app.rtOff
	case pageRules:
		return 0
	}
	return 0
}

func (app *App) moveCursor(delta int) {
	switch app.page {
	case pageProxies, pageProviders, pageLogs, pageRuntime:
		app.cursorTo(app.cursorIndex() + delta)
	}
}

func (app *App) cursorTo(index int) {
	switch app.page {
	case pageProxies:
		if app.focus == 0 {
			app.groupIdx = clamp(index, 0, len(app.groups)-1)
		} else {
			app.nodeIdx = clamp(index, 0, len(app.nodes)-1)
		}
	case pageProviders:
		app.provIdx = clamp(index, 0, len(app.proxyProv)+len(app.ruleProv)-1)
	case pageLogs:
		app.logOff = clamp(len(app.logs)-1-index, 0, maxInt(0, len(app.logs)-1))
	case pageRuntime:
		app.rtOff = clamp(index, 0, app.runtimeMaxScroll())
	}
}

func (app *App) runtimeMaxScroll() int {
	return maxInt(0, len(app.runtimeRows())-(app.scr.H-5))
}

// scroll moves the long documents; each page's step is its own viewport size
// so paging never skips rows, and max offsets keep the last row reachable.
func (app *App) scroll(delta int) {
	switch app.page {
	case pageLogs:
		// drawLogs windows `contentRows` height rows ending at len-logOff.
		step := maxInt(1, app.scr.H-4)
		app.logOff = clamp(app.logOff-delta*step, 0, maxInt(0, len(app.logs)-1))
	case pageConnections:
		// Table body is contentRows height minus the header row.
		step := maxInt(1, app.scr.H-5)
		app.connOff = clamp(app.connOff+delta*step, 0, maxInt(0, len(app.conns)-1))
	case pageDiagnostics:
		// Viewport is contentRows height minus title/header/legend rows;
		// offset == len would render zero rows, so cap at len-1.
		step := maxInt(1, app.scr.H-8)
		app.diagOff = clamp(app.diagOff+delta*step, 0, maxInt(0, len(app.diagRows)-1))
	case pageRuntime:
		step := maxInt(1, app.scr.H-5)
		app.rtOff = clamp(app.rtOff+delta*step, 0, app.runtimeMaxScroll())
	case pageSubscriptions:
		// no scrolling; the preview fits the page by design
	}
}

func clamp(v, low, high int) int {
	if high < low {
		return low
	}
	if v < low {
		return low
	}
	if v > high {
		return high
	}
	return v
}

// dropLastRune removes the final rune, not the final byte, so backspace never
// splits a multi-byte character into invalid UTF-8.
func dropLastRune(s string) string {
	if s == "" {
		return s
	}
	_, size := utf8.DecodeLastRuneInString(s)
	return s[:len(s)-size]
}

func (app *App) onEnter() {
	switch app.page {
	case pageProxies:
		if app.focus == 0 {
			return
		}
		app.askSelectNode()
	case pageProviders:
		app.askRefreshProvider()
	}
}

func (app *App) onModalKey(k Key) {
	if k.Type == KeyRune && (k.Rune == 'y' || k.Rune == 'Y') || k.Type == KeyEnter {
		action := app.pending
		app.pending = nil
		action.run(app)
		return
	}
	app.pending = nil
}

func (app *App) onInputKey(k Key) {
	switch k.Type {
	case KeyEsc:
		app.input = nil
	case KeyEnter:
		current := app.input
		app.input = nil
		value := strings.TrimSpace(current.value)
		if value != "" {
			current.submit(app, value)
		}
	case KeyBackspace:
		app.input.value = dropLastRune(app.input.value)
	case KeyRune:
		app.input.value += string(k.Rune)
	}
}

func (app *App) onFilterKey(k Key) {
	// Any filter edit re-anchors scrolling: the previous offset can point
	// past the newly filtered row set and blank the whole page.
	resetScroll := func() { app.connOff, app.logOff = 0, 0 }
	switch k.Type {
	case KeyEsc:
		// Esc cancels the whole filter, not just the editing line: a filter
		// left applied with no indicator looks like vanishing content.
		app.filtering = false
		app.filter = ""
		app.connOff, app.logOff = 0, 0
		app.rebuildNodes()
	case KeyEnter:
		app.filtering = false
		resetScroll()
		app.rebuildNodes()
	case KeyBackspace:
		app.filter = dropLastRune(app.filter)
		resetScroll()
		app.rebuildNodes()
	case KeyRune:
		app.filter += string(k.Rune)
		resetScroll()
		app.rebuildNodes()
	}
}

func (app *App) onCmdKey(k Key) {
	switch k.Type {
	case KeyEsc:
		app.cmdOpen = false
	case KeyEnter:
		app.cmdOpen = false
		app.executeCommand(app.cmdline)
	case KeyBackspace:
		app.cmdline = dropLastRune(app.cmdline)
	case KeyRune:
		app.cmdline += string(k.Rune)
	}
}

// Known verbs get native handling; anything else passes straight to the
// audited CLI and renders its envelope, which is what makes the command set
// complete by construction. exec/direct stay CLI-only by design.
func (app *App) executeCommand(line string) {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return
	}
	verb, rest := fields[0], fields[1:]
	switch verb {
	case "q", "quit":
		app.requestQuit()
		return
	case "page":
		if len(rest) == 1 {
			resolved := resolvePage(rest[0])
			if _, ok := pageNames[resolved]; !ok {
				app.setNotice("未知页面：" + rest[0] + "（可用：" + strings.Join(pageOrder, " ") + "）")
				return
			}
			app.changePage(resolved)
		}
		return
	case "theme":
		if len(rest) == 1 && Theme(rest[0]).valid() {
			app.SetTheme(Theme(rest[0]))
		} else {
			app.setNotice("用法：theme dark|light")
		}
		return
	case "log-level":
		if len(rest) == 1 {
			app.setLogLevel(rest[0])
		} else {
			app.setNotice("用法：log-level debug|info|warning|error")
		}
		return
	case "help":
		app.pending = &pendingAction{text: helpText, run: func(app *App) {}}
		return
	case "cancel":
		if app.probeCancel != nil {
			app.probeCancel()
			app.setNotice("已请求取消；进行中的测速完成后停止")
		} else {
			app.setNotice("当前没有进行中的批量测速")
		}
		return
	case "mode":
		app.cmdMode(rest)
		return
	case "start", "stop", "restart":
		app.cmdLifecycle(verb)
		return
	case "init":
		app.askInitController()
		return
	case "override":
		// The trusted script is previewed; writing it needs the separate
		// confirmation that the preview opens.
		app.askOverride()
		return
	case "dns":
		app.cmdDNS(rest)
		return
	case "provider":
		if len(rest) == 1 {
			app.askRefreshProviderNamed(rest[0])
		}
		return
	case "subscribe":
		// The file is previewed under the policy the subscription page
		// currently shows, exactly like the baseline console.
		if len(rest) != 1 {
			app.setNotice("用法：subscribe FILE")
			return
		}
		app.subscriptionPreview("file", rest[0])
		return
	case "subscribe-url":
		// The URL lives in a private file; it is read in the worker and
		// never reaches a command line.
		if len(rest) != 1 {
			app.setNotice("用法：subscribe-url PRIVATE_URL_FILE")
			return
		}
		app.subscriptionURLFile(rest[0])
		return
	case "journal":
		since, until := "", ""
		for i := 0; i+1 < len(rest); i += 2 {
			if rest[i] == "--since" {
				since = rest[i+1]
			}
			if rest[i] == "--until" {
				until = rest[i+1]
			}
		}
		app.runJournal(since, until)
		return
	case "chain":
		app.showChain()
		return
	case "diagnose":
		if len(rest) == 2 {
			if rest[0] == "url" {
				app.diagnoseURL(rest[1])
			} else if rest[0] == "process" {
				app.diagnoseProcess(rest[1])
			}
			return
		}
		app.setNotice("用法：diagnose url 公网HTTPS地址 | diagnose process PID")
		return
	}
	// Native verbs the UI knows how to phrase; everything else passes through.
	// Every CLI call goes through post(): a synchronous runCLI here would block
	// the event loop for the whole CLI run and drop its result.
	post := func(kind, verb string, args []string, display string) {
		app.post(kind, func() apiMsg {
			msg := app.runCLI(kind, verb, args, display)
			msg.userCmd = true
			return msg
		})
	}
	switch strings.Join(fields, " ") {
	case "health", "health check":
		app.runHealth()
	case "doctor":
		app.runDoctor()
	case "status":
		app.changePage(pageRuntime)
	case "rules-status":
		post("cli:rules-status", "rules", []string{"status"}, "rules-status")
	case "rules-check":
		post("cli:rules-check", "rules", []string{"check"}, "rules-check")
	case "release check":
		post("cli:release-check", "release", []string{"check"}, "release-check")
	case "version":
		post("cli:version", "version", nil, "version")
	case "core list":
		post("cli:core-list", "core", []string{"list"}, "core-list")
	case "tun status":
		post("cli:tun-status", "tun", []string{"status"}, "tun-status")
	case "config validate":
		post("cli:config-validate", "config", []string{"validate"}, "config-validate")
	case "migrate --dry-run":
		post("cli:migrate-preview", "migrate", []string{"--dry-run"}, "migrate-preview")
	case "reset --dry-run":
		post("cli:reset-preview", "reset", []string{"--dry-run"}, "reset-preview")
	case "profiles":
		// The retained identifier for the subscription page; the profile
		// listing itself is available as ": profile list".
		app.changePage(pageSubscriptions)
	case "profile":
		app.changePage(pageProfile)
	case "profile list":
		post("cli:profiles", "profiles", nil, "profiles")
	case "env show":
		post("cli:env-show", "env", []string{"show"}, "env-show")
	default:
		if verb == "exec" || verb == "direct" || verb == "update" || verb == "rollback" {
			app.setNotice(verb + " 属于安装/进程类命令，请在 Shell 中运行 mihomoctl " + verb)
			return
		}
		app.post("cli:"+line, func() apiMsg {
			// Pass the command as separate argv elements; handing the whole
			// line over as one argument breaks every multi-word verb.
			msg := app.runCLI("cli:"+line, verb, fields[1:], line)
			msg.userCmd = true
			return msg
		})
	}
}

func (app *App) cmdMode(rest []string) {
	if len(rest) != 1 || !map[string]bool{"rule": true, "global": true, "direct": true}[rest[0]] {
		app.setNotice("用法：mode rule|global|direct")
		return
	}
	mode := rest[0]
	app.pending = &pendingAction{
		text: "切换核心运行模式为 " + mode + "？（y 确认 / n 取消；不写入配置文件）",
		run: func(app *App) {
			app.post("op:mode "+mode, func() apiMsg {
				return apiMsg{kind: "op:mode " + mode, opName: "mode " + mode, err: app.src.SetMode(mode)}
			})
		},
	}
}

func (app *App) cmdLifecycle(verb string) {
	app.pending = &pendingAction{
		text: "确认" + map[string]string{"start": "启动", "stop": "停止", "restart": "重启"}[verb] +
			"当前用户的代理服务？（y 确认 / n 取消）",
		run: func(app *App) {
			app.post("op:"+verb, func() apiMsg {
				return app.runLifecycleCLI(verb)
			})
		},
	}
}

func (app *App) cmdDNS(rest []string) {
	if len(rest) == 0 || len(rest) > 2 {
		app.setNotice("用法：dns NAME [A|AAAA|CNAME|TXT|MX]")
		return
	}
	name := rest[0]
	record := "A"
	if len(rest) == 2 {
		record = strings.ToUpper(rest[1])
	}
	app.post("cli:dns", func() apiMsg {
		answer, err := app.src.DNS(name, record)
		if err != nil {
			return apiMsg{kind: "cli:dns", cliKind: "dns", err: err}
		}
		rows := []string{"查询 " + name + " · 记录 " + record + " · 系统 DNS 不受影响"}
		for _, row := range answer.Answer {
			rows = append(rows, fmt.Sprintf("  %s · TTL %d · %s", row.Type, row.TTL, row.Data))
		}
		if len(rows) == 1 {
			rows = append(rows, "  无应答")
		}
		return apiMsg{kind: "cli:dns", cliKind: "dns", lines: rows, userCmd: true}
	})
	app.setNotice("正在查询 DNS…")
}

const helpText = `页面：1 首页 | 2 节点 | 3 订阅 | 4 连接 | 5 规则 | 6 日志 | 7 接入 | 8 提供商 | 9 诊断 | 0 服务
通用：Tab/Shift+Tab 切页或切栏 | ↑↓ 移动 | Enter 确认 | / 过滤（节点/连接/日志/提供商/规则）
      r 刷新 | v 上次结果 | : 命令 | ? 帮助 | o 选项（主题/日志级别/字符集） | q 退出
节点：t 测速 | T 批量(8 并发) | s 排序 | [ ] 换组 | Tab 切换分组/节点栏
订阅：u 输入 URL | f 选择文件 | p 切换策略（简单/完整/仅节点/仅策略/自动） | y 保存并启动
日志：p 暂停 | / 过滤 | PgUp/PgDn 滚动 | 离开本页会停止日志流，返回时按当前级别重连
连接：p 暂停刷新 | / 过滤 | PgUp/PgDn 滚动
诊断：h health | d doctor | j journal | u diagnose url | 大写流程同 Textual 版
提供商：Enter/,: provider NAME 刷新
命令：page NAME | mode rule|global|direct | start|stop|restart | init | dns NAME [TYPE]
      provider NAME | subscribe FILE | subscribe-url PRIVATE_URL_FILE
      journal --since T --until T | health | doctor | status | rules-status
      rules-check | release check | version | core list | tun status | config validate
      migrate --dry-run | reset --dry-run | profile list | env show | chain | cancel | help
      theme dark|light | log-level debug|info|warning|error | override（预览受信脚本，确认后写入）
页面别名：profiles 指向订阅页（profile 是另一页：代理档案与接入声明）
透传：任何其他命令原样转给 mihomoctl --json 并渲染信封（exec/direct/update 除外）`

func readKeys(out chan<- Key) {
	buf := make([]byte, 0, 256)
	chunk := make([]byte, 256)
	for {
		n, err := os.Stdin.Read(chunk)
		if n > 0 {
			buf = append(buf, chunk[:n]...)
			for len(buf) > 0 {
				key, used := Decode(buf)
				if used == 0 {
					break // incomplete escape sequence; wait for more input
				}
				buf = buf[used:]
				out <- key
			}
		}
		if err != nil {
			close(out)
			return
		}
	}
}

func humanBytes(v int64) string {
	value := float64(v)
	for _, unit := range []string{"B", "KiB", "MiB", "GiB", "TiB"} {
		if value < 1024 || unit == "TiB" {
			return fmt.Sprintf("%.1f %s", value, unit)
		}
		value /= 1024
	}
	return ""
}

// truncByWidth cuts a string to a display width, CJK-aware.
func truncByWidth(s string, width int) string {
	used := 0
	for i, r := range s {
		w := runeWidth(r)
		if used+w > width {
			return s[:i]
		}
		used += w
	}
	return s
}

func displayWidth(s string) int {
	used := 0
	for _, r := range s {
		used += runeWidth(r)
	}
	return used
}

// listenerPort is the local proxy port /configs reports, for process checks.
func (app *App) listenerPort() int {
	if snapshot := app.configsPort; snapshot > 0 {
		return snapshot
	}
	return 0
}

func firstPositive(values ...int) int {
	for _, value := range values {
		if value > 0 {
			return value
		}
	}
	return 0
}
