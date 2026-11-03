package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
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

var pageNames = map[string]string{
	pageOverview: "首页", pageProxies: "节点", pageSubscriptions: "订阅", pageConnections: "连接",
	pageRules: "规则", pageLogs: "日志", pageProfile: "接入", pageProviders: "提供商",
	pageDiagnostics: "诊断", pageRuntime: "服务",
}

var groupTypeNames = map[string]string{
	"Selector": "手动", "URLTest": "自动", "Fallback": "转移", "LoadBalance": "负载", "Relay": "链式",
}

var policyOrder = []string{"auto", "provider", "nodes", "policy"}
var policyNames = map[string]string{
	"auto": "自动判断", "provider": "订阅完整策略", "nodes": "仅合并节点", "policy": "仅叠加策略",
}

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
	applyOK bool

	// Batch probe completion: which nodes never started, how many finished.
	cancelled  bool
	skipped    []string
	batchDone  int
	batchTotal int

	// userCmd marks a CLI call the operator typed, so its completion deserves
	// a notice; page auto-refreshes must stay silent.
	userCmd bool
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

	logs      []LogLine
	logOff    int
	logPaused bool

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

	// Reconnect backoff for dropped streams (controller restart, suspend):
	// a closed stream nils its channel in Run, onTick reopens it after this
	// cooldown so a down controller is not hammered.
	trafficRetryAt time.Time
	logsRetryAt    time.Time

	pending  *pendingAction
	input    *inputState
	cmdOpen  bool
	cmdline  string
	notice   string
	noticeAt time.Time

	// Subscription flow: source selection, policy, current preview.
	subKind    string // "url" or "file"
	subPolicy  string
	subPath    string
	subPreview map[string]any
	subID      string
	subSHA     string
	subBusy    bool

	// CLI-backed pages.
	runtimeDoc  []string
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
		focus: 1, subKind: "url", subPolicy: "auto", nodeProvider: map[string]string{},
	}
	app.streamCtx, app.cancelAll = context.WithCancel(context.Background())
	if _, ok := pageNames[app.page]; !ok {
		app.page = pageOverview
	}
	return app
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
		if app.logCh == nil {
			app.post("logs-open", func() apiMsg {
				ch, err := app.src.StartLogs(app.streamCtx)
				return apiMsg{kind: "logs-open", err: err, logs: ch}
			})
		}
	case pageRuntime:
		app.post("cli:status", func() apiMsg { return app.runCLI("status", "status", nil, "status") })
	case pageProfile:
		app.post("cli:profile", func() apiMsg { return app.loadProfile() })
	}
}

func (app *App) openTraffic() {
	if app.trafficCh == nil {
		app.post("traffic-open", func() apiMsg {
			ch, err := app.src.StartTraffic(app.streamCtx)
			return apiMsg{kind: "traffic-open", err: err, traffic: ch}
		})
	}
}

func (app *App) Run() error {
	defer app.cancelAll()
	keys := make(chan Key, 32)
	go readKeys(keys)
	resize := watchResize()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	app.openTraffic()
	app.refresh(app.page)
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
			}
		case line, ok := <-app.logCh:
			if !ok {
				app.logCh = nil
			} else if !app.logPaused {
				app.logs = append(app.logs, line)
				if len(app.logs) > 1000 {
					app.logs = app.logs[len(app.logs)-1000:]
				}
				app.dirty = true
			}
		case <-resize:
			w, h := termSize()
			app.scr.Resize(w, h)
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
	if interval := pageInterval[app.page]; interval > 0 {
		if now.Sub(app.lastFetch[kindFor(app.page)]) > time.Duration(interval*float64(time.Second)) {
			app.refresh(app.page)
		}
	}
	if app.notice != "" && time.Since(app.noticeAt) > 8*time.Second {
		app.notice = ""
		app.dirty = true
	}
	// Reopen dropped streams with a cooldown; inflight dedupe in post()
	// keeps a slow attempt from piling up.
	if app.trafficCh == nil && now.After(app.trafficRetryAt) {
		app.trafficRetryAt = now.Add(5 * time.Second)
		app.openTraffic()
	}
	if app.page == pageLogs && app.logCh == nil && now.After(app.logsRetryAt) {
		app.logsRetryAt = now.Add(5 * time.Second)
		app.refresh(pageLogs)
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

func (app *App) onAPI(msg apiMsg) {
	delete(app.inflight, msg.kind)
	if msg.err != nil {
		app.errs[msg.kind] = msg.err.Error()
		// CLI ops surface as a notice plus a failed result, not a stuck page.
		if strings.HasPrefix(msg.kind, "cli:") {
			app.lastTitle, app.lastResult = msg.cliKind, []string{"操作未完成：" + msg.err.Error()}
			app.setNotice(msg.cliKind + " 失败：" + truncByWidth(msg.err.Error(), 80))
		}
		if msg.kind == "cli:subscription-apply" {
			app.subBusy = false // a failed apply must not strand the page in "saving…"
		}
		if strings.HasPrefix(msg.kind, "delay:") {
			delete(app.testing, nodeKey(msg.delayNode, msg.delayProvider))
			app.delays[nodeKey(msg.delayNode, msg.delayProvider)] = "失败"
		}
		return
	}
	delete(app.errs, msg.kind)
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
	case "traffic-open":
		if msg.traffic != nil {
			app.trafficCh = msg.traffic
		}
	case "logs-open":
		if msg.logs != nil {
			app.logCh = msg.logs
		}
	case "op":
		if msg.text != "" {
			app.setNotice(msg.opName + " 完成：" + msg.text)
		} else {
			app.setNotice(msg.opName + " 完成")
		}
		app.refresh(app.page)
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
	if msg.cliKind != "" {
		app.lastTitle, app.lastResult = msg.cliKind, msg.lines
		if msg.userCmd {
			app.setNotice(msg.cliKind + " 完成，按 v 查看结果")
		}
		switch msg.cliKind {
		case "status":
			app.runtimeDoc = msg.lines
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
	if msg.kind == "cli:subscription-preview" && msg.preview != nil {
		app.subPreview = msg.preview
		app.subID = stringValue(msg.preview["id"])
		app.subSHA = stringValue(msg.preview["sha256"])
		app.setNotice("预览就绪：y 保存并启动（会先确认）")
	}
	if msg.kind == "cli:subscription-apply" {
		app.subBusy = false
		if msg.applyOK {
			app.subPreview, app.subID, app.subSHA = nil, "", ""
			app.setNotice("订阅已保存并启动")
			app.changePage(pageProxies)
		}
	}
}

func stringValue(value any) string {
	if text, ok := value.(string); ok {
		return text
	}
	return ""
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

func (app *App) changePage(page string) {
	if _, ok := pageNames[page]; !ok {
		return
	}
	app.page = page
	app.connOff, app.logOff, app.diagOff, app.rtOff = 0, 0, 0, 0
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
		app.quit = true
		return
	case KeyEsc:
		app.setNotice("")
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
		app.quit = true
	case 'r':
		app.inflight = map[string]bool{}
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
		if app.page != pageOverview && app.page != pageRuntime {
			app.filtering = true
		}
	case ':':
		app.cmdOpen = true
		app.cmdline = ""
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
			app.logPaused = !app.logPaused
			app.setNotice(map[bool]string{true: "已暂停", false: "已继续"}[app.logPaused])
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
	return maxInt(0, len(app.runtimeDoc)-(app.scr.H-5))
}

// scroll moves the long documents: logs page by logOff, diagnostics by diagOff.
func (app *App) scroll(delta int) {
	step := app.scr.H - 5
	if step < 1 {
		step = 1
	}
	switch app.page {
	case pageLogs:
		app.logOff = clamp(app.logOff-delta*step, 0, maxInt(0, len(app.logs)-1))
	case pageConnections:
		app.connOff = clamp(app.connOff+delta*step, 0, maxInt(0, len(app.conns)-1))
	case pageDiagnostics:
		app.diagOff = clamp(app.diagOff+delta*step, 0, maxInt(0, len(app.diagRows)))
	case pageRuntime:
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
	switch k.Type {
	case KeyEsc:
		app.filtering = false
	case KeyEnter:
		app.filtering = false
		app.rebuildNodes()
	case KeyBackspace:
		app.filter = dropLastRune(app.filter)
		app.rebuildNodes()
	case KeyRune:
		app.filter += string(k.Rune)
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
		app.quit = true
		return
	case "page":
		if len(rest) == 1 {
			app.changePage(rest[0])
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
	case "dns":
		app.cmdDNS(rest)
		return
	case "provider":
		if len(rest) == 1 {
			app.askRefreshProviderNamed(rest[0])
		}
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
	case "profiles", "profile list":
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
			app.post("op", func() apiMsg {
				return apiMsg{kind: "op", opName: "mode " + mode, err: app.src.SetMode(mode)}
			})
		},
	}
}

func (app *App) cmdLifecycle(verb string) {
	app.pending = &pendingAction{
		text: "确认" + map[string]string{"start": "启动", "stop": "停止", "restart": "重启"}[verb] +
			"当前用户的代理服务？（y 确认 / n 取消）",
		run: func(app *App) {
			app.post("op", func() apiMsg {
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
			return apiMsg{kind: "cli:dns", err: err}
		}
		rows := []string{"查询 " + name + " · 记录 " + record + " · 系统 DNS 不受影响"}
		for _, row := range answer.Answer {
			rows = append(rows, fmt.Sprintf("  %s · TTL %d · %s", row.Type, row.TTL, row.Data))
		}
		if len(rows) == 1 {
			rows = append(rows, "  无应答")
		}
		return apiMsg{kind: "cli:dns", cliKind: "dns", lines: rows}
	})
	app.setNotice("正在查询 DNS…")
}

const helpText = `页面：1 首页 | 2 节点 | 3 订阅 | 4 连接 | 5 规则 | 6 日志 | 7 接入 | 8 提供商 | 9 诊断 | 0 服务
通用：Tab/Shift+Tab 切页或切栏 | ↑↓ 移动 | Enter 确认 | / 过滤 | r 刷新 | v 上次结果 | : 命令 | q 退出
节点：t 测速 | T 批量(8 并发) | s 排序 | [ ] 换组 | Tab 切换分组/节点栏
订阅：u 输入 URL | f 选择文件 | p 切换策略 | y 保存并启动
诊断：h health | d doctor | j journal | u diagnose url | 大写流程同 Textual 版
提供商：Enter/,: provider NAME 刷新
命令：page NAME | mode rule|global|direct | start|stop|restart | init | dns NAME [TYPE]
      provider NAME | journal --since T --until T | health | doctor | status | rules-status
      rules-check | release check | version | core list | tun status | config validate
      migrate --dry-run | reset --dry-run | profiles | env show | chain | cancel | help
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
