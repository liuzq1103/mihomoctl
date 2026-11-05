package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
)

// plainSource is a controller stand-in for the plain console: it serves a
// fixed group list and records every selection.
type plainSource struct {
	groups      ProxiesDoc
	selected    []string
	authorized  []string
	refuseCross bool
}

func (s *plainSource) Version() (VersionDoc, error) { return VersionDoc{Version: "v1.19.33"}, nil }
func (s *plainSource) Configs() (ConfigsDoc, error) { return ConfigsDoc{Mode: "rule"}, nil }
func (s *plainSource) Proxies() (ProxiesDoc, error) { return s.groups, nil }
func (s *plainSource) Connections() (ConnectionsDoc, error) {
	return ConnectionsDoc{}, nil
}
func (s *plainSource) Rules() (RulesDoc, error)                 { return RulesDoc{}, nil }
func (s *plainSource) RuleProviders() (RuleProvidersDoc, error) { return RuleProvidersDoc{}, nil }
func (s *plainSource) Memory() (MemoryDoc, error)               { return MemoryDoc{}, nil }
func (s *plainSource) ProxyProviders() (ProxyProvidersDoc, error) {
	return ProxyProvidersDoc{}, nil
}

func (s *plainSource) Select(group, node string) error {
	s.selected = append(s.selected, group+"|"+node)
	if s.refuseCross {
		return errors.New("cross-level-selection-refused")
	}
	return nil
}

func (s *plainSource) SelectAllowCrossLevel(group, node string) error {
	s.authorized = append(s.authorized, group+"|"+node)
	return nil
}

func (s *plainSource) DelayFor(provider, node string, timeoutMS int) (int, error) {
	return 0, nil
}
func (s *plainSource) Delay(node string, timeoutMS int) (int, error) { return 0, nil }
func (s *plainSource) SetMode(mode string) error                     { return nil }
func (s *plainSource) RefreshProvider(name string) error             { return nil }
func (s *plainSource) DNS(name, record string) (DNSAnswer, error)    { return DNSAnswer{}, nil }
func (s *plainSource) Download(url string) ([]byte, error)           { return []byte("proxies: []"), nil }
func (s *plainSource) StartTraffic(ctx context.Context) (<-chan Traffic, error) {
	return nil, errors.New("no-stream")
}
func (s *plainSource) StartLogs(ctx context.Context) (<-chan LogLine, error) {
	return nil, errors.New("no-stream")
}

// plainCli answers the service verbs the plain console uses and records
// every call.
type plainCli struct {
	recordingCli
	mu     sync.Mutex
	inputs []string
}

func (c *plainCli) SubscriptionInput(value, kind, policy string) (Envelope, error) {
	c.mu.Lock()
	c.inputs = append(c.inputs, kind+"|"+policy+"|"+value)
	c.mu.Unlock()
	return Envelope{Schema: "mihomoctl/v1", Command: "subscription-preview", Scope: "user", Overall: "PASS",
		Data: map[string]any{
			"state": "preview", "id": strings.Repeat("a", 32), "sha256": strings.Repeat("b", 64),
			"policy": "provider", "requested_policy": policy,
			"nodes": float64(3), "groups": float64(1), "rules": float64(1),
		}}, nil
}

func (c *plainCli) Run(args ...string) (Envelope, error) {
	c.mu.Lock()
	c.calls = append(c.calls, args)
	c.mu.Unlock()
	switch {
	case len(args) > 1 && args[0] == "subscription" && args[1] == "apply":
		return Envelope{Schema: "mihomoctl/v1", Command: "subscription-apply", Scope: "user", Overall: "PASS",
			Data: map[string]any{"state": "ready", "action": "start"}}, nil
	case len(args) > 0 && args[0] == "status":
		return Envelope{Schema: "mihomoctl/v1", Command: "status", Scope: "user", Overall: "PASS",
			Data: map[string]any{
				"scope": "user", "backend": "process", "proxy_mode": "rule",
				"core": map[string]any{"binary": "/bin/mihomo"},
			}}, nil
	}
	return Envelope{Schema: "mihomoctl/v1", Overall: "PASS", Data: map[string]any{}}, nil
}

func (c *plainCli) lastInput() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.inputs) == 0 {
		return ""
	}
	return c.inputs[len(c.inputs)-1]
}

// newPlainSource serves one manual group with two members.
func newPlainSource() *plainSource {
	return &plainSource{groups: ProxiesDoc{Proxies: map[string]Proxy{
		"PROXY": {Type: "Selector", Now: "香港-01", All: []string{"香港-01", "东京-01"}},
		"AUTO":  {Type: "URLTest", Now: "新加坡-01", All: []string{"新加坡-01"}},
	}}}
}

// The menu is the audited plain menu, and q ends it.
func TestPlainConsoleShowsTheMenuAndQuits(t *testing.T) {
	out := &bytes.Buffer{}
	err := runPlainConsole(newPlainSource(), &plainCli{}, strings.NewReader("q\n"), out)
	if err != nil {
		t.Fatalf("the menu must end without an error: %v", err)
	}
	text := out.String()
	for _, want := range []string{"Mihomo 管理", "1. 运行时状态", "2. 选择节点", "3. 导入订阅",
		"4. 初始化控制器", "5. 启动", "6. 停止", "7. 重启生效", "8. 切换模式",
		"10. 探测配置", "11. 历史日志", "12. 代理档案与接入", "q. 退出"} {
		if !strings.Contains(text, want) {
			t.Fatalf("the menu must offer %q:\n%s", want, text)
		}
	}
}

// The runtime entry prints the seven facts and the controller state.
func TestPlainConsolePrintsTheRuntimeStatus(t *testing.T) {
	out := &bytes.Buffer{}
	if err := runPlainConsole(newPlainSource(), &plainCli{}, strings.NewReader("1\nq\n"), out); err != nil {
		t.Fatalf("the status entry must not fail: %v", err)
	}
	text := out.String()
	if !strings.Contains(text, "运行时（作用域 user）") {
		t.Fatalf("the scope must be printed:\n%s", text)
	}
	if !strings.Contains(text, "核心：") || !strings.Contains(text, "代理模式：") {
		t.Fatalf("the runtime facts must be printed:\n%s", text)
	}
	if !strings.Contains(text, "待重启: 否") {
		t.Fatalf("the pending restart must be printed:\n%s", text)
	}
}

// The node entry lists the groups, then the members, and switches the
// selection after the confirmation.
func TestPlainConsoleListsGroupsAndSwitchesNode(t *testing.T) {
	source := newPlainSource()
	out := &bytes.Buffer{}
	input := strings.NewReader("2\n2\n1\ny\nq\n")
	if err := runPlainConsole(source, &plainCli{}, input, out); err != nil {
		t.Fatalf("the node entry must not fail: %v", err)
	}
	text := out.String()
	if !strings.Contains(text, "Mihomo · 策略组") {
		t.Fatalf("the group list must be printed:\n%s", text)
	}
	if !strings.Contains(text, "2. PROXY [Selector]") {
		t.Fatalf("the groups must be numbered:\n%s", text)
	}
	if !strings.Contains(text, "香港-01 ✓") {
		t.Fatalf("the current selection must be marked:\n%s", text)
	}
	if len(source.selected) != 1 || source.selected[0] != "PROXY|香港-01" {
		t.Fatalf("the selection must be applied, got %v", source.selected)
	}
	if !strings.Contains(text, "已确认切换") {
		t.Fatalf("the confirmation must be printed:\n%s", text)
	}
}

// A cross-level selection is only applied with the explicit authorisation.
func TestPlainConsoleAsksBeforeACrossLevelSelection(t *testing.T) {
	source := newPlainSource()
	source.refuseCross = true
	out := &bytes.Buffer{}
	// The confirmation of the switch, then a refusal of the authorisation.
	if err := runPlainConsole(source, &plainCli{}, strings.NewReader("2\n2\n1\ny\nn\nq\n"), out); err != nil {
		t.Fatalf("the node entry must not fail: %v", err)
	}
	if len(source.authorized) != 0 {
		t.Fatalf("a refused authorisation must not select anything, got %v", source.authorized)
	}
	if !strings.Contains(out.String(), "明确授权跨层切换") {
		t.Fatalf("the authorisation must be asked:\n%s", out.String())
	}
	// A refused authorisation must not be reported as a confirmed switch.
	if strings.Contains(out.String(), "已确认切换") {
		t.Fatalf("a refused switch must not be reported as confirmed:\n%s", out.String())
	}

	source = newPlainSource()
	source.refuseCross = true
	out = &bytes.Buffer{}
	if err := runPlainConsole(source, &plainCli{}, strings.NewReader("2\n2\n1\ny\ny\nq\n"), out); err != nil {
		t.Fatalf("the node entry must not fail: %v", err)
	}
	if len(source.authorized) != 1 || source.authorized[0] != "PROXY|香港-01" {
		t.Fatalf("the authorised selection must be applied, got %v", source.authorized)
	}
}

// The subscription entry previews under the guided policy and saves after
// the confirmation.
func TestPlainConsolePreviewsTheSubscriptionGuided(t *testing.T) {
	cli := &plainCli{}
	out := &bytes.Buffer{}
	input := strings.NewReader("3\n1\nhttps://example.com/sub\ny\nq\n")
	if err := runPlainConsole(newPlainSource(), cli, input, out); err != nil {
		t.Fatalf("the subscription entry must not fail: %v", err)
	}
	if got := cli.lastInput(); got != "url|simple|https://example.com/sub" {
		t.Fatalf("the guided policy must reach the service, got %q", got)
	}
	text := out.String()
	if !strings.Contains(text, "节点 3") {
		t.Fatalf("the preview must be printed:\n%s", text)
	}
	if !strings.Contains(text, "已保存并启动") {
		t.Fatalf("the save must be reported:\n%s", text)
	}
	applied := false
	for _, call := range cli.calls {
		if len(call) > 1 && call[0] == "subscription" && call[1] == "apply" {
			applied = true
		}
	}
	if !applied {
		t.Fatalf("the preview must be applied, got %v", cli.calls)
	}
}

// A service that refuses the guided policy falls back to the automatic
// judgement and says so out loud.
func TestPlainConsoleFallsBackLoudly(t *testing.T) {
	cli := &policyRefusingCli{}
	out := &bytes.Buffer{}
	input := strings.NewReader("3\n2\n/private/provider.yaml\nn\nq\n")
	if err := runPlainConsole(newPlainSource(), cli, input, out); err != nil {
		t.Fatalf("the subscription entry must not fail: %v", err)
	}
	// The service records every verb it is asked to run; only the ones that
	// carried a policy matter here.
	policies := []string{}
	for _, policy := range cli.policies() {
		if policy != "" {
			policies = append(policies, policy)
		}
	}
	if len(policies) != 2 || policies[0] != "simple" || policies[1] != "auto" {
		t.Fatalf("the console must ask for the guided policy first, got %v", policies)
	}
	if !strings.Contains(out.String(), "未提供引导导入") {
		t.Fatalf("the fallback must be reported:\n%s", out.String())
	}
}

// A failed operation is reported and the menu continues.
func TestPlainConsoleSurvivesAFailingOperation(t *testing.T) {
	out := &bytes.Buffer{}
	input := strings.NewReader("5\ny\nq\n")
	cli := &plainCli{}
	cli.calls = nil
	err := runPlainConsole(newPlainSource(), &failingLifecycleCli{}, input, out)
	if err != nil {
		t.Fatalf("a failed operation must not end the menu: %v", err)
	}
	text := out.String()
	if !strings.Contains(text, "操作未完成") {
		t.Fatalf("the failure must be reported:\n%s", text)
	}
	if !strings.Contains(text, "Mihomo 管理") {
		t.Fatalf("the menu must continue:\n%s", text)
	}
}

// failingLifecycleCli refuses every lifecycle verb.
type failingLifecycleCli struct {
	plainCli
}

func (c *failingLifecycleCli) Run(args ...string) (Envelope, error) {
	if len(args) > 0 && (args[0] == "start" || args[0] == "stop" || args[0] == "restart") {
		return Envelope{}, errors.New("runtime-unavailable")
	}
	return c.plainCli.Run(args...)
}

// The probe configuration entry parses the request and previews it.
func TestPlainConsoleParsesTheProbeRequest(t *testing.T) {
	kind, name, options, err := parseProbeRequest(`provider "订阅 A" --preset resilient --url https://example.com`)
	if err != nil {
		t.Fatalf("the request must parse: %v", err)
	}
	if kind != "provider" || name != "订阅 A" {
		t.Fatalf("the request must keep its kind and name, got %q/%q", kind, name)
	}
	if len(options) != 4 || options[0] != "--preset" || options[3] != "https://example.com" {
		t.Fatalf("the options must be kept, got %v", options)
	}
	if _, _, _, err := parseProbeRequest("节点 名称"); err == nil {
		t.Fatal("a request without a kind must be refused")
	}
}

// The disconnected source fails every read with its reason: nothing may
// look like a healthy runtime.
func TestDisconnectedSourceFailsEveryRead(t *testing.T) {
	source := newDisconnectedSource("controller-not-configured-as-loopback")
	if version, err := source.Version(); err == nil || version.Version != "" {
		t.Fatalf("the version must not be fabricated: %v %q", err, version.Version)
	}
	if configs, err := source.Configs(); err == nil || configs.Mode != "" {
		t.Fatalf("the configs must not be fabricated: %v %q", err, configs.Mode)
	}
	if proxies, err := source.Proxies(); err == nil || len(proxies.Proxies) != 0 {
		t.Fatalf("the proxies must not be fabricated: %v", err)
	}
	if err := source.Select("PROXY", "香港-01"); err == nil {
		t.Fatal("a selection must fail")
	}
	if _, err := source.DelayFor("", "香港-01", 5000); err == nil {
		t.Fatal("a probe must fail")
	}
	if err := source.SetMode("rule"); err == nil {
		t.Fatal("a mode change must fail")
	}
	if _, err := source.Download("https://example.com"); err == nil {
		t.Fatal("a download must fail")
	}
	if _, err := source.StartLogs(context.Background()); err == nil {
		t.Fatal("the log stream must fail")
	}
	// Every failure carries the reason, so the console can explain itself.
	_, err := source.Version()
	if err == nil || !strings.Contains(err.Error(), "controller-not-configured-as-loopback") {
		t.Fatalf("the reason must be carried, got %v", err)
	}
}

// A source without a reason still fails with an honest code.
func TestDisconnectedSourceAlwaysHasAReason(t *testing.T) {
	source := newDisconnectedSource("")
	_, err := source.Version()
	if err == nil || err.Error() == "" {
		t.Fatalf("the failure must carry a code, got %v", err)
	}
}

// A disconnected controller must not stop the console: every entry reports
// the reason and the menu continues.
func TestPlainConsoleSurvivesADisconnectedController(t *testing.T) {
	out := &bytes.Buffer{}
	input := strings.NewReader("1\n2\n3\nq\n")
	if err := runPlainConsole(newDisconnectedSource("controller-not-configured-as-loopback"), &plainCli{}, input, out); err != nil {
		t.Fatalf("a disconnected controller must not end the menu: %v", err)
	}
	text := out.String()
	if !strings.Contains(text, "controller-not-configured-as-loopback") {
		t.Fatalf("the reason must be reported:\n%s", text)
	}
	if !strings.Contains(text, "Mihomo 管理") {
		t.Fatalf("the menu must continue:\n%s", text)
	}
}

// ---------------------------------------------------------------------------
// The plain console reports a setup that is not ready, reads a secret
// without echoing it and keeps its promises.
// ---------------------------------------------------------------------------

// failingStatusCli answers the status verb with a failure envelope.
type failingStatusCli struct {
	plainCli
	overall string
}

func (c *failingStatusCli) Run(args ...string) (Envelope, error) {
	if len(args) > 0 && args[0] == "status" {
		return Envelope{Schema: "mihomoctl/v1", Overall: "FAIL",
			Errors: []ErrDoc{{Code: "manager-missing"}}}, nil
	}
	return c.plainCli.Run(args...)
}

// A service that answers with a failure envelope has not set the console up,
// and the console says so.
func TestPlainConsoleReportsAFailingStartupEnvelope(t *testing.T) {
	out := &bytes.Buffer{}
	if err := runPlainConsole(newPlainSource(), &failingStatusCli{}, strings.NewReader("q\n"), out); err != nil {
		t.Fatalf("the menu must not fail: %v", err)
	}
	text := out.String()
	if !strings.Contains(text, "配置尚未就绪") {
		t.Fatalf("the failed envelope must be reported:\n%s", text)
	}
	if !strings.Contains(text, "manager-missing") {
		t.Fatalf("the reason must be reported:\n%s", text)
	}
	if !strings.Contains(text, "首次配置：选择 3 导入订阅") {
		t.Fatalf("the setup hint must be printed:\n%s", text)
	}
}

// maskedReader is an input that knows how to hide what it reads.
type maskedReader struct {
	reader *bufio.Reader
	prompt string
	used   bool
}

func (r *maskedReader) Read(p []byte) (int, error) { return r.reader.Read(p) }

func (r *maskedReader) ReadMasked(prompt string) (string, error) {
	r.used = true
	r.prompt = prompt
	line, err := r.reader.ReadString('\n')
	return strings.TrimSpace(line), err
}

// The subscription URL is read through the masked input, so it never
// reaches the screen.
func TestPlainConsoleMasksTheSubscriptionURL(t *testing.T) {
	input := &maskedReader{reader: bufio.NewReader(strings.NewReader("3\n1\nhttps://example.com/sub\ny\n"))}
	out := &bytes.Buffer{}
	cli := &plainCli{}
	if err := runPlainConsole(newPlainSource(), cli, input, out); err != nil {
		t.Fatalf("the subscription entry must not fail: %v", err)
	}
	if !input.used {
		t.Fatal("the URL must be read through the masked input")
	}
	if !strings.Contains(input.prompt, "隐藏输入") {
		t.Fatalf("the prompt must say that the input is hidden, got %q", input.prompt)
	}
	if strings.Contains(out.String(), "https://example.com/sub") {
		t.Fatalf("the URL must not be printed:\n%s", out.String())
	}
	if got := cli.lastInput(); got != "url|simple|https://example.com/sub" {
		t.Fatalf("the URL must still reach the service, got %q", got)
	}
}

// A plain reader (a pipe, a script, a test) still works.
func TestPlainConsoleReadsWithoutAMaskedInput(t *testing.T) {
	out := &bytes.Buffer{}
	if err := runPlainConsole(newPlainSource(), &plainCli{},
		strings.NewReader("3\n1\nhttps://example.com/sub\nn\nq\n"), out); err != nil {
		t.Fatalf("the subscription entry must not fail: %v", err)
	}
	if !strings.Contains(out.String(), "HTTPS 订阅 URL") {
		t.Fatalf("the prompt must be printed:\n%s", out.String())
	}
}

// The journal belongs to the managed runtime: without the service that
// knows it, the console says that it is not available.
func TestPlainConsoleJournalNeedsTheService(t *testing.T) {
	out := &bytes.Buffer{}
	if err := runPlainConsole(newPlainSource(), &plainCli{},
		strings.NewReader("11\n\n\nq\n"), out); err != nil {
		t.Fatalf("the journal entry must not fail: %v", err)
	}
	text := out.String()
	if !strings.Contains(text, "journal-not-supported") {
		t.Fatalf("the missing capability must be reported:\n%s", text)
	}
}

// plainJournalCli is a service that can read the managed journal.
type plainJournalCli struct {
	plainCli
}

func (c *plainJournalCli) Journal(since, until string, lines int) (Envelope, error) {
	return Envelope{Schema: "mihomoctl/v1", Overall: "PASS",
		Data: map[string]any{"entries": []any{"一、日志"}}}, nil
}

// With the capability the journal is read from the service.
func TestPlainConsoleJournalReadsThroughTheService(t *testing.T) {
	out := &bytes.Buffer{}
	if err := runPlainConsole(newPlainSource(), &plainJournalCli{},
		strings.NewReader("11\n\n\nq\n"), out); err != nil {
		t.Fatalf("the journal entry must not fail: %v", err)
	}
	if !strings.Contains(out.String(), "一、日志") {
		t.Fatalf("the journal must be printed:\n%s", out.String())
	}
}

// restartRequiredCli is a service whose save leaves the runtime waiting for
// a restart.
type restartRequiredCli struct {
	plainCli
	restartCalls int
	restartFails bool
}

func (c *restartRequiredCli) Run(args ...string) (Envelope, error) {
	if len(args) > 0 && args[0] == "subscription" && len(args) > 1 && args[1] == "apply" {
		return Envelope{Schema: "mihomoctl/v1", Overall: "PASS",
			Data: map[string]any{"state": "restart-required"}}, nil
	}
	if len(args) > 0 && args[0] == "restart" {
		c.restartCalls++
		if c.restartFails {
			return Envelope{}, errors.New("runtime-unavailable")
		}
		return Envelope{Schema: "mihomoctl/v1", Overall: "PASS"}, nil
	}
	return c.plainCli.Run(args...)
}

// A save that still waits for a restart is only announced as started when
// the restart of the confirmed action really worked.
func TestPlainConsoleSaveReportsARestartRequirement(t *testing.T) {
	out := &bytes.Buffer{}
	cli := &restartRequiredCli{}
	if err := runPlainConsole(newPlainSource(), cli,
		strings.NewReader("3\n1\nhttps://example.com/sub\ny\nq\n"), out); err != nil {
		t.Fatalf("the subscription entry must not fail: %v", err)
	}
	text := out.String()
	if cli.restartCalls != 1 {
		t.Fatalf("the confirmed action must restart the runtime, got %d", cli.restartCalls)
	}
	if !strings.Contains(text, "已保存并启动") {
		t.Fatalf("the successful save must be reported:\n%s", text)
	}

	// A restart that fails is reported instead of being announced as a
	// started runtime.
	out = &bytes.Buffer{}
	cli = &restartRequiredCli{restartFails: true}
	if err := runPlainConsole(newPlainSource(), cli,
		strings.NewReader("3\n1\nhttps://example.com/sub\ny\nq\n"), out); err != nil {
		t.Fatalf("the subscription entry must not fail: %v", err)
	}
	text = out.String()
	if strings.Contains(text, "已保存并启动") {
		t.Fatalf("a failed restart must not be announced as started:\n%s", text)
	}
	if !strings.Contains(text, "subscription-saved-restart-failed") {
		t.Fatalf("the failed restart must be reported:\n%s", text)
	}
}
