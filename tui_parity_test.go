package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// levelSource is a demo source that can open its log stream at a chosen
// level and records every open, so the log-stream lifecycle is observable.
type levelSource struct {
	*demoSource
	mu      sync.Mutex
	levels  []string
	opened  []context.Context
	canceld []bool
}

func newLevelSource() *levelSource {
	return &levelSource{demoSource: newDemoSource()}
}

func (s *levelSource) StartLogs(ctx context.Context) (<-chan LogLine, error) {
	return s.StartLogsAt(ctx, "info")
}

func (s *levelSource) StartLogsAt(ctx context.Context, level string) (<-chan LogLine, error) {
	s.mu.Lock()
	s.levels = append(s.levels, level)
	s.opened = append(s.opened, ctx)
	s.mu.Unlock()
	out := make(chan LogLine)
	go func() {
		<-ctx.Done()
		close(out)
	}()
	return out, nil
}

func (s *levelSource) openCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.levels)
}

func (s *levelSource) lastLevel() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.levels) == 0 {
		return ""
	}
	return s.levels[len(s.levels)-1]
}

// lastCancelled reports whether the newest stream context was cancelled.
func (s *levelSource) lastCancelled() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.opened) == 0 {
		return false
	}
	return s.opened[len(s.opened)-1].Err() != nil
}

// guidedCli is a CLI service that offers the guided subscription import: the
// route the plain CLI preview verb does not have.
type guidedCli struct {
	recordingCli
	mu     sync.Mutex
	inputs []string
}

func (c *guidedCli) SubscriptionInput(value, kind, policy string) (Envelope, error) {
	c.mu.Lock()
	c.inputs = append(c.inputs, kind+"|"+policy+"|"+value)
	c.mu.Unlock()
	return Envelope{Schema: "mihomoctl/v1", Command: "subscription-preview", Scope: "user", Overall: "PASS",
		Data: map[string]any{
			"state": "preview", "id": strings.Repeat("a", 32), "sha256": strings.Repeat("b", 64),
			"policy": "provider", "requested_policy": policy, "nodes": 2, "groups": 1, "rules": 1,
		}}, nil
}

func (c *guidedCli) lastInput() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.inputs) == 0 {
		return ""
	}
	return c.inputs[len(c.inputs)-1]
}

// policyRefusingCli refuses the guided policy the way a service that only
// knows auto/nodes/provider/policy does, and accepts the automatic one.
type policyRefusingCli struct {
	recordingCli
	mu       sync.Mutex
	seen     []string
	rejected bool
}

func (c *policyRefusingCli) Run(args ...string) (Envelope, error) {
	policy := ""
	for index, arg := range args {
		if arg == "--policy" && index+1 < len(args) {
			policy = args[index+1]
		}
	}
	c.mu.Lock()
	c.seen = append(c.seen, policy)
	c.mu.Unlock()
	if policy == "simple" {
		return Envelope{Schema: "mihomoctl/v1", Command: "subscription-preview", Scope: "user",
			Overall: "FAIL", Errors: []ErrDoc{{Code: "subscription-policy-invalid",
				Detail: "policy must be one of auto, nodes, provider, policy"}}}, nil
	}
	return Envelope{Schema: "mihomoctl/v1", Command: "subscription-preview", Scope: "user", Overall: "PASS",
		Data: map[string]any{"state": "preview", "id": strings.Repeat("a", 32),
			"sha256": strings.Repeat("b", 64), "policy": policy, "requested_policy": policy,
			"nodes": 2, "groups": 1, "rules": 1}}, nil
}

func (c *policyRefusingCli) policies() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.seen...)
}

// otherPolicyCli answers every request with the automatic policy, whatever
// was asked for.
type otherPolicyCli struct {
	recordingCli
}

func (c *otherPolicyCli) Run(args ...string) (Envelope, error) {
	return Envelope{Schema: "mihomoctl/v1", Command: "subscription-preview", Scope: "user", Overall: "PASS",
		Data: map[string]any{"state": "preview", "id": strings.Repeat("a", 32),
			"sha256": strings.Repeat("b", 64), "policy": "auto", "requested_policy": "auto",
			"nodes": 2, "groups": 1, "rules": 1}}, nil
}

// drainAPI applies every pending message, so a test can observe the state
// the console reaches after its own asynchronous work. The console posts its
// work from goroutines, so the drain waits for a short silence instead of
// giving up on the first empty read.
func drainAPI(t *testing.T, app *App) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case msg := <-app.apiCh:
			app.onAPI(msg)
		case <-time.After(20 * time.Millisecond):
			return
		}
	}
}

// The retained "profiles" identifier must route to the subscription page,
// and the profile page must stay a different destination.
func TestPageAliasRoutesToTheSubscriptionPage(t *testing.T) {
	app := NewApp(newDemoSource(), &stubCli{env: Envelope{Overall: "PASS"}}, 100, 30, pageOverview, true)
	app.changePage("profiles")
	if app.page != pageSubscriptions {
		t.Fatalf("the profiles alias must open the subscription page, got %q", app.page)
	}
	app.changePage(pageProfile)
	if app.page != pageProfile {
		t.Fatalf("the profile page must stay its own page, got %q", app.page)
	}
	app.executeCommand("page profiles")
	if app.page != pageSubscriptions {
		t.Fatalf(": page profiles must open the subscription page, got %q", app.page)
	}
	app.executeCommand("page nosuchpage")
	if app.page != pageSubscriptions {
		t.Fatalf("an unknown page must not change the current one, got %q", app.page)
	}
}

// The log stream belongs to the logs page: it stops when the page is left
// and is reopened when the page is entered again.
func TestLogStreamStopsOnLeaveAndReconnectsOnReturn(t *testing.T) {
	source := newLevelSource()
	app := NewApp(source, &stubCli{env: Envelope{Overall: "PASS"}}, 100, 30, pageOverview, true)
	app.changePage(pageLogs)
	drainAPI(t, app)
	if source.openCount() != 1 {
		t.Fatalf("entering the logs page must open exactly one stream, got %d", source.openCount())
	}
	if source.lastLevel() != "info" {
		t.Fatalf("the default level must be info, got %q", source.lastLevel())
	}
	app.changePage(pageOverview)
	drainAPI(t, app)
	if app.logCh != nil {
		t.Fatal("the console must forget the channel of a stopped stream")
	}
	if !source.lastCancelled() {
		t.Fatal("the log stream must be cancelled when the page is left")
	}
	app.changePage(pageLogs)
	drainAPI(t, app)
	if source.openCount() != 2 {
		t.Fatalf("returning to the logs page must reopen the stream, got %d opens", source.openCount())
	}
}

// Changing the level restarts the stream, because the level is part of the
// stream request.
func TestLogLevelChangeRestartsTheStream(t *testing.T) {
	source := newLevelSource()
	app := NewApp(source, &stubCli{env: Envelope{Overall: "PASS"}}, 100, 30, pageLogs, true)
	app.changePage(pageLogs)
	drainAPI(t, app)
	if source.openCount() != 1 {
		t.Fatalf("expected one stream, got %d", source.openCount())
	}
	app.setLogLevel("warning")
	drainAPI(t, app)
	if app.logLevel != "warning" {
		t.Fatalf("the level must be remembered, got %q", app.logLevel)
	}
	if source.openCount() != 2 {
		t.Fatalf("a level change must restart the stream, got %d opens", source.openCount())
	}
	if source.lastLevel() != "warning" {
		t.Fatalf("the restarted stream must use the new level, got %q", source.lastLevel())
	}
	app.setLogLevel("nonsense")
	if app.logLevel != "warning" {
		t.Fatalf("an unknown level must be refused, got %q", app.logLevel)
	}
}

// The theme changes the accent colours, and the switch repaints the frame
// instead of leaving the old colours behind.
func TestThemeSwitchChangesAccentCodes(t *testing.T) {
	app := NewApp(newDemoSource(), &stubCli{env: Envelope{Overall: "PASS"}}, 100, 30, pageOverview, true)
	app.setProxies(map[string]Proxy{"PROXY": {Type: "Selector", Now: "香港-01", All: []string{"香港-01"}}})
	app.changePage(pageProxies)
	app.draw()
	var dark bytes.Buffer
	if err := app.scr.Flush(&dark); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(dark.String(), "92") {
		t.Fatalf("the dark theme must use the bright accents, got %q", dark.String())
	}
	app.SetTheme(ThemeLight)
	app.draw()
	var light bytes.Buffer
	if err := app.scr.Flush(&light); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(light.String(), "32") {
		t.Fatalf("the light theme must use the normal accents, got %q", light.String())
	}
	if strings.Contains(light.String(), "92") {
		t.Fatalf("the light theme must not keep the dark accents: %q", light.String())
	}
}

// The ASCII mode replaces the Unicode marks, for terminals that cannot
// render them.
func TestASCIIModeReplacesTheSelectionMark(t *testing.T) {
	app := NewApp(newDemoSource(), &stubCli{env: Envelope{Overall: "PASS"}}, 100, 30, pageProxies, true)
	app.setProxies(map[string]Proxy{"PROXY": {Type: "Selector", Now: "香港-01", All: []string{"香港-01"}}})
	app.rebuildNodes()
	app.draw()
	if plain := app.scr.DumpPlain(); !strings.Contains(plain, "✓") {
		t.Fatalf("the Unicode theme must show the check mark:\n%s", plain)
	}
	app.SetASCII(true)
	app.draw()
	plain := app.scr.DumpPlain()
	if strings.Contains(plain, "✓") {
		t.Fatalf("the ASCII mode must not draw the check mark:\n%s", plain)
	}
	if !strings.Contains(plain, "*") {
		t.Fatalf("the ASCII mode must draw the star marker:\n%s", plain)
	}
}

// "simple" is the guided import, not another name for "auto": the console
// asks the service for it, and says what it means.
func TestSimplePolicyUsesTheGuidedRoute(t *testing.T) {
	cli := &guidedCli{}
	app := NewApp(newDemoSource(), cli, 100, 30, pageSubscriptions, true)
	if app.subPolicy != "simple" {
		t.Fatalf("the default policy must be the guided import, got %q", app.subPolicy)
	}
	app.subscriptionPreview("file", "/private/provider.yaml")
	drainAPI(t, app)
	if got := cli.lastInput(); got != "file|simple|/private/provider.yaml" {
		t.Fatalf("the guided route must receive the simple policy, got %q", got)
	}
	if app.subPreview == nil {
		t.Fatal("the guided preview must install")
	}
	if app.subEffective != "provider" || app.subRequested != "simple" {
		t.Fatalf("the page must know both policies, got effective=%q requested=%q",
			app.subEffective, app.subRequested)
	}
	app.draw()
	plain := app.scr.DumpPlain()
	if !strings.Contains(plain, "实际导入策略") {
		t.Fatalf("the page must show the effective policy:\n%s", plain)
	}
}

// Without the guided route the console says so; it must not quietly turn
// the guided import into "auto" without saying so.
func TestSimplePolicyFallsBackLoudly(t *testing.T) {
	cli := &policyRefusingCli{}
	app := NewApp(newDemoSource(), cli, 100, 30, pageSubscriptions, true)
	app.subscriptionPreview("file", "/private/provider.yaml")
	drainAPI(t, app)
	if got := cli.policies(); len(got) != 2 || got[0] != "simple" || got[1] != "auto" {
		t.Fatalf("the console must ask for the guided policy first and fall back to auto, got %v", got)
	}
	if app.subPolicyNote == "" {
		t.Fatal("the fallback must be explained")
	}
	app.draw()
	plain := app.scr.DumpPlain()
	if !strings.Contains(plain, "未提供引导导入") {
		t.Fatalf("the page must explain the fallback:\n%s", plain)
	}
}

// A service that answers with another policy than the one that was
// requested must be reported, not silently accepted.
func TestPreviewReportsThePolicyTheServiceUsed(t *testing.T) {
	cli := &otherPolicyCli{}
	app := NewApp(newDemoSource(), cli, 100, 30, pageSubscriptions, true)
	app.subscriptionPreview("file", "/private/provider.yaml")
	drainAPI(t, app)
	if app.subPreview == nil {
		t.Fatal("the preview must install")
	}
	if app.subEffective != "auto" || app.subRequested != "auto" {
		t.Fatalf("the page must know the effective policy, got %q/%q", app.subEffective, app.subRequested)
	}
	if app.subPolicyNote == "" {
		t.Fatal("an unhonoured policy must be reported")
	}
}

// resolvingCli answers like a service that resolved the guided import
// itself: it reports the policy it applied and whether the guided path was
// used.
type resolvingCli struct {
	recordingCli
	policy string
	guided bool
}

func (c *resolvingCli) SubscriptionInput(value, kind, policy string) (Envelope, error) {
	return Envelope{Schema: "mihomoctl/v1", Command: "subscription-preview", Scope: "user", Overall: "PASS",
		Data: map[string]any{
			"state": "preview", "id": strings.Repeat("a", 32), "sha256": strings.Repeat("b", 64),
			"policy": c.policy, "requested_policy": c.policy, "guided": c.guided,
			"nodes": float64(2), "groups": float64(1), "rules": float64(1),
		}}, nil
}

// The guided import resolves against the local configuration, so the console
// must say which of the two guided outcomes the service chose, and must not
// report a fallback that did not happen.
func TestGuidedImportReportsTheOutcomeTheServiceChose(t *testing.T) {
	// The local configuration is still simple: the service imports the
	// nodes and builds a single Proxy group.
	cli := &resolvingCli{policy: "provider", guided: true}
	app := NewApp(newDemoSource(), cli, 100, 30, pageSubscriptions, true)
	app.subscriptionPreview("file", "/private/provider.yaml")
	drainAPI(t, app)
	if app.subSent != "simple" {
		t.Fatalf("the guided policy must reach the service unchanged, got %q", app.subSent)
	}
	if !strings.Contains(app.subPolicyNote, "引导导入") {
		t.Fatalf("the guided outcome must be explained, got %q", app.subPolicyNote)
	}
	if strings.Contains(app.subPolicyNote, "未提供引导导入") {
		t.Fatalf("a resolved guided import is not a fallback: %q", app.subPolicyNote)
	}
	app.draw()
	plain := app.scr.DumpPlain()
	if !strings.Contains(plain, "单一 Proxy 分组") {
		t.Fatalf("the page must name the guided outcome:\n%s", plain)
	}

	// The local configuration already carries routing: only the nodes are
	// merged and the existing groups and rules stay.
	cli = &resolvingCli{policy: "nodes"}
	app = NewApp(newDemoSource(), cli, 100, 30, pageSubscriptions, true)
	app.subscriptionPreview("file", "/private/provider.yaml")
	drainAPI(t, app)
	if app.subSent != "simple" {
		t.Fatalf("the guided policy must reach the service unchanged, got %q", app.subSent)
	}
	if !strings.Contains(app.subPolicyNote, "只合并节点") {
		t.Fatalf("the nodes-only outcome must be explained, got %q", app.subPolicyNote)
	}
}

// slowSource holds every log stream open until the test releases it, so a
// stream that was opened for a page the user already left can be observed.
type slowSource struct {
	*demoSource
	waiting chan chan struct{}
	mu      sync.Mutex
	opened  []<-chan LogLine
}

func (s *slowSource) StartLogs(ctx context.Context) (<-chan LogLine, error) {
	return s.StartLogsAt(ctx, "info")
}

func (s *slowSource) StartLogsAt(ctx context.Context, level string) (<-chan LogLine, error) {
	gate := make(chan struct{})
	s.waiting <- gate
	<-gate
	out := make(chan LogLine)
	go func() {
		<-ctx.Done()
		close(out)
	}()
	s.mu.Lock()
	s.opened = append(s.opened, out)
	s.mu.Unlock()
	return out, nil
}

// A stream that was opened for a page the user already left must never be
// adopted, not even when the user comes back before the open lands.
func TestStaleStreamResultIsNeverAdopted(t *testing.T) {
	source := &slowSource{demoSource: newDemoSource(), waiting: make(chan chan struct{}, 4)}
	app := NewApp(source, &stubCli{env: Envelope{Overall: "PASS"}}, 100, 30, pageLogs, true)
	app.changePage(pageLogs)
	first := <-source.waiting // the first open is waiting to complete
	app.changePage(pageOverview)
	app.changePage(pageLogs)
	second := <-source.waiting // the current open is waiting to complete
	close(first)               // the stale open lands first
	drainAPI(t, app)
	if app.logCh != nil {
		t.Fatal("a stream opened for a page that was left must not be adopted")
	}
	close(second)
	drainAPI(t, app)
	if app.logCh == nil {
		t.Fatal("the current stream must be adopted")
	}
}

// The "subscribe-url" command reads the URL from a private file in the
// worker, so the URL itself never has to be typed and never reaches a
// command line.
func TestSubscribeURLCommandReadsThePrivateFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "subscription.url")
	if err := os.WriteFile(path, []byte("  https://example.com/sub  \n"), 0o600); err != nil {
		t.Fatalf("cannot write the URL file: %v", err)
	}
	cli := &guidedCli{}
	app := NewApp(newDemoSource(), cli, 100, 30, pageSubscriptions, true)
	app.executeCommand("subscribe-url " + path)
	drainAPI(t, app)
	if got := cli.lastInput(); got != "url|simple|https://example.com/sub" {
		t.Fatalf("the URL must be read from the file and trimmed, got %q", got)
	}
	if app.subPreview == nil {
		t.Fatal("the preview must install")
	}
}

// The command line options reach the console without a startup notice, and
// an unknown theme name is ignored rather than fatal.
func TestApplyOptionsSetsTheThemeAndCharacterSet(t *testing.T) {
	app := NewApp(newDemoSource(), &stubCli{env: Envelope{Overall: "PASS"}}, 100, 30, pageOverview, true)
	app.Configure("light", true)
	if app.theme != ThemeLight {
		t.Fatalf("the light theme must be applied, got %q", app.theme)
	}
	if !app.ascii {
		t.Fatal("the plain character set must be applied")
	}
	if app.notice != "" {
		t.Fatalf("startup must stay quiet, got %q", app.notice)
	}
	app.Configure("nonsense", false)
	if app.theme != ThemeLight {
		t.Fatalf("an unknown theme must be ignored, got %q", app.theme)
	}
}

// The controller address keeps the host it was validated on, so an IPv6 or
// a named loopback still works.
func TestAPISourceKeepsTheValidatedHost(t *testing.T) {
	cases := []struct {
		host string
		want string
	}{
		{"", "http://127.0.0.1:9090"},
		{"127.0.0.1", "http://127.0.0.1:9090"},
		{"localhost", "http://localhost:9090"},
		{"::1", "http://[::1]:9090"},
	}
	for _, test := range cases {
		source := newAPISource(CtlConfig{Port: 9090, Host: test.host})
		if source.base != test.want {
			t.Fatalf("host %q must address %q, got %q", test.host, test.want, source.base)
		}
	}
}

// serviceCli stands in for the shared application service: it records every
// verb the console asks it to run.
type serviceCli struct {
	mu    sync.Mutex
	calls [][]string
	delay float64
	fail  bool
}

func (c *serviceCli) Run(args ...string) (Envelope, error) {
	c.mu.Lock()
	c.calls = append(c.calls, append([]string(nil), args...))
	fail, delay := c.fail, c.delay
	c.mu.Unlock()
	if fail {
		return Envelope{Schema: "mihomoctl/v1", Overall: "FAIL",
			Errors: []ErrDoc{{Code: "cross-level-selection-refused", Detail: "聚合组"}}}, nil
	}
	return Envelope{Schema: "mihomoctl/v1", Overall: "PASS",
		Data: map[string]any{"delay_ms": delay}}, nil
}

func (c *serviceCli) RunWithStdin(input []byte, args ...string) (Envelope, error) {
	return c.Run(args...)
}

func (c *serviceCli) lastCall() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.calls) == 0 {
		return nil
	}
	return c.calls[len(c.calls)-1]
}

// With a service attached, the mutations run through the service: it owns
// the selection rules and the node identities, and confirms every change.
func TestMutationsUseTheServiceWhenItIsConfigured(t *testing.T) {
	cli := &serviceCli{delay: 42}
	source := newAPISourceWithService(CtlConfig{Port: 9090}, cli)
	if err := source.Select("PROXY", "东京-01"); err != nil {
		t.Fatalf("select must succeed: %v", err)
	}
	if got := cli.lastCall(); len(got) != 3 || got[0] != "select" || got[1] != "PROXY" || got[2] != "东京-01" {
		t.Fatalf("the selection must go through the service, got %v", got)
	}
	if err := source.SetMode("global"); err != nil {
		t.Fatalf("mode must succeed: %v", err)
	}
	if got := cli.lastCall(); len(got) != 2 || got[0] != "mode" || got[1] != "global" {
		t.Fatalf("the mode change must go through the service, got %v", got)
	}
	if err := source.RefreshProvider("subscribe-a"); err != nil {
		t.Fatalf("the provider refresh must succeed: %v", err)
	}
	if got := cli.lastCall(); len(got) != 3 || got[0] != "provider" || got[1] != "refresh" {
		t.Fatalf("the provider refresh must go through the service, got %v", got)
	}
	delay, err := source.DelayFor("subscribe-a", "东京-01", 5000)
	if err != nil {
		t.Fatalf("the delay must succeed: %v", err)
	}
	if delay != 42 {
		t.Fatalf("the measured delay must come from the service, got %d", delay)
	}
	if got := cli.lastCall(); len(got) != 4 || got[0] != "latency" || got[2] != "--provider" {
		t.Fatalf("the probe must carry the provider identity, got %v", got)
	}
}

// A service refusal keeps its own code, so the console can say why the
// change was refused instead of showing a generic failure.
func TestServiceRefusalIsReported(t *testing.T) {
	cli := &serviceCli{fail: true}
	source := newAPISourceWithService(CtlConfig{Port: 9090}, cli)
	err := source.Select("PROXY", "东京-01")
	if err == nil {
		t.Fatal("a refused selection must be an error")
	}
	if !strings.Contains(err.Error(), "cross-level-selection-refused") {
		t.Fatalf("the refusal must keep its code, got %v", err)
	}
}

// Without a service the source keeps its direct controller behaviour.
func TestMutationsWithoutAServiceKeepTheDirectPath(t *testing.T) {
	source := newAPISource(CtlConfig{Port: 9090})
	if source.service != nil {
		t.Fatal("the plain constructor must not attach a service")
	}
}

// The overview shows the service status: the pending restart, the
// controller state and the features that could not be read.
func TestOverviewShowsTheServiceStatus(t *testing.T) {
	cli := &stubCli{env: Envelope{Schema: "mihomoctl/v1", Overall: "PASS", Data: map[string]any{
		"controller": "unavailable", "error": "config-missing", "pending_restart": true,
	}}}
	app := NewApp(newDemoSource(), cli, 100, 30, pageOverview, true)
	app.refreshOverviewStatus()
	drainAPI(t, app)
	app.draw()
	plain := app.scr.DumpPlain()
	if !strings.Contains(plain, "尚未生效") {
		t.Fatalf("the pending restart must be visible:\n%s", plain)
	}
	if !strings.Contains(plain, "控制器尚未连接") {
		t.Fatalf("the controller state must be visible:\n%s", plain)
	}
	if !strings.Contains(plain, "config-missing") {
		t.Fatalf("the reason must be visible:\n%s", plain)
	}

	// A feature whose read failed is named, so a partial page never reads
	// as a complete one.
	app = NewApp(newDemoSource(), &stubCli{env: Envelope{Overall: "PASS"}}, 100, 30, pageOverview, true)
	app.errs["proxies"] = "controller-unreachable"
	app.draw()
	plain = app.scr.DumpPlain()
	if !strings.Contains(plain, "功能 groups 暂不可用") {
		t.Fatalf("an unavailable feature must be named:\n%s", plain)
	}
}

// ownerCli is a service that can prove whether the running core belongs to
// this scope.
type ownerCli struct {
	serviceCli
	owned  bool
	reason string
}

func (c *ownerCli) RuntimeOwnerProof() (bool, string) { return c.owned, c.reason }

// The controller check alone does not say whose core answered; the service
// owner proof is what says so.
func TestRuntimeOwnerProofIsCheckedWhenTheServiceOffersIt(t *testing.T) {
	source := newAPISourceWithService(CtlConfig{Port: 9090}, &ownerCli{owned: true})
	if err := source.verifyOwner(); err != nil {
		t.Fatalf("a proven owner must pass, got %v", err)
	}
	source = newAPISourceWithService(CtlConfig{Port: 9090}, &ownerCli{owned: false, reason: "runtime-not-managed"})
	err := source.verifyOwner()
	if err == nil {
		t.Fatal("an unproven owner must fail")
	}
	if err.Error() != "runtime-not-managed" {
		t.Fatalf("the reason must be kept, got %v", err)
	}
	// A service that cannot prove it is not asked.
	source = newAPISourceWithService(CtlConfig{Port: 9090}, &serviceCli{})
	if err := source.verifyOwner(); err != nil {
		t.Fatalf("a service without the proof must not fail the check, got %v", err)
	}
}

// The options picker drives the theme, the log level and the character set.
func TestOptionsPickerAppliesTheChosenValue(t *testing.T) {
	source := newLevelSource()
	app := NewApp(source, &stubCli{env: Envelope{Overall: "PASS"}}, 100, 30, pageLogs, true)
	app.changePage(pageLogs)
	drainAPI(t, app)
	app.openOptions()
	if app.picker == nil {
		t.Fatal("the options picker must open")
	}
	app.pickerKey(Key{Type: KeyDown})  // log level
	app.pickerKey(Key{Type: KeyEnter}) // open its sub-list
	items := app.picker.items()
	if len(items) != 4 {
		t.Fatalf("the log level list must offer four levels, got %d", len(items))
	}
	for app.picker.index < 3 {
		app.pickerKey(Key{Type: KeyDown})
	}
	app.pickerKey(Key{Type: KeyEnter})
	if app.logLevel != "error" {
		t.Fatalf("the picked level must be applied, got %q", app.logLevel)
	}
	if app.picker != nil {
		t.Fatal("the picker must close after a final choice")
	}
	drainAPI(t, app)
	if source.lastLevel() != "error" {
		t.Fatalf("the stream must run at the picked level, got %q", source.lastLevel())
	}
}

// A narrow terminal must not draw columns past its right edge.
func TestNarrowTerminalKeepsEveryColumnOnScreen(t *testing.T) {
	app := NewApp(newDemoSource(), &stubCli{env: Envelope{Overall: "PASS"}}, 60, 20, pageConnections, true)
	conns, _ := newDemoSource().Connections()
	app.conns = conns.Connections
	app.changePage(pageConnections)
	app.draw()
	columns := app.connectionColumns()
	if columns.downX+columns.downW > app.scr.W {
		t.Fatalf("the download column ends at %d, past the width %d",
			columns.downX+columns.downW, app.scr.W)
	}
	for _, line := range strings.Split(app.scr.DumpPlain(), "\n") {
		if displayWidth(line) > app.scr.W {
			t.Fatalf("a line is wider than the terminal: %d > %d", displayWidth(line), app.scr.W)
		}
	}
}

// Below the supported size the console says so instead of drawing a frame
// nobody can read.
func TestTinyTerminalShowsTheMinimumSizeWarning(t *testing.T) {
	app := NewApp(newDemoSource(), &stubCli{env: Envelope{Overall: "PASS"}}, 50, 10, pageOverview, true)
	app.draw()
	plain := app.scr.DumpPlain()
	if !strings.Contains(plain, "60×14") {
		t.Fatalf("the tiny terminal must be reported:\n%s", plain)
	}
}

// Esc cancels a review that was prepared but not saved.
func TestEscapeCancelsThePendingPreview(t *testing.T) {
	app := NewApp(newDemoSource(), &stubCli{env: Envelope{Overall: "PASS"}}, 100, 30, pageSubscriptions, true)
	app.SetInitialPreview(map[string]any{
		"state": "preview", "id": strings.Repeat("a", 32), "sha256": strings.Repeat("b", 64),
		"policy": "provider", "nodes": 1,
	})
	if app.subPreview == nil {
		t.Fatal("the seeded preview must be kept")
	}
	if app.page != pageSubscriptions {
		t.Fatalf("a seeded preview must open the subscription page, got %q", app.page)
	}
	app.onKey(Key{Type: KeyRune, Rune: 'x'}) // an unrelated key first
	app.onKey(Key{Type: KeyEsc})
	if app.subPreview != nil {
		t.Fatal("Esc must cancel the pending preview")
	}
	if !strings.Contains(app.notice, "已取消") {
		t.Fatalf("the cancellation must be reported, got %q", app.notice)
	}
}

// discardCli releases a preview the way a service that owns the temporary
// candidate file does, and can be told to fail.
type discardCli struct {
	recordingCli
	mu      sync.Mutex
	dropped []string
	fail    bool
}

func (c *discardCli) SubscriptionDiscard(id string) (Envelope, error) {
	c.mu.Lock()
	c.dropped = append(c.dropped, id)
	fail := c.fail
	c.mu.Unlock()
	if fail {
		return Envelope{Overall: "FAIL"}, errors.New("discard refused")
	}
	return Envelope{Schema: "mihomoctl/v1", Command: "subscription-discard", Overall: "PASS"}, nil
}

func (c *discardCli) discards() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.dropped...)
}

// An abandoned preview must be released without blocking the key handler,
// and a failed release must stay invisible: it is not a console error.
func TestPreviewDiscardRunsInTheBackgroundAndStaysQuiet(t *testing.T) {
	cli := &discardCli{}
	app := NewApp(newDemoSource(), cli, 100, 30, pageSubscriptions, true)
	app.subID = "preview-1"
	app.discardPreview()
	drainAPI(t, app)
	if got := cli.discards(); len(got) != 1 || got[0] != "preview-1" {
		t.Fatalf("the abandoned preview must be released once, got %v", got)
	}
	for key := range app.errs {
		if strings.HasPrefix(key, "discard:") {
			t.Fatalf("a successful release must not be recorded as an error: %v", app.errs)
		}
	}

	// A refused release is best effort: no error entry, no notice.
	cli.mu.Lock()
	cli.fail = true
	cli.mu.Unlock()
	app.subID = "preview-2"
	app.discardPreview()
	drainAPI(t, app)
	for key := range app.errs {
		if strings.HasPrefix(key, "discard:") {
			t.Fatalf("a refused release must not be recorded as an error: %v", app.errs)
		}
	}
	if app.notice != "" {
		t.Fatalf("a refused release must not raise a notice, got %q", app.notice)
	}
}

// The filter reaches the pages that consume it.
func TestFilterAppliesToProvidersAndRules(t *testing.T) {
	app := NewApp(newDemoSource(), &stubCli{env: Envelope{Overall: "PASS"}}, 100, 30, pageProviders, true)
	app.proxyProv = []ProxyProvider{{Name: "subscribe-a", VehicleType: "HTTP"}, {Name: "other", VehicleType: "File"}}
	app.ruleProv = []RuleProvider{{Name: "reject", Behavior: "domain", RuleCount: 10}}
	app.changePage(pageProviders)
	app.onKey(Key{Type: KeyRune, Rune: '/'})
	if !app.filtering {
		t.Fatal("the filter must open on the providers page")
	}
	for _, r := range "subscribe" {
		app.onKey(Key{Type: KeyRune, Rune: r})
	}
	app.onKey(Key{Type: KeyEnter})
	app.draw()
	plain := app.scr.DumpPlain()
	if !strings.Contains(plain, "subscribe-a") {
		t.Fatalf("the matching provider must stay visible:\n%s", plain)
	}
	if strings.Contains(plain, "other") {
		t.Fatalf("the other provider must be filtered out:\n%s", plain)
	}
}

// Quitting waits for a confirmed operation instead of cutting it in half.
func TestQuitWaitsForTheRunningOperation(t *testing.T) {
	app := NewApp(newDemoSource(), &stubCli{env: Envelope{Overall: "PASS"}}, 100, 30, pageOverview, true)
	app.post("op:start", func() apiMsg { return apiMsg{kind: "op:start", opName: "start"} })
	app.requestQuit()
	if app.quit {
		t.Fatal("the console must not exit while an operation is running")
	}
	if !app.exitRequested {
		t.Fatal("the exit must be deferred")
	}
	drainAPI(t, app)
	if !app.quit {
		t.Fatal("the console must exit once the operation finished")
	}
}

// The runtime page presents the seven V1 facts, and prints every one of
// them even when the observation is missing.
func TestRuntimeFactsPrintEveryRow(t *testing.T) {
	rows := runtimeFacts(map[string]any{"scope": "user", "backend": "process", "overall": "PASS"})
	joined := strings.Join(rows, "\n")
	for _, want := range []string{"运行时 · 作用域 user · 后端 process · 结论 PASS",
		"核心：unknown", "控制器：unknown", "监听：unknown", "生效配置：unknown",
		"代理模式：unknown", "TUN：unknown"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q in:\n%s", want, joined)
		}
	}
}

// The policy list keeps the guided import first and offers every policy of
// the Textual console.
func TestPolicyListCoversEveryPolicy(t *testing.T) {
	if len(policyOrder) != 5 {
		t.Fatalf("expected five policies, got %v", policyOrder)
	}
	for _, policy := range policyOrder {
		if policyNames[policy] == "" || policyHelp[policy] == "" {
			t.Fatalf("policy %q has no label or no explanation", policy)
		}
	}
	if policyOrder[0] != "simple" {
		t.Fatalf("the guided import must be the first policy, got %q", policyOrder[0])
	}
}

// The theme command switches the palette and refuses an unknown theme.
func TestThemeCommandSwitchesThePalette(t *testing.T) {
	app := NewApp(newDemoSource(), &stubCli{env: Envelope{Overall: "PASS"}}, 100, 30, pageOverview, true)
	app.executeCommand("theme light")
	if app.theme != ThemeLight {
		t.Fatalf("the theme command must apply the theme, got %q", app.theme)
	}
	app.executeCommand("theme neon")
	if app.theme != ThemeLight {
		t.Fatalf("an unknown theme must be refused, got %q", app.theme)
	}
	if !strings.Contains(app.notice, "用法") {
		t.Fatalf("an unknown theme must be explained, got %q", app.notice)
	}
}

// The console starts on the page the retained identifier names.
func TestNewAppResolvesThePageAlias(t *testing.T) {
	app := NewApp(newDemoSource(), &stubCli{env: Envelope{Overall: "PASS"}}, 100, 30, "profiles", true)
	if app.page != pageSubscriptions {
		t.Fatalf("the retained identifier must open the subscription page, got %q", app.page)
	}
}

// The picker returns to its parent level instead of closing.
func TestPickerReturnsToTheParentLevel(t *testing.T) {
	app := NewApp(newDemoSource(), &stubCli{env: Envelope{Overall: "PASS"}}, 100, 30, pageOverview, true)
	app.openOptions()
	app.pickerKey(Key{Type: KeyEnter}) // open the theme sub-list
	if len(app.picker.items()) != 2 {
		t.Fatalf("the theme sub-list must offer two choices, got %d", len(app.picker.items()))
	}
	app.pickerKey(Key{Type: KeyLeft})
	if len(app.picker.items()) != 4 {
		t.Fatalf("the picker must return to the options level, got %d items", len(app.picker.items()))
	}
	if app.picker == nil {
		t.Fatal("the picker must stay open")
	}
	app.pickerKey(Key{Type: KeyEsc})
	if app.picker != nil {
		t.Fatal("Esc must close the picker")
	}
}

// The ASCII character set replaces the box drawing of the modal.
func TestASCIICharacterSetDrawsPlainBoxes(t *testing.T) {
	app := NewApp(newDemoSource(), &stubCli{env: Envelope{Overall: "PASS"}}, 100, 30, pageOverview, true)
	app.pending = &pendingAction{text: "确认？", run: func(app *App) {}}
	app.draw()
	if plain := app.scr.DumpPlain(); !strings.Contains(plain, "│") {
		t.Fatalf("the Unicode character set must draw the box:\n%s", plain)
	}
	app.SetASCII(true)
	app.draw()
	plain := app.scr.DumpPlain()
	if strings.Contains(plain, "│") || strings.Contains(plain, "─") {
		t.Fatalf("the ASCII character set must not draw box runes:\n%s", plain)
	}
	if !strings.Contains(plain, "|") {
		t.Fatalf("the ASCII character set must draw a plain box:\n%s", plain)
	}
}

// The logs page shows the level the stream runs at.
func TestLogsPageShowsTheStreamLevel(t *testing.T) {
	app := NewApp(newDemoSource(), &stubCli{env: Envelope{Overall: "PASS"}}, 100, 30, pageLogs, true)
	app.setLogLevel("warning")
	app.draw()
	plain := app.scr.DumpPlain()
	if !strings.Contains(plain, "日志级别：warning") {
		t.Fatalf("the logs page must show the level:\n%s", plain)
	}
}

// A page whose read failed shows the real reason instead of a "loading"
// line that would never end.
func TestFailedReadsShowTheirReasonOnThePage(t *testing.T) {
	cases := []struct {
		page  string
		kind  string
		want  string
		never string
	}{
		{page: pageRuntime, kind: "cli:status", want: "不可用：controller-unreachable", never: "正在读取运行时事实"},
		{page: pageProfile, kind: "cli:profile", want: "不可用：config-missing", never: "正在读取代理档案"},
		{page: pageProviders, kind: "proxy-providers", want: "不可用：core-not-running", never: "正在读取提供商"},
		{page: pageRules, kind: "rules", want: "不可用：core-not-running", never: "正在读取规则"},
	}
	for _, test := range cases {
		app := NewApp(newDemoSource(), &stubCli{env: Envelope{Overall: "PASS"}}, 100, 30, test.page, true)
		app.errs[test.kind] = test.want[len("不可用："):]
		app.draw()
		plain := app.scr.DumpPlain()
		if !strings.Contains(plain, test.want) {
			t.Fatalf("the page must show the reason %q:\n%s", test.want, plain)
		}
		if strings.Contains(plain, test.never) {
			t.Fatalf("the page must not keep the loading line %q:\n%s", test.never, plain)
		}
	}
}

// ---------------------------------------------------------------------------
// The controller clients must never follow a redirect: the bearer token
// would be handed to another service.
// ---------------------------------------------------------------------------

// controllerFixture is a controller that answers with a document.
func controllerFixture(t *testing.T, handler http.HandlerFunc) (*apiSource, func()) {
	t.Helper()
	server := httptest.NewServer(handler)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		server.Close()
		t.Fatalf("the fixture URL must parse: %v", err)
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil {
		server.Close()
		t.Fatalf("the fixture port must be a number: %v", err)
	}
	source := newAPISource(CtlConfig{Host: parsed.Hostname(), Port: port, Token: "secret"})
	return source, server.Close
}

// A redirect is refused and the bearer token never reaches the target.
func TestControllerRedirectsAreRefused(t *testing.T) {
	var leaked bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			leaked = true
		}
		w.Write([]byte(`{"mode":"rule"}`))
	}))
	defer target.Close()
	source, closeFixture := controllerFixture(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusFound)
	})
	defer closeFixture()

	_, err := source.Configs()
	if err == nil {
		t.Fatal("a redirect must be refused")
	}
	if !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("the reason must name the redirect, got %v", err)
	}
	if leaked {
		t.Fatal("the bearer token must not reach the redirect target")
	}
	// The streaming client refuses it as well.
	if _, err := source.StartLogs(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "redirect") {
		t.Fatalf("the log stream must refuse the redirect too, got %v", err)
	}
}

// The connections document is reduced to the fields a human may read; the
// rule payload comes back only when the details are asked for.
func TestConnectionsAreRedactedUntilTheDetailsAreAskedFor(t *testing.T) {
	document := `{"downloadTotal":10,"uploadTotal":20,"connections":[{"id":"1",
		"upload":1,"download":2,"chains":["DIRECT"],"rule":"MATCH","rulePayload":"secret-rule",
		"metadata":{"host":"example.com","destinationIP":"10.0.0.1","destinationPort":"443",
		"network":"tcp","sourceIP":"192.168.0.2","sourcePort":"5000","inboundUser":"someone"}}]}`
	source, closeFixture := controllerFixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(document))
	})
	defer closeFixture()

	doc, err := source.Connections()
	if err != nil {
		t.Fatalf("the connections must be read: %v", err)
	}
	if len(doc.Connections) != 1 {
		t.Fatalf("one connection must be read, got %d", len(doc.Connections))
	}
	conn := doc.Connections[0]
	if conn.RulePayload != "" {
		t.Fatalf("the rule payload must be hidden, got %q", conn.RulePayload)
	}
	if conn.Metadata.SourceIP != "" || conn.Metadata.SourcePort != "" || conn.Metadata.InboundUser != "" {
		t.Fatalf("the source address must be hidden, got %+v", conn.Metadata)
	}
	if conn.Metadata.Host != "example.com" || conn.Metadata.DstPort != "443" {
		t.Fatalf("the readable fields must be kept, got %+v", conn.Metadata)
	}

	source.SetConnectionDetails(true)
	doc, err = source.Connections()
	if err != nil {
		t.Fatalf("the connections must be read: %v", err)
	}
	if doc.Connections[0].RulePayload != "secret-rule" {
		t.Fatalf("the rule payload must be there when the details are asked for, got %q",
			doc.Connections[0].RulePayload)
	}
	if doc.Connections[0].Metadata.SourceIP != "" {
		t.Fatal("the source address stays hidden even with the details")
	}
}

// The app forwards the details to a source that can show them.
func TestSetDetailsReachesTheSource(t *testing.T) {
	source := newAPISource(CtlConfig{Port: 9090})
	app := NewApp(source, &stubCli{env: Envelope{Overall: "PASS"}}, 100, 30, pageConnections, true)
	app.SetDetails(true)
	if !source.details {
		t.Fatal("the details must reach the source")
	}
	app.SetDetails(false)
	if source.details {
		t.Fatal("the details must be switchable off again")
	}
}

// ---------------------------------------------------------------------------
// The profile page speaks to the service with real argv, and reads the
// envelope as well as the Go error.
// ---------------------------------------------------------------------------

// profileCli records the argv of every call and answers per verb.
type profileCli struct {
	recordingCli
	failures map[string]string
}

func (c *profileCli) Run(args ...string) (Envelope, error) {
	c.calls = append(c.calls, args)
	key := strings.Join(args, " ")
	if code, ok := c.failures[key]; ok {
		return Envelope{Schema: "mihomoctl/v1", Overall: "FAIL",
			Errors: []ErrDoc{{Code: code}}}, nil
	}
	return Envelope{Schema: "mihomoctl/v1", Overall: "PASS", Data: map[string]any{}}, nil
}

// The profile page uses separate tokens, and a failed envelope is reported
// instead of read as an empty page.
func TestProfilePageUsesSeparateTokensAndReadsTheEnvelope(t *testing.T) {
	cli := &profileCli{failures: map[string]string{"env show": "env-unavailable"}}
	app := NewApp(newDemoSource(), cli, 100, 30, pageProfile, true)
	msg := app.loadProfile()
	if msg.err != nil {
		t.Fatalf("the profile page must not fail as a whole: %v", msg.err)
	}
	joined := strings.Join(msg.lines, "\n")
	if !strings.Contains(joined, "环境变量：不可用 — env-unavailable") {
		t.Fatalf("the failed envelope must be reported:\n%s", joined)
	}
	for _, call := range cli.calls {
		if len(call) == 1 && strings.Contains(call[0], " ") {
			t.Fatalf("the verb must use separate tokens, got %q", call[0])
		}
	}
	found := map[string]bool{}
	for _, call := range cli.calls {
		found[strings.Join(call, " ")] = true
	}
	if !found["integration list"] || !found["env show"] {
		t.Fatalf("the profile verbs must reach the service, got %v", cli.calls)
	}
}

// ---------------------------------------------------------------------------
// The subscription save reports what the service actually did.
// ---------------------------------------------------------------------------

// saveStartCli saves the subscription and starts the runtime in one step.
type saveStartCli struct {
	recordingCli
	state   string
	overall string
}

func (c *saveStartCli) SubscriptionSaveAndStart(id, sha string) (Envelope, error) {
	overall := c.overall
	if overall == "" {
		overall = "PASS"
	}
	env := Envelope{Schema: "mihomoctl/v1", Overall: overall,
		Data: map[string]any{"state": c.state}}
	if overall != "PASS" {
		env.Errors = []ErrDoc{{Code: "subscription-apply-failed", Detail: "写入被拒绝"}}
	}
	return env, nil
}

// A saved subscription that still waits for a restart is not announced as a
// started runtime.
func TestSubscriptionSaveReportsWhatTheServiceActuallyDid(t *testing.T) {
	cli := &saveStartCli{state: "restart-required"}
	app := NewApp(newDemoSource(), cli, 100, 30, pageSubscriptions, true)
	app.subPreview = map[string]any{"id": "abc", "sha256": "def"}
	app.subID, app.subSHA = "abc", "def"
	app.askApplySubscription()
	app.pending.run(app)
	drainAPI(t, app)
	if !strings.Contains(app.notice, "尚未生效") {
		t.Fatalf("the pending restart must be reported, got %q", app.notice)
	}
	if strings.Contains(app.notice, "已保存并启动") {
		t.Fatalf("a pending restart must not be announced as started, got %q", app.notice)
	}
	if !app.pendingRestart {
		t.Fatal("the pending restart must be recorded")
	}

	// A refused save is a failure, not a silent success.
	for _, overall := range []string{"FAIL", "UNVERIFIED"} {
		cli = &saveStartCli{overall: overall}
		app = NewApp(newDemoSource(), cli, 100, 30, pageSubscriptions, true)
		app.subPreview = map[string]any{"id": "abc", "sha256": "def"}
		app.subID, app.subSHA = "abc", "def"
		app.askApplySubscription()
		app.pending.run(app)
		drainAPI(t, app)
		if !strings.Contains(app.notice, "subscription-apply-failed") {
			t.Fatalf("the %s envelope must be reported, got %q", overall, app.notice)
		}
		if strings.Contains(app.notice, "已保存") {
			t.Fatalf("a refused save must not be announced as saved, got %q", app.notice)
		}
	}
}

// applyCli answers the subscription verbs of a service that does not offer
// the save-and-start capability.
type applyCli struct {
	recordingCli
	applyState    string
	restartResult Envelope
	restartErr    error
}

func (c *applyCli) Run(args ...string) (Envelope, error) {
	c.calls = append(c.calls, args)
	if len(args) > 0 && args[0] == "subscription" && len(args) > 1 && args[1] == "apply" {
		return Envelope{Schema: "mihomoctl/v1", Overall: "PASS",
			Data: map[string]any{"state": c.applyState}}, nil
	}
	if len(args) > 0 && args[0] == "restart" {
		if c.restartErr != nil {
			return Envelope{}, c.restartErr
		}
		if c.restartResult.Overall == "" {
			return Envelope{Schema: "mihomoctl/v1", Overall: "PASS"}, nil
		}
		return c.restartResult, nil
	}
	return Envelope{Schema: "mihomoctl/v1", Overall: "PASS"}, nil
}

// Without the capability the console applies and restarts, and a failing
// restart is reported instead of being announced as a started runtime.
func TestSubscriptionSaveFallsBackToApplyAndRestart(t *testing.T) {
	cli := &applyCli{applyState: "restart-required"}
	app := NewApp(newDemoSource(), cli, 100, 30, pageSubscriptions, true)
	app.subPreview = map[string]any{"id": "abc", "sha256": "def"}
	app.subID, app.subSHA = "abc", "def"
	app.askApplySubscription()
	app.pending.run(app)
	drainAPI(t, app)
	restarted := false
	for _, call := range cli.calls {
		if len(call) > 0 && call[0] == "restart" {
			restarted = true
		}
	}
	if !restarted {
		t.Fatalf("the confirmed action must restart the runtime, got %v", cli.calls)
	}
	if !strings.Contains(app.notice, "已保存并启动") {
		t.Fatalf("the successful save must be reported, got %q", app.notice)
	}

	// A restart that fails must not be reported as a started runtime.
	cli = &applyCli{applyState: "restart-required",
		restartResult: Envelope{Schema: "mihomoctl/v1", Overall: "FAIL",
			Errors: []ErrDoc{{Code: "runtime-unavailable"}}}}
	app = NewApp(newDemoSource(), cli, 100, 30, pageSubscriptions, true)
	app.subPreview = map[string]any{"id": "abc", "sha256": "def"}
	app.subID, app.subSHA = "abc", "def"
	app.askApplySubscription()
	app.pending.run(app)
	drainAPI(t, app)
	if strings.Contains(app.notice, "已保存并启动") {
		t.Fatalf("a failed restart must not be announced as started, got %q", app.notice)
	}
	if !strings.Contains(app.notice, "subscription-saved-restart-failed") {
		t.Fatalf("the failed restart must be reported, got %q", app.notice)
	}
	if !app.pendingRestart {
		t.Fatal("the pending restart must be recorded")
	}
}

// ---------------------------------------------------------------------------
// The journal belongs to the managed runtime: it is only read through the
// service that knows the unit.
// ---------------------------------------------------------------------------

// journalCli is a service that can read the managed journal.
type journalCli struct {
	recordingCli
	lines []string
}

func (c *journalCli) Journal(since, until string, lines int) (Envelope, error) {
	c.calls = append(c.calls, []string{"journal", since, until})
	return Envelope{Schema: "mihomoctl/v1", Overall: "PASS",
		Data: map[string]any{"entries": c.lines}}, nil
}

// A service without the journal capability is not asked for one.
func TestJournalIsOnlyReadThroughTheService(t *testing.T) {
	app := NewApp(newDemoSource(), &stubCli{env: Envelope{Overall: "PASS"}}, 100, 30, pageDiagnostics, true)
	app.runJournal("", "")
	drainAPI(t, app)
	if !strings.Contains(app.notice, "journal-not-supported") {
		t.Fatalf("the missing capability must be reported, got %q", app.notice)
	}
	if len(app.diagRows) != 0 {
		t.Fatalf("no rows may be invented, got %v", app.diagRows)
	}

	cli := &journalCli{lines: []string{"一、日志"}}
	app = NewApp(newDemoSource(), cli, 100, 30, pageDiagnostics, true)
	app.runJournal("2026-01-01", "")
	drainAPI(t, app)
	if len(app.diagRows) == 0 {
		t.Fatal("the journal must reach the diagnostics page")
	}
}

// ---------------------------------------------------------------------------
// The override script is previewed first and written only after a
// confirmation.
// ---------------------------------------------------------------------------

// The script flags are forwarded, and the apply waits for the confirmation.
func TestOverridePreviewForwardsTheScriptAndTheConfirmationAppliesIt(t *testing.T) {
	cli := &recordingCli{}
	app := NewApp(newDemoSource(), cli, 100, 30, pageOverview, true)
	app.ConfigureScript("/private/trusted.js", true)
	app.askOverride()
	drainAPI(t, app)
	if len(cli.calls) != 1 {
		t.Fatalf("the preview must be one call, got %v", cli.calls)
	}
	want := []string{"override", "--script", "/private/trusted.js", "--flclash-compat"}
	if strings.Join(cli.calls[0], " ") != strings.Join(want, " ") {
		t.Fatalf("the preview must forward the script flags, got %v", cli.calls[0])
	}
	// The preview never writes on its own.
	for _, call := range cli.calls {
		for _, arg := range call {
			if arg == "--apply" {
				t.Fatal("the preview must not apply anything")
			}
		}
	}
	// The preview opens the confirmation, and the confirmation applies.
	if app.pending == nil {
		t.Fatal("the preview must ask for a confirmation")
	}
	app.pending.run(app)
	drainAPI(t, app)
	applied := false
	for _, call := range cli.calls {
		for _, arg := range call {
			if arg == "--apply" {
				applied = true
			}
		}
	}
	if !applied {
		t.Fatalf("the confirmed action must apply, got %v", cli.calls)
	}
}

// A refused confirmation writes nothing.
func TestOverrideConfirmationRefusesWithoutApply(t *testing.T) {
	cli := &recordingCli{}
	app := NewApp(newDemoSource(), cli, 100, 30, pageOverview, true)
	app.ConfigureScript("/private/trusted.js", false)
	app.askOverride()
	drainAPI(t, app)
	if app.pending == nil {
		t.Fatal("the preview must ask for a confirmation")
	}
	// The modal is dismissed: the run function never fires.
	app.pending = nil
	if len(cli.calls) != 1 {
		t.Fatalf("only the preview may have run, got %v", cli.calls)
	}
	for _, call := range cli.calls {
		for _, arg := range call {
			if arg == "--apply" {
				t.Fatal("a refused confirmation must not apply anything")
			}
		}
	}
}

// Without a trusted script the console says so instead of guessing one.
func TestOverrideNeedsATrustedScript(t *testing.T) {
	cli := &recordingCli{}
	app := NewApp(newDemoSource(), cli, 100, 30, pageOverview, true)
	app.askOverride()
	drainAPI(t, app)
	if len(cli.calls) != 0 {
		t.Fatalf("nothing may be called without a script, got %v", cli.calls)
	}
	if !strings.Contains(app.notice, "受信脚本") {
		t.Fatalf("the missing script must be reported, got %q", app.notice)
	}
}
