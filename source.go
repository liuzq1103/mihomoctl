package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// testURL matches the Python console: only a public HTTPS 204 target.
const testURL = "https://www.gstatic.com/generate_204"

// Source is every data operation the UI needs. Fetches are synchronous; the
// app always runs them in goroutines so a key press never waits on the
// network.
type Source interface {
	Version() (VersionDoc, error)
	Configs() (ConfigsDoc, error)
	Proxies() (ProxiesDoc, error)
	Connections() (ConnectionsDoc, error)
	Rules() (RulesDoc, error)
	RuleProviders() (RuleProvidersDoc, error)
	Memory() (MemoryDoc, error)
	ProxyProviders() (ProxyProvidersDoc, error)
	Select(group, node string) error
	// DelayFor probes a node; a non-empty provider uses the provider-scoped
	// healthcheck route (v1.4.3 provider identities).
	DelayFor(provider, node string, timeoutMS int) (int, error)
	Delay(node string, timeoutMS int) (int, error)
	SetMode(mode string) error
	RefreshProvider(name string) error
	DNS(name, record string) (DNSAnswer, error)
	Download(url string) ([]byte, error)
	StartTraffic(ctx context.Context) (<-chan Traffic, error)
	StartLogs(ctx context.Context) (<-chan LogLine, error)
}

// LogLevelSource is an optional Source capability: reopen the log stream at
// a chosen level. The level is part of the stream request, so changing it
// means restarting the stream.
//
// It is deliberately not part of Source: a source that cannot choose a level
// simply keeps the default one, and every existing stub still compiles.
type LogLevelSource interface {
	StartLogsAt(ctx context.Context, level string) (<-chan LogLine, error)
}

// SubscriptionInputCli is an optional CliSource capability: import a private
// subscription with the guided "simple" semantics.
//
// The guided import is a service-level operation, not a CLI verb: it looks at
// the local configuration to decide between a full provider import (the local
// configuration is still a simple shape) and a nodes-only merge (the local
// routing must be preserved). The CLI preview verb only accepts
// auto/nodes/provider/policy, because "simple" has no meaning without that
// local state.
//
// A service that does not implement it keeps the console honest: the request
// falls back to "auto" and the page says so.
type SubscriptionInputCli interface {
	SubscriptionInput(value, kind, policy string) (Envelope, error)
}

// CrossLevelSelectSource is an optional Source capability: select a member
// that skips the group hierarchy. The service refuses such a selection
// unless it is authorised explicitly, so the console asks before it tries.
type CrossLevelSelectSource interface {
	SelectAllowCrossLevel(group, node string) error
}

// SubscriptionDiscardCli is an optional CliSource capability: release a
// private preview the user abandoned, so the backend can drop its temporary
// candidate file.
type SubscriptionDiscardCli interface {
	SubscriptionDiscard(id string) (Envelope, error)
}

// RuntimeOwnerSource is an optional CliSource capability: the service can
// prove that the running core belongs to this user's scope. An anonymous 401
// only proves that the controller asks for a secret; the owner proof is what
// says that this core is the one this scope manages.
type RuntimeOwnerSource interface {
	// RuntimeOwnerProof reports whether the running core belongs to the
	// scope, with the reason when it does not.
	RuntimeOwnerProof() (bool, string)
}

// SubscriptionSaveAndStartCli is an optional CliSource capability: save the
// previewed subscription and bring the runtime up with it.
//
// The service owns that sequence, and it reports what really happened: a
// result that still waits for a restart is not a started runtime. The console
// asks for the capability when the service offers it, and checks the
// envelope it gets back.
type SubscriptionSaveAndStartCli interface {
	SubscriptionSaveAndStart(id, sha string) (Envelope, error)
}

// JournalCli is an optional CliSource capability: read the journal of the
// runtime this scope manages.
//
// The journal belongs to that unit. A console that guesses a unit name would
// read an unrelated service's log and present it as this runtime's history,
// so the journal is only read through the service that knows the unit.
type JournalCli interface {
	Journal(since, until string, lines int) (Envelope, error)
}

// ConnectionDetailsSource is an optional Source capability: include the
// sensitive connection details that the console hides by default.
//
// The controller answers with the source address, the inbound user and the
// rule payload of every connection. The audited console shows only the
// fields a human may read, so the source drops the rest; the rule payload
// comes back only when the operator asks for the details explicitly.
type ConnectionDetailsSource interface {
	SetConnectionDetails(enabled bool)
}

// apiSource talks to the mihomo controller over keep-alive HTTP. Connections
// are pooled per host, so polling costs no TCP setup, unlike the Python
// console which opens and closes a connection per request.
type apiSource struct {
	base    string
	token   string
	call    *http.Client // request/response with a hard timeout
	live    *http.Client // streaming endpoints; bounded by context instead
	details bool         // include the sensitive connection details on request

	// service is the shared application service. When it is set, the
	// mutations that change the running core go through it: the service
	// owns the selection rules (group membership, node identity, the
	// cross-level authorisation) and confirms every change by reading it
	// back. A direct controller write would bypass all of that.
	service CliSource
}

// errControllerRedirect is the reason a controller redirect is refused.
//
// The controller answers with a bearer token. A redirect — even to another
// port of the same host — would hand that token to a different service, so
// the console never follows one: the answer has to come from the controller
// it verified.
var errControllerRedirect = errors.New("controller-redirect-refused")

// refuseControllerRedirect refuses every redirect of the controller clients.
func refuseControllerRedirect(req *http.Request, via []*http.Request) error {
	return errControllerRedirect
}

func newAPISource(cfg CtlConfig) *apiSource {
	transport := &http.Transport{
		MaxIdleConns:        8,
		MaxIdleConnsPerHost: 8,
		IdleConnTimeout:     90 * time.Second,
		// Bounds how long opening a stream may hang (a wedged controller
		// would otherwise park the open attempt forever and block reconnect);
		// body reads stay unbounded, as streaming requires.
		ResponseHeaderTimeout: 10 * time.Second,
	}
	return &apiSource{
		base:  "http://" + net.JoinHostPort(controllerHost(cfg), strconv.Itoa(cfg.Port)),
		token: cfg.Token,
		call: &http.Client{Transport: transport, Timeout: 8 * time.Second,
			CheckRedirect: refuseControllerRedirect},
		live: &http.Client{Transport: transport, CheckRedirect: refuseControllerRedirect},
	}
}

// newAPISourceWithService attaches the shared application service to the
// controller source. Reads stay on the controller API; the mutations run
// through the service, which is the only component that knows the scope
// rules and the node identities. Without a service the source keeps its
// direct controller behaviour, which is what the fixtures exercise.
func newAPISourceWithService(cfg CtlConfig, cli CliSource) *apiSource {
	source := newAPISource(cfg)
	source.service = cli
	return source
}

// controllerHost is the host the controller was validated on. The validated
// address is preserved as it was written, so "::1" and "localhost" keep
// working; a configuration without a host falls back to the IPv4 loopback
// the fixtures use.
func controllerHost(cfg CtlConfig) string {
	if cfg.Host != "" {
		return cfg.Host
	}
	return "127.0.0.1"
}

// verify reproduces the Python client check: the controller must reject an
// anonymous /version with 401 and accept the authorized one.
//
// When the service can also prove that the running core belongs to this
// scope, the proof is part of the check: the 401 alone says nothing about
// whose core answered.
func (a *apiSource) verify() error {
	req, err := http.NewRequest("GET", a.base+"/version", nil)
	if err != nil {
		return err
	}
	resp, err := a.call.Do(req)
	if err != nil {
		if errors.Is(err, errControllerRedirect) {
			return errControllerRedirect
		}
		return errors.New("controller-unreachable")
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		return errors.New("controller-authentication-not-enforced")
	}
	if err := a.verifyOwner(); err != nil {
		return err
	}
	_, err = a.Version()
	return err
}

// verifyOwner asks the service to prove that the running core belongs to
// this scope. A service that cannot prove it is not asked.
func (a *apiSource) verifyOwner() error {
	owner, ok := a.service.(RuntimeOwnerSource)
	if !ok {
		return nil
	}
	owned, reason := owner.RuntimeOwnerProof()
	if owned {
		return nil
	}
	if reason == "" {
		reason = "runtime-owner-mismatch"
	}
	return errors.New(reason)
}

func (a *apiSource) request(method, path string, body, out any, client *http.Client) error {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, a.base+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		if errors.Is(err, errControllerRedirect) {
			return errControllerRedirect
		}
		return errors.New("controller-unreachable")
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return errors.New("controller-authentication-failed")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("controller-request-failed-%d", resp.StatusCode)
	}
	if out != nil {
		raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		if err != nil {
			return errors.New("controller-response-invalid")
		}
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, out); err != nil {
				return errors.New("controller-response-invalid")
			}
		}
	}
	return nil
}

func (a *apiSource) Version() (VersionDoc, error) {
	var out VersionDoc
	err := a.request("GET", "/version", nil, &out, a.call)
	return out, err
}

func (a *apiSource) Configs() (ConfigsDoc, error) {
	var out ConfigsDoc
	err := a.request("GET", "/configs", nil, &out, a.call)
	return out, err
}

func (a *apiSource) Proxies() (ProxiesDoc, error) {
	var out ProxiesDoc
	err := a.request("GET", "/proxies", nil, &out, a.call)
	return out, err
}

func (a *apiSource) Connections() (ConnectionsDoc, error) {
	var out ConnectionsDoc
	err := a.request("GET", "/connections", nil, &out, a.call)
	if err != nil {
		return ConnectionsDoc{}, err
	}
	out.Connections = a.projectConnections(out.Connections)
	return out, nil
}

// projectConnections reduces the controller document to the fields a human
// may read.
//
// The controller answers with the source address, the inbound user and the
// rule payload of every connection. The audited service drops them before
// the data ever leaves the service, so the source drops them here too: the
// rule payload comes back only when the operator asks for the details
// explicitly.
func (a *apiSource) projectConnections(conns []Conn) []Conn {
	projected := make([]Conn, 0, len(conns))
	for _, conn := range conns {
		meta := conn.Metadata
		meta.SourceIP = ""
		meta.SourcePort = ""
		meta.InboundUser = ""
		if !a.details {
			conn.RulePayload = ""
		}
		conn.Metadata = meta
		projected = append(projected, conn)
	}
	return projected
}

// SetConnectionDetails includes the sensitive connection details (the rule
// payload) in the projection. The console keeps them hidden by default.
func (a *apiSource) SetConnectionDetails(enabled bool) { a.details = enabled }

func (a *apiSource) Rules() (RulesDoc, error) {
	var out RulesDoc
	err := a.request("GET", "/rules", nil, &out, a.call)
	return out, err
}

func (a *apiSource) RuleProviders() (RuleProvidersDoc, error) {
	var out RuleProvidersDoc
	err := a.request("GET", "/providers/rules", nil, &out, a.call)
	return out, err
}

func (a *apiSource) Memory() (MemoryDoc, error) {
	var out MemoryDoc
	err := a.request("GET", "/memory", nil, &out, a.call)
	return out, err
}

func (a *apiSource) Select(group, node string) error {
	if a.service != nil {
		// The service checks that the group is a Selector, that the node is
		// a member of it and that the node identity is unambiguous, refuses
		// a cross-level selection without authorisation, and confirms the
		// change by reading the group back.
		env, err := a.service.Run("select", group, node)
		return serviceError(env, err)
	}
	return a.request("PUT", "/proxies/"+url.PathEscape(group), map[string]string{"name": node}, nil, a.call)
}

// SelectAllowCrossLevel performs the selection that skips the group
// hierarchy. It is the explicit authorisation the service asks for; a
// source without a service has no hierarchy to skip.
func (a *apiSource) SelectAllowCrossLevel(group, node string) error {
	if a.service != nil {
		env, err := a.service.Run("select", group, node, "--allow-cross-level")
		return serviceError(env, err)
	}
	return a.Select(group, node)
}

func (a *apiSource) Delay(node string, timeoutMS int) (int, error) {
	return a.DelayFor("", node, timeoutMS)
}

func (a *apiSource) DelayFor(provider, node string, timeoutMS int) (int, error) {
	if a.service != nil {
		// The service probes the exact node identity against the public
		// target and owns the timeout; it also refuses a node that is not
		// in the core any more.
		args := []string{"latency", node}
		if provider != "" {
			args = append(args, "--provider", provider)
		} else {
			args = append(args, "--global")
		}
		env, err := a.service.Run(args...)
		if err := serviceError(env, err); err != nil {
			return 0, err
		}
		return envelopeDelay(env), nil
	}
	var out struct {
		Delay int `json:"delay"`
	}
	// Provider nodes use /providers/proxies/P/N/healthcheck; global nodes use
	// /proxies/N/delay — mirroring the audited Python measure_delay.
	var path string
	if provider != "" {
		path = "/providers/proxies/" + url.PathEscape(provider) + "/" + url.PathEscape(node) + "/healthcheck"
	} else {
		path = "/proxies/" + url.PathEscape(node) + "/delay"
	}
	path += "?url=" + url.QueryEscape(testURL) + "&timeout=" + strconv.Itoa(timeoutMS)
	if err := a.request("GET", path, nil, &out, a.call); err != nil {
		return 0, err
	}
	return out.Delay, nil
}

func (a *apiSource) SetMode(mode string) error {
	if a.service != nil {
		// The service validates the mode and confirms it by reading the
		// running configuration back.
		env, err := a.service.Run("mode", mode)
		return serviceError(env, err)
	}
	return a.request("PATCH", "/configs", map[string]string{"mode": mode}, nil, a.call)
}

// serviceError turns a service envelope into an error. A refusal keeps the
// service's own code and detail, so the console can show why the change was
// refused instead of a generic failure.
func serviceError(env Envelope, err error) error {
	if err != nil {
		return err
	}
	if env.Overall == "PASS" {
		return nil
	}
	if len(env.Errors) > 0 {
		failure := env.Errors[0]
		code := failure.Code
		if code == "" {
			code = "service-request-failed"
		}
		if failure.Detail != "" {
			return fmt.Errorf("%s: %s", code, failure.Detail)
		}
		return errors.New(code)
	}
	return errors.New("service-request-failed")
}

// envelopeDelay reads the measured delay out of a service envelope. The
// value crosses a JSON boundary, so it arrives as a float64.
func envelopeDelay(env Envelope) int {
	switch value := env.Data["delay_ms"].(type) {
	case float64:
		return int(value)
	case int:
		return value
	case int64:
		return int(value)
	case json.Number:
		number, err := value.Int64()
		if err != nil {
			return 0
		}
		return int(number)
	}
	return 0
}

// streamLines reads one newline-delimited JSON stream until the context ends.
// Backpressure is the channel: a slow UI drops nothing, the kernel buffer and
// the read loop pace themselves. mkErr, when non-nil, renders a scanner
// failure as one stream item so the break is visible instead of silent.
func streamLines[T any](a *apiSource, ctx context.Context, path string, mkErr func(error) T) (<-chan T, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", a.base+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	resp, err := a.live.Do(req)
	if err != nil {
		if errors.Is(err, errControllerRedirect) {
			return nil, errControllerRedirect
		}
		return nil, errors.New("controller-unreachable")
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("controller-request-failed-%d", resp.StatusCode)
	}
	out := make(chan T, 16)
	go func() {
		defer close(out)
		defer resp.Body.Close()
		scanner := bufio.NewScanner(resp.Body)
		// 1 MiB cap: a single oversized log line must not silently kill the
		// stream (the default 64 KiB would end the scan with an error).
		scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			var value T
			if json.Unmarshal([]byte(line), &value) != nil {
				continue
			}
			select {
			case out <- value:
			case <-ctx.Done():
				return
			}
		}
		// Scanner failures (oversized line, mid-stream read error) surface as
		// a visible item; the app then reconnects with backoff.
		if err := scanner.Err(); err != nil && ctx.Err() == nil && mkErr != nil {
			select {
			case out <- mkErr(err):
			case <-ctx.Done():
			}
		}
	}()
	return out, nil
}

func (a *apiSource) ProxyProviders() (ProxyProvidersDoc, error) {
	var out ProxyProvidersDoc
	err := a.request("GET", "/providers/proxies", nil, &out, a.call)
	return out, err
}

func (a *apiSource) RefreshProvider(name string) error {
	if a.service != nil {
		// The service resolves the exact configured provider name and
		// refuses an unknown one instead of refreshing a guess.
		env, err := a.service.Run("provider", "refresh", name)
		return serviceError(env, err)
	}
	return a.request("PUT", "/providers/proxies/"+url.PathEscape(name), nil, nil, a.call)
}

func (a *apiSource) DNS(name, record string) (DNSAnswer, error) {
	var out DNSAnswer
	path := "/dns/query?" + url.Values{"name": {name}, "type": {record}}.Encode()
	err := a.request("GET", path, nil, &out, a.call)
	return out, err
}

// Download fetches a subscription URL directly, ignoring any proxy variables
// the shell may carry, and bounds the payload like the Python downloader.
func (a *apiSource) Download(rawURL string) ([]byte, error) {
	client := &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{Proxy: nil},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("too-many-redirects")
			}
			return nil
		},
	}
	resp, err := client.Get(rawURL)
	if err != nil {
		return nil, errors.New("subscription-download-failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("subscription-download-failed-%d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil || len(body) == 0 {
		return nil, errors.New("subscription-download-failed")
	}
	return body, nil
}

func (a *apiSource) StartTraffic(ctx context.Context) (<-chan Traffic, error) {
	return streamLines[Traffic](a, ctx, "/traffic", nil)
}

func (a *apiSource) StartLogs(ctx context.Context) (<-chan LogLine, error) {
	return a.StartLogsAt(ctx, "info")
}

// StartLogsAt opens the log stream at the requested level. The level is part
// of the request, so a level change means a new stream.
func (a *apiSource) StartLogsAt(ctx context.Context, level string) (<-chan LogLine, error) {
	switch level {
	case "debug", "info", "warning", "error":
	default:
		level = "info"
	}
	return streamLines[LogLine](a, ctx, "/logs?level="+level, func(err error) LogLine {
		return LogLine{Type: "error", Payload: "日志流读取中断：" + err.Error()}
	})
}

// demoSource synthesizes a plausible controller so the console can be felt
// (and its frame budget measured) without a running core.
type demoSource struct {
	mu    sync.Mutex
	modes string
	conns []Conn
	rng   *rand.Rand
}

func newDemoSource() *demoSource {
	d := &demoSource{modes: "rule", rng: rand.New(rand.NewSource(42))}
	d.conns = make([]Conn, 28)
	for i := range d.conns {
		d.conns[i] = d.synthConn(i)
	}
	return d
}

func (d *demoSource) Proxies() (ProxiesDoc, error) {
	groups := []Proxy{}
	names := []string{}
	for _, spec := range []struct {
		name string
		kind string
		n    int
	}{
		{"PROXY", "Selector", 48},
		{"Auto", "URLTest", 48},
		{"Fallback", "Fallback", 6},
		{"Streaming", "Selector", 12},
	} {
		members := make([]string, 0, spec.n)
		prefix := []string{"香港", "东京", "新加坡", "首尔", "法兰克福", "洛杉矶", "圣何塞"}[len(names)%7]
		for i := 0; i < spec.n; i++ {
			members = append(members, fmt.Sprintf("%s-%02d", prefix, i+1))
		}
		now := ""
		if spec.kind == "Selector" {
			now = members[len(names)%spec.n]
		} else if len(members) > 0 {
			now = members[0]
		}
		names = append(names, spec.name)
		groups = append(groups, Proxy{Type: spec.kind, Now: now, All: members})
	}
	for _, spec := range []struct{ name, kind string }{
		{"DIRECT", "Direct"}, {"REJECT", "Reject"},
	} {
		names = append(names, spec.name)
		groups = append(groups, Proxy{Type: spec.kind})
	}
	proxies := map[string]Proxy{}
	for i, name := range names {
		proxies[name] = groups[i]
	}
	return ProxiesDoc{Proxies: proxies}, nil
}

func (d *demoSource) synthConn(i int) Conn {
	chains := [][]string{
		{"PROXY", "香港-01"}, {"Auto", "东京-07"}, {"PROXY", "新加坡-03"},
		{"Streaming", "首尔-02"}, {"DIRECT"},
	}
	chain := chains[i%len(chains)]
	hosts := []string{
		"api.openai.com", "claude.ai", "github.com", "pypi.org", "cdn.jsdelivr.net",
		"registry.npmjs.org", "huggingface.co", "storage.googleapis.com",
	}
	down := int64(i * 262144)
	if i%5 == 0 {
		down *= 4
	}
	return Conn{
		ID:       fmt.Sprintf("demo-%04d", i),
		Start:    time.Now().Add(-time.Duration(i) * time.Minute),
		Upload:   int64(i * 65536),
		Download: down,
		Chains:   chain,
		Rule:     []string{"OpenAI", "Claude", "GeoSite:cn", "Match"}[i%4],
		Metadata: ConnMeta{
			Host: hosts[i%len(hosts)], Network: []string{"tcp", "udp"}[i%2],
			DstIP: "203.0.113." + strconv.Itoa(i%250+1), DstPort: "443",
		},
	}
}

func (d *demoSource) Connections() (ConnectionsDoc, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for i := range d.conns {
		d.conns[i].Download += int64(d.rng.Intn(300000))
		d.conns[i].Upload += int64(d.rng.Intn(60000))
	}
	return ConnectionsDoc{
		DownloadTotal: 3_400_000, UploadTotal: 1_100_000,
		Connections: append([]Conn(nil), d.conns...),
	}, nil
}

func (d *demoSource) Version() (VersionDoc, error) {
	return VersionDoc{Version: "v1.19.33 (demo)", Meta: true}, nil
}

func (d *demoSource) Configs() (ConfigsDoc, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return ConfigsDoc{Mode: d.modes}, nil
}

func (d *demoSource) Rules() (RulesDoc, error) {
	rules := []Rule{}
	kinds := []string{"DOMAIN-SUFFIX", "IP-CIDR", "GEOIP", "PROCESS-NAME", "MATCH"}
	for i := 0; i < 40; i++ {
		rules = append(rules, Rule{
			Type:    kinds[i%len(kinds)],
			Payload: fmt.Sprintf("example-%02d.com/%d", i%20, i),
			Proxy:   []string{"PROXY", "DIRECT", "REJECT"}[i%3],
		})
	}
	return RulesDoc{Rules: rules}, nil
}

func (d *demoSource) RuleProviders() (RuleProvidersDoc, error) {
	return RuleProvidersDoc{Providers: map[string]RuleProvider{
		"reject": {Name: "reject", Behavior: "domain", RuleCount: 80_000, VehicleType: "HTTP"},
		"proxy":  {Name: "proxy", Behavior: "domain", RuleCount: 21_000, VehicleType: "HTTP"},
		"direct": {Name: "direct", Behavior: "domain", RuleCount: 900, VehicleType: "File"},
	}}, nil
}

func (d *demoSource) Memory() (MemoryDoc, error) {
	return MemoryDoc{Inuse: 52_400_000}, nil
}

func (d *demoSource) Select(group, node string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return nil
}

func (d *demoSource) Delay(node string, timeoutMS int) (int, error) {
	return d.DelayFor("", node, timeoutMS)
}

func (d *demoSource) DelayFor(provider, node string, timeoutMS int) (int, error) {
	time.Sleep(time.Duration(150+rand.Intn(500)) * time.Millisecond)
	if rand.Intn(8) == 0 {
		return 0, errors.New("controller-request-failed-503")
	}
	return 20 + rand.Intn(380), nil
}

func (d *demoSource) SetMode(mode string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.modes = mode
	return nil
}

func (d *demoSource) ProxyProviders() (ProxyProvidersDoc, error) {
	// A few named nodes so the provider identity path is visible in demo mode.
	names := func(list ...string) []json.RawMessage {
		rows := make([]json.RawMessage, 0, 128)
		for _, name := range list {
			raw, _ := json.Marshal(map[string]string{"name": name})
			rows = append(rows, raw)
		}
		for len(rows) < 114 {
			raw, _ := json.Marshal(map[string]string{"name": fmt.Sprintf("节点-%03d", len(rows))})
			rows = append(rows, raw)
		}
		return rows
	}
	second := names("东京-07")
	for len(second) < 63 {
		raw, _ := json.Marshal(map[string]string{"name": fmt.Sprintf("备用-%03d", len(second))})
		second = append(second, raw)
	}
	return ProxyProvidersDoc{Providers: map[string]ProxyProvider{
		"subscribe-a": {Name: "subscribe-a", VehicleType: "HTTP", UpdatedAt: "2026-11-01T14:00:00Z", Proxies: names("香港-01", "东京-01")},
		"subscribe-b": {Name: "subscribe-b", VehicleType: "HTTP", UpdatedAt: "2026-10-31T09:12:00Z", Proxies: second},
	}}, nil
}

func (d *demoSource) RefreshProvider(name string) error {
	time.Sleep(400 * time.Millisecond)
	return nil
}

func (d *demoSource) DNS(name, record string) (DNSAnswer, error) {
	return DNSAnswer{Answer: []DNSRecord{
		{Type: "A", TTL: 300, Data: "203.0.113.20"},
		{Type: "A", TTL: 300, Data: "203.0.113.21"},
	}}, nil
}

func (d *demoSource) Download(rawURL string) ([]byte, error) {
	time.Sleep(300 * time.Millisecond)
	return []byte("proxies:\n  - name: 香港-01\n    type: ss\n"), nil
}

func (d *demoSource) StartTraffic(ctx context.Context) (<-chan Traffic, error) {
	out := make(chan Traffic, 4)
	go func() {
		defer close(out)
		up, down := int64(180_000), int64(1_900_000)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				up += int64(rand.Intn(60_000)) - 30_000
				down += int64(rand.Intn(600_000)) - 300_000
				if up < 0 {
					up = 10_000
				}
				if down < 0 {
					down = 100_000
				}
				select {
				case out <- Traffic{Up: up, Down: down}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return out, nil
}

func (d *demoSource) StartLogs(ctx context.Context) (<-chan LogLine, error) {
	return d.StartLogsAt(ctx, "info")
}

// StartLogsAt opens the demo log stream at the requested level, so the
// level switch is observable without a live core.
func (d *demoSource) StartLogsAt(ctx context.Context, level string) (<-chan LogLine, error) {
	out := make(chan LogLine, 32)
	messages := []string{
		"match DomainSuffix(openai.com) using PROXY",
		"match GeoSite(cn) using DIRECT",
		"[TCP] 127.0.0.1:44812 --> api.openai.com:443 match OpenAI using PROXY",
		"[UDP] 127.0.0.1:53124 --> 8.8.8.8:53 match dns using DIRECT",
		"health check url failed: 香港-03 timeout",
		"initial configuration in progress",
	}
	levels := []string{"info", "warning", "error"}
	minimum := logLevelRank(level)
	go func() {
		defer close(out)
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Duration(200+rand.Intn(300)) * time.Millisecond):
				line := LogLine{Type: levels[rand.Intn(10)/4], Payload: messages[rand.Intn(len(messages))]}
				if logLevelRank(line.Type) < minimum {
					continue
				}
				select {
				case out <- line:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return out, nil
}

// logLevelRank orders the log levels the core accepts.
func logLevelRank(level string) int {
	switch level {
	case "debug":
		return 0
	case "info":
		return 1
	case "warning":
		return 2
	case "error":
		return 3
	}
	return 1
}
