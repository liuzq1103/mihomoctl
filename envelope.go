package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/liuzq1103/mihomoctl/internal/command"
	"github.com/liuzq1103/mihomoctl/internal/platform"
	"github.com/liuzq1103/mihomoctl/internal/routing"
	"github.com/liuzq1103/mihomoctl/internal/runtimecore"
	"io"
	"strings"
	"time"
)

// Envelope is the mihomoctl/v1 JSON contract every CLI verb emits; the TUI
// renders these documents verbatim instead of re-deciding anything.
type Envelope struct {
	Schema  string         `json:"schema"`
	Command string         `json:"command"`
	Scope   string         `json:"scope"`
	Overall string         `json:"overall"`
	Data    map[string]any `json:"data"`
	Checks  []Check        `json:"checks"`
	Errors  []ErrDoc       `json:"errors"`
}

type Check struct {
	Name     string `json:"name"`
	Status   string `json:"status"`
	Evidence string `json:"evidence"`
	Detail   string `json:"detail"`
}

type ErrDoc struct {
	Code        string `json:"code"`
	Detail      string `json:"detail"`
	Remediation string `json:"remediation"`
}

// CliSource invokes the shared Go application service for transactional operations.
type CliSource interface {
	Run(args ...string) (Envelope, error)
	// RunWithStdin pipes private content (subscription payloads) instead of
	// writing it to disk or passing it in argv.
	RunWithStdin(input []byte, args ...string) (Envelope, error)
}

type realCli struct{ system bool }

// newRealCli now returns an in-process Go service. The legacy binary argument
// is accepted for source compatibility but never executes another program.
func newRealCli(binary string) CliSource { return &realCli{} }

// limitWriter bounds how much a child process can buffer into memory: past
// max it errors (which kills the child), instead of growing the buffer for
// the whole run and checking the size only after exit. Soft mode keeps
// draining the child but discards the bytes — for streams that are pure
// diagnostics (stderr), where killing a succeeding run would be worse.
type limitWriter struct {
	buf       *bytes.Buffer
	max       int
	truncated bool
	soft      bool
}

func (w *limitWriter) Write(p []byte) (int, error) {
	if w.buf.Len()+len(p) > w.max {
		w.truncated = true
		if w.soft {
			// Keep whatever still fits, absorb and discard the rest.
			if room := w.max - w.buf.Len(); room > 0 {
				w.buf.Write(p[:room])
			}
			return len(p), nil
		}
		return 0, errors.New("mihomoctl-output-too-large")
	}
	return w.buf.Write(p)
}

func (c *realCli) run(stdin []byte, args ...string) (Envelope, error) {
	p, err := command.Parse(args, bytes.NewReader(stdin), io.Discard, io.Discard)
	if err != nil {
		return bridgeEnvelope(platform.Failure("mihomoctl", scopeName(c.system), err))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	return bridgeEnvelope(command.Execute(ctx, c.system, p.Request))
}
func scopeName(system bool) string {
	if system {
		return "system"
	}
	return "user"
}
func bridgeEnvelope(env platform.Envelope) (Envelope, error) {
	if legacy, ok := env.Data["legacy"].(map[string]any); ok {
		env.Data = legacy
		delete(env.Data, "schema")
		delete(env.Data, "command")
		delete(env.Data, "overall")
	}
	raw, err := json.Marshal(env)
	if err != nil {
		return Envelope{}, err
	}
	var result Envelope
	err = json.Unmarshal(raw, &result)
	return result, err
}
func (c *realCli) Run(args ...string) (Envelope, error) { return c.run(nil, args...) }
func (c *realCli) RunWithStdin(input []byte, args ...string) (Envelope, error) {
	return c.run(input, args...)
}

func (c *realCli) SubscriptionInput(value, kind, policy string) (Envelope, error) {
	s, err := platform.NewScope(c.system)
	if err != nil {
		return Envelope{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	env, err := routing.SubscriptionInput(ctx, platform.App{Scope: s}, value, kind, policy)
	if err != nil {
		return bridgeEnvelope(platform.Failure("subscription", s.Name, err))
	}
	return bridgeEnvelope(env)
}
func (c *realCli) SubscriptionDiscard(id string) (Envelope, error) {
	s, err := platform.NewScope(c.system)
	if err != nil {
		return Envelope{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	env, err := routing.SubscriptionDiscard(ctx, platform.App{Scope: s}, id)
	if err != nil {
		return bridgeEnvelope(platform.Failure("subscription", s.Name, err))
	}
	return bridgeEnvelope(env)
}

func (c *realCli) RuntimeOwnerProof() (bool, string) {
	s, err := platform.NewScope(c.system)
	if err != nil {
		return false, platform.SafeError(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = routing.VerifyController(ctx, platform.App{Scope: s})
	if err != nil {
		return false, routing.ErrorCode(err)
	}
	return true, ""
}

func (c *realCli) SubscriptionSaveAndStart(id, sha string) (Envelope, error) {
	s, e := platform.NewScope(c.system)
	if e != nil {
		return Envelope{}, e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	env, e := routing.SubscriptionSaveAndStart(ctx, platform.App{Scope: s}, id, sha)
	if e != nil {
		return bridgeEnvelope(platform.Failure("subscription", s.Name, e))
	}
	return bridgeEnvelope(env)
}
func (c *realCli) Journal(since, until string, lines int) (Envelope, error) {
	s, e := platform.NewScope(c.system)
	if e != nil {
		return Envelope{}, e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	env, e := runtimecore.Journal(ctx, platform.App{Scope: s}, since, until, lines)
	if e != nil {
		return bridgeEnvelope(platform.Failure("journal", s.Name, e))
	}
	return bridgeEnvelope(env)
}

// demoCli answers with canned envelopes so the whole UI (including the
// subscription flow) can be exercised without Python or a live core.
type demoCli struct{}

func (c *demoCli) RunWithStdin(input []byte, args ...string) (Envelope, error) {
	return c.Run(args...)
}

func (c *demoCli) Run(args ...string) (Envelope, error) {
	joined := strings.Join(args, " ")
	base := Envelope{Schema: "mihomoctl/v1", Scope: "user", Overall: "PASS", Data: map[string]any{}}
	switch {
	case strings.HasPrefix(joined, "subscription preview"):
		base.Command = "subscription-preview"
		base.Data = map[string]any{
			"state": "preview", "id": strings.Repeat("a", 32), "sha256": strings.Repeat("b", 64),
			"policy": "provider", "requested_policy": "auto", "nodes": 114, "added": 114,
			"replaced": 0, "removed": 0, "groups": 8, "removed_groups": 2, "rules": 61,
			"removed_rules": 0, "ignored_fields": []any{"tun", "dns"},
		}
	case strings.HasPrefix(joined, "subscription apply"):
		base.Command = "subscription-apply"
		base.Data = map[string]any{"state": "ready", "action": "start", "id": strings.Repeat("a", 32)}
	case strings.HasPrefix(joined, "controller initialize"):
		base.Command = "controller-initialize"
		base.Data = map[string]any{"state": "restart-required", "port": 9090}
	case strings.HasPrefix(joined, "status"):
		base.Command = "status"
		base.Data = map[string]any{
			"scope": "user", "backend": "process", "proxy_mode": "rule",
			"active_config": "/home/demo/.local/share/mihomoctl/mihomo/config.yaml",
			"listeners":     []any{map[string]any{"name": "mixed", "type": "mixed", "address": "127.0.0.1", "port": 7890, "authenticated": false}},
			"controller":    map[string]any{"address": "127.0.0.1", "port": 9090, "authenticated": true},
			"runtime":       map[string]any{"running": true, "detail": "pid 4242"},
			"core":          map[string]any{"binary": "/home/demo/.local/bin/mihomo", "config": "config.yaml"},
			"tun":           map[string]any{"enabled": false},
			"errors":        []any{},
		}
	case joined == "health check" || strings.HasPrefix(joined, "health check --egress-url"):
		base.Command = "health"
		base.Checks = []Check{
			{Name: "manager-config", Status: "PASS", Evidence: "confirmed"},
			{Name: "runtime-running", Status: "PASS", Evidence: "confirmed", Detail: "pid 4242"},
			{Name: "listener-reachable", Status: "PASS", Evidence: "inferred", Detail: "127.0.0.1:7890"},
			{Name: "egress-through-remote-node", Status: "PASS", Evidence: "confirmed", Detail: "egress 203.0.113.7"},
			{Name: "model-end-to-end", Status: "UNVERIFIED", Evidence: "unavailable", Detail: "readiness is not model e2e"},
		}
	case joined == "doctor":
		base.Command = "doctor"
		base.Checks = []Check{
			{Name: "manager-config", Status: "PASS", Evidence: "confirmed"},
			{Name: "core-binary", Status: "PASS", Evidence: "confirmed", Detail: "/home/demo/.local/bin/mihomo"},
			{Name: "runtime", Status: "PASS", Evidence: "confirmed", Detail: "running=True"},
			{Name: "dependency-systemctl", Status: "SKIPPED", Evidence: "unavailable"},
			{Name: "dependency-go-binary", Status: "PASS", Evidence: "confirmed"},
		}
		base.Data = map[string]any{"scope": "user", "backend": "process"}
	case strings.HasPrefix(joined, "profiles") || strings.HasPrefix(joined, "profile list"):
		base.Command = "profiles"
		base.Data = map[string]any{"profiles": []any{
			map[string]any{"name": "default", "http": "127.0.0.1:7890", "socks": "127.0.0.1:7891", "selected": true},
			map[string]any{"name": "streaming", "http": "127.0.0.1:7892", "socks": "127.0.0.1:7893"},
		}}
	case strings.HasPrefix(joined, "integration list"):
		base.Command = "integration-list"
		base.Data = map[string]any{"bindings": []any{
			map[string]any{"name": "codex", "adapter": "systemd", "profile": "default", "target": "codex.service"},
		}}
	case strings.HasPrefix(joined, "env show"):
		base.Command = "env-show"
		base.Data = map[string]any{
			"HTTP_PROXY":  "http://REDACTED:REDACTED@127.0.0.1:7890",
			"HTTPS_PROXY": "http://REDACTED:REDACTED@127.0.0.1:7890",
			"ALL_PROXY":   "socks5://REDACTED:REDACTED@127.0.0.1:7891",
			"NO_PROXY":    "localhost,127.0.0.1",
		}
	case strings.HasPrefix(joined, "version"):
		base.Command = "version"
		base.Data = map[string]any{"mihomoctl": platform.Version, "schema": "mihomoctl/v1", "core": "v1.19.10"}
	case strings.HasPrefix(joined, "release check"):
		base.Command = "release-check"
		base.Data = map[string]any{"current": "1.4.2", "latest": "1.4.2", "up_to_date": true}
	case strings.HasPrefix(joined, "rules check"):
		base.Command = "rules-check"
		base.Checks = []Check{{Name: "rules-required-group", Status: "PASS", Evidence: "confirmed"},
			{Name: "rules-provider-order", Status: "PASS", Evidence: "confirmed"}}
		base.Data = map[string]any{"rules": 12, "providers": 3}
	case strings.HasPrefix(joined, "rules status"):
		base.Command = "rules-status"
		base.Data = map[string]any{"rules": 12, "providers": 3, "provider_capability": "supported"}
	case strings.HasPrefix(joined, "tun status"):
		base.Command = "tun-status"
		base.Data = map[string]any{"enabled": false, "scope": "user"}
	case strings.HasPrefix(joined, "core list"):
		base.Command = "core-list"
		base.Data = map[string]any{"installed": []any{"v1.19.10"}, "active": "v1.19.10"}
	case strings.HasPrefix(joined, "config validate"):
		base.Command = "config-validate"
		base.Checks = []Check{{Name: "config-parse", Status: "PASS", Evidence: "confirmed", Detail: "1 listening surfaces"},
			{Name: "core-validate", Status: "PASS", Evidence: "confirmed"}}
	case strings.HasPrefix(joined, "migrate --dry-run"):
		base.Command = "migrate-preview"
		base.Data = map[string]any{"legacy_found": false, "note": "nothing to migrate"}
	case strings.HasPrefix(joined, "reset --dry-run"):
		base.Command = "reset-preview"
		base.Data = map[string]any{"would_reset": []any{"config", "credentials"}, "would_keep": []any{"core", "cache"}}
	default:
		base.Command = joined
		base.Data = map[string]any{"note": "demo 模式：该命令的完整输出未内置"}
	}
	// Round-trip through JSON so demo values carry production types
	// (numbers as float64), exactly what the real CLI decoder produces.
	raw, err := json.Marshal(base)
	if err != nil {
		return Envelope{}, err
	}
	var env Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return Envelope{}, err
	}
	return env, nil
}
