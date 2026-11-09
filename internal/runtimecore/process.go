package runtimecore

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

type identity struct {
	PID   int      `json:"pid"`
	UID   int      `json:"uid"`
	Start string   `json:"start_time"`
	Boot  string   `json:"boot_id"`
	Exe   string   `json:"exe"`
	Args  []string `json:"argv"`
}
type runtimeState struct {
	Version   int      `json:"version"`
	Namespace string   `json:"namespace"`
	Scope     string   `json:"scope"`
	Config    string   `json:"config"`
	Home      string   `json:"home"`
	Identity  identity `json:"identity"`
}

func cleanEnvironment(core bool, vars map[string]string) []string {
	out := []string{}
	for _, v := range os.Environ() {
		key, _, _ := strings.Cut(v, "=")
		if member(key, proxyKeys...) {
			continue
		}
		if core && (strings.HasPrefix(key, "CLASH_") || strings.HasPrefix(key, "MIHOMO_") || strings.HasPrefix(key, "LD_") || key == "GODEBUG" || key == launchTokenKey) {
			continue
		}
		out = append(out, v)
	}
	for _, k := range sortedKeys(vars) {
		out = append(out, k+"="+vars[k])
	}
	return out
}
func validateCore(ctx context.Context, a platform.App, binary string, text []byte) error {
	if e := trustedExecutable(binary, a.Scope.System); e != nil {
		return e
	}
	cfg, e := platform.DecodeYAML(text)
	if e != nil {
		return platform.ConfigDiagnostic(e)
	}
	staging, e := os.MkdirTemp("", "mihomoctl-go-validate-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(staging)
	proofs, e := stageResources(ctx, a, cfg, staging)
	if e != nil {
		return e
	}
	text, e = marshalYAML(cfg)
	if e != nil {
		return e
	}
	candidate := filepath.Join(staging, "candidate.yaml")
	if e = platform.AtomicWrite(candidate, text, 0600); e != nil {
		return e
	}
	checkctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(checkctx, binary, "-t", "-d", staging, "-f", candidate)
	cmd.Env = cleanEnvironment(true, nil)
	if e = validationIdentity(ctx, cmd, a, staging); e != nil {
		return e
	}
	if e = cmd.Run(); e != nil {
		if checkctx.Err() != nil {
			return platform.Fail("core-timeout")
		}
		return platform.Fail("core-config-invalid")
	}
	return verifyResources(ctx, a, proofs)
}
func readState(a platform.App, m manager) (*runtimeState, error) {
	p := a.Scope.RuntimeState()
	if e := platform.CheckPath(p); e != nil {
		return nil, e
	}
	if _, e := os.Lstat(p); os.IsNotExist(e) {
		return nil, nil
	}
	b, e := platform.ReadPrivate(p)
	if e != nil {
		return nil, e
	}
	var s runtimeState
	if json.Unmarshal(b, &s) != nil || s.Version != 1 || s.Namespace != "mihomoctl-go" || s.Scope != a.Scope.Name || s.Config != m.Core.Config || s.Home != a.Scope.CoreHome() || s.Identity.PID < 2 || s.Identity.Start == "" || s.Identity.Boot == "" || s.Identity.Exe != m.Core.Binary {
		return nil, platform.Usage("runtime-state-invalid")
	}
	return &s, nil
}
func runningIdentity(ctx context.Context, a platform.App, m manager) (*identity, error) {
	if m.Core.Backend == "systemd" {
		return serviceIdentity(ctx, a, m)
	}
	s, e := readState(a, m)
	if e != nil || s == nil {
		return nil, e
	}
	if !identityAlive(s.Identity) {
		if processExists(s.Identity.PID) {
			return nil, platform.Usage("runtime-identity-mismatch")
		}
		return nil, nil
	}
	want := []string{m.Core.Binary, "-d", a.Scope.CoreHome(), "-f", m.Core.Config}
	if s.Identity.UID != os.Geteuid() || !equalStrings(s.Identity.Args, want) {
		return nil, platform.Usage("runtime-identity-mismatch")
	}
	return &s.Identity, nil
}
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func status(ctx context.Context, a platform.App, command string, stoppedOK bool) (platform.Envelope, error) {
	doc := platform.Document(command, a.Scope.Name, nil)
	x, e := resolve(a, "")
	if e != nil {
		doc.Overall = "UNVERIFIED"
		doc.Data = map[string]any{"scope": a.Scope.Name, "backend": nil, "core": map[string]any{"initialized": false}, "controller": nil, "listeners": []any{}, "active_config": nil, "proxy": nil, "mode": nil, "tun": nil, "errors": []string{renderError(e)}, "error": platform.SafeError(e), "overall": "UNVERIFIED", "evidence": "unavailable"}
		return doc, nil
	}
	id, e := runningIdentity(ctx, a, x.Manager)
	if e != nil {
		return doc, e
	}
	running := id != nil
	listening := running
	evidence := "unavailable"
	if running {
		evidence = "inferred"
	}
	rows := []map[string]any{}
	for _, ep := range x.Endpoints {
		owned := running && ownsListener(*id, ep)
		if !owned {
			listening = false
		}
		s := "not-listening"
		if owned {
			s = "listening"
		}
		rows = append(rows, map[string]any{"name": ep.Name, "source": ep.Source, "type": ep.Type, "address": ep.Address, "port": ep.Port, "authenticated": ep.Authenticated, "status": s, "evidence": evidence})
	}
	var controller any
	if x.Controller != nil {
		owned := running && ownsListener(*id, *x.Controller)
		if !owned {
			listening = false
		}
		state := "not-listening"
		if owned {
			state = "listening"
		}
		controller = map[string]any{"address": x.Controller.Address, "port": x.Controller.Port, "authenticated": true, "status": state, "evidence": evidence}
	}
	detail := runtimeStoppedDetail(a, x.Manager)
	runtime := map[string]any{"backend": x.Manager.Core.Backend, "running": running, "detail": detail}
	if running {
		detail = "running"
		delete(runtime, "detail")
		runtime["pid"] = id.PID
		runtime["listening"] = listening
		runtime["identity"] = map[string]any{"config": x.Manager.Core.Config, "exe": id.Exe, "pid": id.PID, "uid": id.UID, "start_time": id.Start}
	}
	doc.Data = map[string]any{"scope": a.Scope.Name, "backend": x.Manager.Core.Backend, "core": map[string]any{"binary": x.Manager.Core.Binary, "config": x.Manager.Core.Config, "backend": x.Manager.Core.Backend, "initialized": true, "status": detail}, "controller": controller, "listeners": rows, "active_config": x.Manager.Core.Config, "config": map[string]any{"path": x.Manager.Core.Config, "active": true}, "mode": x.Config["mode"], "routing_mode": x.Config["mode"], "tun": map[string]any{"enabled": x.Manager.Tun.Enabled, "device": tunDevice(x.Manager), "system_only": true}, "runtime": runtime, "evidence": "inferred", "errors": []string{}, "error": nil}
	if !running {
		doc.Data["error"] = detail
	}
	if platform.String(x.Config["mode"]) == "" {
		doc.Data["routing_mode"] = "unknown"
	}
	vars, e := environment(x, "")
	if e == nil {
		doc.Data["proxy"] = redactedEnvironment(x, vars)
	} else {
		doc.Data["errors"] = []string{renderError(e)}
		doc.Data["error"] = renderError(e)
		doc.Overall = "FAIL"
	}
	doc.Data["proxy_mode"] = "listener-environment"
	if x.Manager.Tun.Enabled {
		doc.Data["proxy_mode"] = "tun"
	}
	if (!running || !listening) && !stoppedOK {
		doc.Overall = "FAIL"
	}
	if stoppedOK && running {
		doc.Overall = "FAIL"
	}
	doc.Data["overall"] = doc.Overall
	return doc, nil
}

func runtimeStoppedDetail(a platform.App, m manager) string {
	if m.Core.Backend != "process" {
		return "stopped"
	}
	if _, err := os.Lstat(a.Scope.RuntimeState()); os.IsNotExist(err) {
		return "no-state"
	}
	return "crashed"
}
func lifecycle(ctx context.Context, a platform.App, action string) error {
	if e := preventLockInheritance(a); e != nil {
		return e
	}
	x, e := resolve(a, "")
	if e != nil {
		return e
	}
	if x.Manager.Core.Backend == "systemd" {
		return serviceLifecycle(ctx, a, x, action)
	}
	if action == "stop" {
		return stopProcess(ctx, a, x.Manager)
	}
	if action == "restart" {
		if e = stopProcess(ctx, a, x.Manager); e != nil {
			return e
		}
	}
	id, e := runningIdentity(ctx, a, x.Manager)
	if e != nil {
		return e
	}
	if id != nil {
		h, e := healthResolved(ctx, a, x, nil)
		if e != nil {
			return e
		}
		if h.Overall != "PASS" {
			return platform.Fail("health-blocked")
		}
		return nil
	}
	if e = trustedExecutable(x.Manager.Core.Binary, a.Scope.System); e != nil {
		return e
	}
	if e = validateCore(ctx, a, x.Manager.Core.Binary, x.Text); e != nil {
		return e
	}
	if e = platform.PrivateDir(a.Scope.CoreHome()); e != nil {
		return e
	}
	// Bind every configured surface before launch to detect foreign listeners.
	sockets := []netCloser{}
	for _, ep := range surfaces(x) {
		l, e := reservePort(ep)
		if e != nil {
			for _, s := range sockets {
				s.Close()
			}
			return retryManagedPorts(ctx, a, x)
		}
		sockets = append(sockets, l)
	}
	for _, s := range sockets {
		s.Close()
	}
	logpath := filepath.Join(a.Scope.StateRoot, "logs", "mihomo.log")
	if e = platform.CheckPath(logpath); e != nil {
		return e
	}
	if _, e = os.Lstat(logpath); e == nil {
		if _, e = platform.ReadPrivate(logpath); e != nil {
			return e
		}
	}
	if e = platform.PrivateDir(filepath.Dir(logpath)); e != nil {
		return e
	}
	log, e := os.OpenFile(logpath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer log.Close()
	cmd := exec.Command(x.Manager.Core.Binary, "-d", a.Scope.CoreHome(), "-f", x.Manager.Core.Config)
	cmd.Env = cleanEnvironment(true, nil)
	token, e := recordLaunch(a, x.Manager)
	if e != nil {
		return e
	}
	if token != "" {
		cmd.Env = append(cmd.Env, launchTokenKey+"="+token)
	}
	cmd.Stdin = nil
	cmd.Stdout = log
	cmd.Stderr = log
	detach(cmd)
	if e = cmd.Start(); e != nil {
		return platform.Fail("core-unavailable")
	}
	compoundCheckpoint("process-started-before-state")
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var current identity
	for tries := 0; tries < 50; tries++ {
		current, e = inspectIdentity(cmd.Process.Pid)
		if e == nil && current.Exe == x.Manager.Core.Binary && equalStrings(current.Args, append([]string{x.Manager.Core.Binary}, cmd.Args[1:]...)) {
			break
		}
		select {
		case <-ctx.Done():
			_ = cmd.Process.Kill()
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
	if e != nil || current.Exe != x.Manager.Core.Binary || !equalStrings(current.Args, cmd.Args) {
		_ = cmd.Process.Kill()
		return platform.Fail("runtime-identity-unavailable")
	}
	cleanup := func() {
		_ = signalOwned(current, false)
		select {
		case <-done:
		case <-time.After(time.Second):
			_ = signalOwned(current, true)
		}
	}
	state := runtimeState{1, "mihomoctl-go", a.Scope.Name, x.Manager.Core.Config, a.Scope.CoreHome(), current}
	if e = platform.WriteJSON(a.Scope.RuntimeState(), state); e != nil {
		cleanup()
		return e
	}
	startupTimeout := time.Duration(defaults(x.Profile).Health.Timeout) * time.Second
	deadline := time.NewTimer(startupTimeout)
	defer deadline.Stop()
	startctx, cancel := context.WithTimeout(ctx, startupTimeout)
	defer cancel()
	for {
		h, e := healthResolved(startctx, a, x, &current)
		if e == nil && h.Overall == "PASS" {
			return nil
		}
		select {
		case <-ctx.Done():
			cleanup()
			_ = os.Remove(a.Scope.RuntimeState())
			return ctx.Err()
		case <-done:
			_ = os.Remove(a.Scope.RuntimeState())
			return platform.Fail("core-start-failed")
		case <-deadline.C:
			cleanup()
			_ = os.Remove(a.Scope.RuntimeState())
			return platform.Fail("health-blocked")
		case <-time.After(100 * time.Millisecond):
		}
	}
}

type netCloser interface{ Close() error }

func stopProcess(ctx context.Context, a platform.App, m manager) error {
	id, e := runningIdentity(ctx, a, m)
	if e != nil {
		return e
	}
	if id == nil {
		if _, e = os.Lstat(a.Scope.RuntimeState()); e == nil {
			return os.Remove(a.Scope.RuntimeState())
		}
		return nil
	}
	if e = signalOwned(*id, false); e != nil {
		return e
	}
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	killed := false
	for identityAlive(*id) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			if killed {
				return platform.Fail("runtime-stop-timeout")
			}
			killed = true
			if e = signalOwned(*id, true); e != nil {
				return e
			}
			timer.Reset(time.Second)
		case <-tick.C:
		}
	}
	return os.Remove(a.Scope.RuntimeState())
}
func surfaces(x resolved) []endpoint {
	out := append([]endpoint{}, x.Endpoints...)
	if x.Controller != nil {
		out = append(out, *x.Controller)
	}
	return out
}
