package runtimecore

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

func tempPrivate(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "linux" {
		return t.TempDir()
	}
	home, e := os.UserHomeDir()
	if e != nil {
		t.Fatal(e)
	}
	dir, e := os.MkdirTemp(home, ".mihomoctl-go-test-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}
func testApp(t *testing.T) platform.App {
	t.Helper()
	root := tempPrivate(t)
	return platform.App{Scope: platform.Scope{Name: "user", ConfigRoot: filepath.Join(root, "config", "mihomoctl-go"), DataRoot: filepath.Join(root, "data", "mihomoctl-go"), StateRoot: filepath.Join(root, "state", "mihomoctl-go"), CacheRoot: filepath.Join(root, "cache", "mihomoctl-go"), RuntimeRoot: filepath.Join(root, "run", "mihomoctl-go")}}
}
func fixture(t *testing.T) (platform.App, manager) {
	t.Helper()
	a := testApp(t)
	p := defaults(profile{HTTP: "proxy", SOCKS: "proxy", Credentials: filepath.Join(a.Scope.ConfigRoot, "credentials", "default.yaml")})
	m := manager{Version: 1, Core: coreSettings{Binary: filepath.Join(a.Scope.DataRoot, "mihomo"), Config: filepath.Join(a.Scope.ConfigRoot, "mihomo", "config.yaml"), Backend: "process"}, Default: "default", Profiles: map[string]profile{"default": p}, Tun: tunSettings{Device: "mihomo0"}}
	c := credentials{"unit-user", "unit-secret"}
	cfg := map[string]any{"mode": "rule", "listeners": []any{map[string]any{"name": "proxy", "type": "mixed", "listen": "127.0.0.1", "port": 18789, "users": []any{map[string]any{"username": c.Username, "password": c.Password}}}}, "external-controller": "127.0.0.1:19090", "secret": strings.Repeat("a", 64), "rules": []any{"MATCH,DIRECT"}}
	for path, v := range map[string]any{a.Scope.ManagerPath(): m, m.Core.Config: cfg, p.Credentials: c} {
		if e := platform.WriteYAML(path, v); e != nil {
			t.Fatal(e)
		}
	}
	return a, m
}
func requireCode(t *testing.T, err error, want string) {
	t.Helper()
	var p *platform.Error
	if !errors.As(err, &p) || p.Code != want {
		t.Fatalf("want %s, got %v", want, err)
	}
}
func TestHandlesGrammar(t *testing.T) {
	for _, s := range []string{"init", "start", "stop", "restart", "status", "logs", "config validate", "config check", "profile list", "profile show", "profile validate", "profile set-default", "profiles", "env show", "env export", "exec", "direct", "integration list", "integration show", "integration check", "integration export", "integration install", "integration remove", "service install", "service start", "service stop", "service restart", "service status", "service uninstall", "tun status", "tun enable", "tun disable", "health check", "health", "doctor", "reset", "migrate", "rollback", "core adopt", "core list"} {
		if !Handles(strings.Fields(s)) {
			t.Error(s)
		}
	}
	for _, s := range []string{"diagnose", "ready", "paseo", "core install", "core update", "release check", "update", "status extra", "profile", "tun", "config", "core list extra"} {
		if Handles(strings.Fields(s)) {
			t.Error("accepted", s)
		}
	}
	if Handles(nil) {
		t.Error("accepted empty command")
	}
}
func TestManagerStrictSchemaAndScope(t *testing.T) {
	a, m := fixture(t)
	if e := validateManager(a, m); e != nil {
		t.Fatal(e)
	}
	original, e := platform.ReadPrivate(a.Scope.ManagerPath())
	if e != nil {
		t.Fatal(e)
	}
	for _, text := range []string{string(original) + "unknown: true\n", string(original) + "version: 1\n", "version: 1\ncore: &x {}\nprofiles: *x\n", string(original) + "---\nextra: true\n"} {
		if e := platform.AtomicWrite(a.Scope.ManagerPath(), []byte(text), 0600); e != nil {
			t.Fatal(e)
		}
		if _, e := loadManager(a); e == nil {
			t.Fatal("accepted unsafe manager")
		}
	}
	m.Profiles["default"] = profile{HTTP: "proxy", Credentials: filepath.Join(filepath.Dir(a.Scope.ConfigRoot), "outside.yaml")}
	if e := validateManager(a, m); e == nil {
		t.Fatal("accepted outside credentials")
	}
	m.Profiles["default"] = defaults(profile{HTTP: "proxy"})
	m.Core.Config = filepath.Join(filepath.Dir(a.Scope.ConfigRoot), "outside.yaml")
	if e := validateManager(a, m); e == nil {
		t.Fatal("accepted outside core config")
	}
}
func TestEndpointSecurityAndProtocols(t *testing.T) {
	base := func() map[string]any {
		return map[string]any{"listeners": []any{map[string]any{"name": "proxy", "type": "mixed", "listen": "127.0.0.1", "port": 12345, "users": []any{map[string]any{"username": "u", "password": "p"}}}}}
	}
	mutations := map[string]func(map[string]any){"wildcard": func(c map[string]any) { c["listeners"].([]any)[0].(map[string]any)["listen"] = "0.0.0.0" }, "public": func(c map[string]any) { c["listeners"].([]any)[0].(map[string]any)["listen"] = "192.0.2.1" }, "no-auth": func(c map[string]any) { delete(c["listeners"].([]any)[0].(map[string]any), "users") }, "auth-bypass": func(c map[string]any) { c["skip-auth-prefixes"] = []any{"127.0.0.1/32"} }, "dns": func(c map[string]any) { c["dns"] = map[string]any{"listen": "127.0.0.1:1053"} }, "tun": func(c map[string]any) { c["tun"] = map[string]any{"enable": true} }, "tls": func(c map[string]any) { c["external-controller-tls"] = "127.0.0.1:9090" }, "legacy-anon": func(c map[string]any) { c["port"] = 12346 }, "short-secret": func(c map[string]any) { c["external-controller"] = "127.0.0.1:19090"; c["secret"] = "short" }, "float-port": func(c map[string]any) { c["listeners"].([]any)[0].(map[string]any)["port"] = 12345.5 }, "duplicate-bind": func(c map[string]any) { c["port"] = 12345; c["authentication"] = []any{"u:p"} }, "transparent": func(c map[string]any) { c["redir-port"] = 12346 }, "bad-users": func(c map[string]any) {
		c["listeners"].([]any)[0].(map[string]any)["users"] = []any{map[string]any{"username": "u", "password": "p", "extra": true}}
	}}
	for n, mutate := range mutations {
		t.Run(n, func(t *testing.T) {
			c := base()
			mutate(c)
			if _, _, e := parseEndpoints(c, false, nil); e == nil {
				t.Fatal("unsafe endpoints accepted")
			}
		})
	}
	c := base()
	c["port"] = 0
	eps, _, e := parseEndpoints(c, false, nil)
	if e != nil || len(eps) != 1 || !eps[0].http() || !eps[0].socks() {
		t.Fatal(e, eps)
	}
	c["listeners"].([]any)[0].(map[string]any)["listen"] = "192.0.2.1"
	if _, _, e = parseEndpoints(c, true, []string{"192.0.2.1"}); e != nil {
		t.Fatal(e)
	}
}
func TestProfileCredentialsMismatchFailsClosed(t *testing.T) {
	a, m := fixture(t)
	if e := platform.WriteYAML(m.Profiles["default"].Credentials, credentials{"different", "bad"}); e != nil {
		t.Fatal(e)
	}
	_, e := resolve(a, "")
	requireCode(t, e, "credentials-mismatch")
}
func TestEnvironmentEncodingAndRedaction(t *testing.T) {
	x := resolved{Name: "default", Profile: defaults(profile{HTTP: "m", SOCKS: "m"}), Credentials: credentials{"u@ser", "p:/%?#'"}, Endpoints: []endpoint{{Name: "m", Type: "mixed", Address: "::1", Port: 12345}}}
	v, e := environment(x, "")
	if e != nil {
		t.Fatal(e)
	}
	if len(v) != 8 || !strings.Contains(v["HTTP_PROXY"], "u%40ser:p%3A%2F%25%3F%23%27@[::1]:12345") {
		t.Fatal(v)
	}
	b, _ := json.Marshal(redactedEnvironment(x, v))
	if strings.Contains(string(b), "u%40ser") || strings.Contains(string(b), "p%3A") {
		t.Fatal("credential leak", string(b))
	}
	x.Profile.SOCKS = ""
	if _, e = environment(x, ""); e == nil {
		t.Fatal("missing protocol guessed")
	}
}
func TestRunProfileAndRedactedEnv(t *testing.T) {
	a, _ := fixture(t)
	for _, cmd := range [][]string{{"profile", "list"}, {"profiles"}, {"profile", "show"}, {"profile", "validate"}, {"env", "show"}, {"tun", "status"}, {"integration", "list"}} {
		r := platform.Request{Command: cmd, Args: []string{"default"}}
		doc, e := Run(context.Background(), a, r)
		if e != nil || doc.Overall != "PASS" {
			t.Fatalf("%v: %v %+v", cmd, e, doc)
		}
		b, _ := json.Marshal(doc)
		if strings.Contains(string(b), "unit-secret") {
			t.Fatal("secret leak")
		}
	}
	_, e := Run(context.Background(), a, platform.Request{Command: []string{"rollback"}})
	requireCode(t, e, "historical-rollback-disabled")
	_, e = Run(context.Background(), a, platform.Request{Command: []string{"diagnose"}})
	requireCode(t, e, "unknown-command")
}
func TestTransactionRollbackAndCrashRecovery(t *testing.T) {
	a, _ := fixture(t)
	p := filepath.Join(a.Scope.ConfigRoot, "one")
	if e := platform.AtomicWrite(p, []byte("before"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := applyFiles(a, map[string][]byte{p: []byte("after")}); e != nil {
		t.Fatal(e)
	}
	if b, _ := platform.ReadPrivate(p); string(b) != "after" {
		t.Fatal(string(b))
	}
	j := journal{1, []fileSnapshot{{Path: p, Before: []byte("before"), Existed: true, After: []byte("after")}, {Path: filepath.Join(a.Scope.ConfigRoot, "new"), After: []byte("new")}}}
	if e := platform.WriteJSON(journalPath(a), j); e != nil {
		t.Fatal(e)
	}
	if e := recoverTransaction(a); e != nil {
		t.Fatal(e)
	}
	if b, _ := platform.ReadPrivate(p); string(b) != "before" {
		t.Fatal(string(b))
	}
	j.Files[0].Path = filepath.Join(filepath.Dir(a.Scope.ConfigRoot), "outside")
	if e := platform.WriteJSON(journalPath(a), j); e != nil {
		t.Fatal(e)
	}
	requireCode(t, recoverTransaction(a), "transaction-invalid")
}
func TestTransactionConflictPreservesNewState(t *testing.T) {
	a, _ := fixture(t)
	p := filepath.Join(a.Scope.ConfigRoot, "one")
	if e := platform.AtomicWrite(p, []byte("foreign"), 0600); e != nil {
		t.Fatal(e)
	}
	j := journal{1, []fileSnapshot{{Path: p, Before: []byte("old"), After: []byte("new"), Existed: true}}}
	if e := platform.WriteJSON(journalPath(a), j); e != nil {
		t.Fatal(e)
	}
	requireCode(t, recoverTransaction(a), "transaction-conflict")
	b, _ := platform.ReadPrivate(p)
	if string(b) != "foreign" {
		t.Fatal("overwrote conflict")
	}
}
func TestSymlinkRefusal(t *testing.T) {
	a, m := fixture(t)
	real := filepath.Join(a.Scope.ConfigRoot, "real")
	if e := os.Rename(m.Core.Config, real); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(real, m.Core.Config); e != nil {
		t.Skip("symlink unavailable:", e)
	}
	_, e := resolve(a, "")
	requireCode(t, e, "symlink-refused")
}
func TestConfigWithoutCoreIsUnverified(t *testing.T) {
	a := testApp(t)
	p := filepath.Join(a.Scope.ConfigRoot, "candidate.yaml")
	if e := platform.WriteYAML(p, map[string]any{"mode": "rule", "rules": []string{"MATCH,DIRECT"}}); e != nil {
		t.Fatal(e)
	}
	doc, e := Run(context.Background(), a, platform.Request{Command: []string{"config", "validate"}, Options: map[string][]string{"file": {p}}})
	if e != nil || doc.Overall != "UNVERIFIED" {
		t.Fatal(doc, e)
	}
}
func TestExportsAreArtifactsOnly(t *testing.T) {
	a, _ := fixture(t)
	vars := map[string]string{}
	for _, k := range proxyKeys {
		vars[k] = "http://u:p%40ss@127.0.0.1:1234"
	}
	for _, adapter := range []string{"exec", "systemd", "docker", "kubernetes", "supervisor", "pm2", "ci"} {
		files, e := renderExport(a, "test", binding{Adapter: adapter, Target: "test.service", ConnectHost: "192.0.2.3"}, vars)
		if e != nil || len(files) == 0 {
			t.Fatal(adapter, e)
		}
		for n := range files {
			if filepath.Base(n) != n {
				t.Fatal("unsafe export path")
			}
		}
	}
	if _, e := renderExport(a, "x", binding{Adapter: "unknown"}, vars); e == nil {
		t.Fatal("unknown adapter accepted")
	}
	text, e := unitText(a, manager{Core: coreSettings{Binary: "/trusted/mihomo", Config: "/private/core.yaml"}})
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(text, unitMarker) || strings.Contains(text, "unit-secret") {
		t.Fatal(text)
	}
}
func TestCleanChildEnvironment(t *testing.T) {
	t.Setenv("HTTP_PROXY", "old")
	t.Setenv("http_proxy", "old")
	t.Setenv("RUNTIMECORE_KEEP", "yes")
	t.Setenv("CLASH_OVERRIDE_SECRET", "injection")
	env := strings.Join(cleanEnvironment(false, nil), "\n")
	if strings.Contains(env, "HTTP_PROXY=") || strings.Contains(env, "http_proxy=") || !strings.Contains(env, "RUNTIMECORE_KEEP=yes") || !strings.Contains(env, "CLASH_OVERRIDE_SECRET=injection") {
		t.Fatal(env)
	}
	env = strings.Join(cleanEnvironment(true, nil), "\n")
	if strings.Contains(env, "CLASH_OVERRIDE_SECRET=") {
		t.Fatal("core override inherited")
	}
}

func TestCoreListBeforeInitialization(t *testing.T) {
	a := testApp(t)
	doc, e := Run(context.Background(), a, platform.Request{Command: []string{"core", "list"}})
	if e != nil || doc.Overall != "PASS" {
		t.Fatal(doc, e)
	}
	if len(doc.Data["installs"].([]map[string]any)) != 0 {
		t.Fatal(doc)
	}
}
func TestSystemdOwnershipAndEnvironmentEncoding(t *testing.T) {
	a, m := fixture(t)
	m.Core.Backend = "systemd"
	path := unitPath(a)
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		t.Fatal(e)
	}
	unit, e := unitText(a, m)
	if e != nil {
		t.Fatal(e)
	}
	if e := platform.AtomicWrite(path, []byte(unit), 0600); e != nil {
		t.Fatal(e)
	}
	props := map[string]string{"FragmentPath": path, "User": "", "ExecStart": "{ path=" + m.Core.Binary + " ; argv[]=" + strings.Join([]string{m.Core.Binary, "-d", serviceHome(a), "-f", serviceConfig(a, m)}, " ") + " ; ignore_errors=no ; }"}
	if e := requireLoadedUnit(a, m, props); e != nil {
		t.Fatal(e)
	}
	props["DropInPaths"] = "/foreign/override.conf"
	requireCode(t, requireLoadedUnit(a, m, props), "systemd-dropin-unowned")
	props["DropInPaths"] = ""
	props["ExecStartPost"] = "/foreign/hook"
	requireCode(t, requireLoadedUnit(a, m, props), "systemd-definition-unverified")
	vars := map[string]string{"HTTP_PROXY": "http://u:p%40ss@127.0.0.1:1234"}
	files := integrationArtifacts(a, "test", binding{Target: "test.service"}, vars)
	env, _ := integrationPaths(a, "test", binding{Target: "test.service"})
	if !strings.Contains(string(files[env]), "p%40ss") || strings.Contains(string(files[env]), "p%%40ss") {
		t.Fatal("changed URL encoding")
	}
	a.Scope.System = true
	unit, e = unitText(a, m)
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(unit, "User=mihomoctl-go") || !strings.Contains(unit, "BindPaths=") || !strings.Contains(unit, "BindReadOnlyPaths=") || !strings.Contains(unit, "RuntimeDirectoryMode=0700") {
		t.Fatal(unit)
	}
	m.Core.Binary = filepath.Join(a.Scope.DataRoot, "cores", "v1.19.33", "mihomo")
	unit, e = unitText(a, m)
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(unit, "TemporaryFileSystem=") || !strings.Contains(unit, "service-binary") {
		t.Fatal("private delivery core missing read-only namespace exposure")
	}
}

func TestIntegrationOwnershipRequiresReceiptAndUnchangedBytes(t *testing.T) {
	a, _ := fixture(t)
	b := binding{Profile: "default", Adapter: "systemd", Target: "consumer.service"}
	vars := map[string]string{"HTTP_PROXY": "http://u:p%40ss@127.0.0.1:1234"}
	files := integrationArtifacts(a, "consumer", b, vars)
	for p, v := range files {
		if e := platform.AtomicWrite(p, v, 0600); e != nil {
			t.Fatal(e)
		}
	}
	_, e := ownedIntegration(a, "consumer", b)
	requireCode(t, e, "integration-file-not-managed")
	hashes := map[string]string{}
	for p, v := range files {
		hashes[p] = platform.Hash(v)
	}
	if e := platform.WriteJSON(integrationReceiptPath(a, "consumer"), integrationReceipt{1, "consumer", b.Target, hashes}); e != nil {
		t.Fatal(e)
	}
	if owned, e := ownedIntegration(a, "consumer", b); e != nil || !owned {
		t.Fatal(owned, e)
	}
	_, drop := integrationPaths(a, "consumer", b)
	if e := platform.AtomicWrite(drop, append(files[drop], []byte("ExecStartPost=/foreign\n")...), 0600); e != nil {
		t.Fatal(e)
	}
	_, e = ownedIntegration(a, "consumer", b)
	requireCode(t, e, "integration-artifact-drifted")
	if strings.Contains(string(files[drop]), "EnvironmentFile=\"") {
		t.Fatal("EnvironmentFile quoted as argv")
	}
	b.Target = "changed.service"
	_, e = ownedIntegration(a, "consumer", b)
	requireCode(t, e, "integration-target-drifted")
}
func TestReadersRefusePendingTransaction(t *testing.T) {
	a, _ := fixture(t)
	if e := platform.WriteJSON(journalPath(a), journal{Version: 1}); e != nil {
		t.Fatal(e)
	}
	_, e := Run(context.Background(), a, platform.Request{Command: []string{"env", "show"}})
	requireCode(t, e, "transaction-recovery-required")
}
func TestInvalidScalarTypesRejected(t *testing.T) {
	a, m := fixture(t)
	raw, e := platform.ReadPrivate(a.Scope.ManagerPath())
	if e != nil {
		t.Fatal(e)
	}
	for _, text := range []string{strings.Replace(string(raw), "timeout: 10", "timeout: 0", 1), strings.Replace(string(raw), "http_listener: proxy", "http_listener: 1234", 1)} {
		if e := platform.AtomicWrite(a.Scope.ManagerPath(), []byte(text), 0600); e != nil {
			t.Fatal(e)
		}
		if _, e := loadManager(a); e == nil {
			t.Fatal("coerced manager scalar")
		}
	}
	path := m.Profiles["default"].Credentials
	if e := platform.AtomicWrite(path, []byte("username: user\npassword: 1234\n"), 0600); e != nil {
		t.Fatal(e)
	}
	_, e = loadCredentials(m.Profiles["default"])
	requireCode(t, e, "credentials-invalid")
}
