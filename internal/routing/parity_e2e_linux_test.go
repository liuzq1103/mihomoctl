//go:build linux

package routing

import (
	"archive/zip"
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

// The tests in this file are end-to-end acceptance for the parity rows that
// helper-level coverage could not close: every command travels the public
// Run path — grammar gate, mutation gate, pre-snapshot recovery, resolution,
// dispatch — against a private managed scope whose validator is /usr/bin/true.
// A real core via MIHOMOCTL_GO_TEST_CORE stays optional; the acceptance here
// is about the routing layer's own contracts.

// stringList reads a payload list that may be []string in memory or []any
// after an envelope round-trip.
func stringList(t *testing.T, label string, v any) []string {
	t.Helper()
	switch list := v.(type) {
	case []string:
		return list
	case []any:
		out := make([]string, 0, len(list))
		for _, item := range list {
			s, ok := item.(string)
			if !ok {
				t.Fatalf("%s: non-string entry %v", label, v)
			}
			out = append(out, s)
		}
		return out
	default:
		t.Fatalf("%s: unsupported list %v (%T)", label, v, v)
		return nil
	}
}

// decodeConfigFile reads the live managed configuration as a document.
func decodeConfigFile(t *testing.T, path string) map[string]any {
	t.Helper()
	raw, err := platform.ReadPrivate(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	doc, err := platform.DecodeYAML(raw)
	if err != nil {
		t.Fatalf("decode config: %v", err)
	}
	return doc
}

// probeGroup returns the named proxy-group of a document.
func probeGroup(t *testing.T, doc map[string]any, name string) map[string]any {
	t.Helper()
	for _, g := range anyList(doc["proxy-groups"]) {
		if gm, ok := g.(map[string]any); ok && gm["name"] == name {
			return gm
		}
	}
	t.Fatalf("group %q missing: %v", name, doc["proxy-groups"])
	return nil
}

// configBytes returns the live configuration bytes for equality checks.
func configBytes(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := platform.ReadPrivate(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// buildDashboardArchive writes a small reviewed dashboard zip and returns its
// path and pinned digest.
func buildDashboardArchive(t *testing.T) (string, string) {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	entries := []struct{ name, body string }{
		{"ui/assets/app.js", "console.log('app')\n"},
		{"ui/index.html", "<html>reviewed dashboard</html>\n"},
	}
	for _, entry := range entries {
		f, err := w.Create(entry.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write([]byte(entry.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(privateTempDir(t), "dashboard.zip")
	if err := platform.AtomicWrite(archive, buf.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	return archive, hashSHA256(buf.Bytes())
}

// TestLinuxControllerSetupDigestBoundArchive is the full controller setup
// acceptance: a local dashboard archive installs only under its pinned
// sha256, the existing controller endpoint and secret survive untouched
// (auth safe), a failed digest installs nothing, and a second setup never
// silently replaces the installed dashboard.
func TestLinuxControllerSetupDigestBoundArchive(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("user-scope mutation gate refuses root")
	}
	a, configPath := subscriptionScope(t, linuxFreshConfig, "/usr/bin/true")
	archive, digest := buildDashboardArchive(t)
	original := configBytes(t, configPath)
	mihomoDir := filepath.Join(a.Scope.ConfigRoot, "mihomo")

	// A mismatched digest refuses before anything is installed or written.
	bad := RunRequest(t, a, []string{"controller", "setup"},
		map[string]string{"archive": archive, "sha256": strings.Repeat("a", 64)})
	if bad.Overall != "FAIL" || len(bad.Errors) != 1 || bad.Errors[0].Code != "dashboard-sha256-mismatch" {
		t.Fatalf("digest mismatch: overall=%s errors=%v", bad.Overall, bad.Errors)
	}
	if installed, _ := filepath.Glob(filepath.Join(mihomoDir, "dashboard-*")); len(installed) != 0 {
		t.Fatalf("failed setup left assets: %v", installed)
	}
	if now := configBytes(t, configPath); !bytes.Equal(now, original) {
		t.Fatalf("failed setup rewrote the configuration:\n%s", now)
	}

	// The digest-bound setup lands through the full Run path.
	envelope := RunRequest(t, a, []string{"controller", "setup"},
		map[string]string{"archive": archive, "sha256": digest})
	if envelope.Overall != "PASS" {
		t.Fatalf("setup: overall=%s errors=%v", envelope.Overall, envelope.Errors)
	}
	legacy := dataLegacy(t, envelope)
	mustEqual(t, "endpoint", legacy["endpoint"], "127.0.0.1:19090")
	mustEqual(t, "state", legacy["state"], "restart-required")
	mustEqual(t, "ui", legacy["ui"], "external")

	doc := decodeConfigFile(t, configPath)
	mustEqual(t, "external-controller", doc["external-controller"], "127.0.0.1:19090")
	mustEqual(t, "secret", doc["secret"], fixtureToken)
	ui, ok := doc["external-ui"].(string)
	if !ok || !strings.HasPrefix(ui, mihomoDir+string(os.PathSeparator)) {
		t.Fatalf("external-ui = %v", doc["external-ui"])
	}
	cors, ok := doc["external-controller-cors"].(map[string]any)
	if !ok || platform.Bool(cors["allow-private-network"]) || len(anyList(cors["allow-origins"])) != 0 {
		t.Fatalf("cors = %v", doc["external-controller-cors"])
	}
	index, err := platform.ReadPrivate(filepath.Join(ui, "index.html"))
	if err != nil || string(index) != "<html>reviewed dashboard</html>\n" {
		t.Fatalf("index.html = %q err = %v", index, err)
	}
	info, err := os.Lstat(filepath.Join(ui, "index.html"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("index.html mode = %v err = %v", info.Mode().Perm(), err)
	}
	if _, err := os.Lstat(filepath.Join(ui, "assets", "app.js")); err != nil {
		t.Fatalf("archive asset missing: %v", err)
	}
	afterSetup := configBytes(t, configPath)

	// Replacement requires an explicit archive; a bare setup refuses and
	// changes nothing.
	again := RunRequest(t, a, []string{"controller", "setup"}, nil)
	if again.Overall != "UNVERIFIED" || len(again.Errors) != 1 ||
		again.Errors[0].Code != "existing-dashboard-preserved-use-explicit-archive-to-replace" {
		t.Fatalf("bare re-setup: overall=%s errors=%v", again.Overall, again.Errors)
	}
	if now := configBytes(t, configPath); !bytes.Equal(now, afterSetup) {
		t.Fatal("refused re-setup modified the configuration")
	}
}

var linuxProbeConfig = "external-controller: 127.0.0.1:19090\nsecret: " + fixtureToken + "\n" +
	"proxies:\n  - name: inline\n    type: ss\n    server: 127.0.0.1\n    port: 8388\n    cipher: aes-128-gcm\n    password: pw\n" +
	"proxy-providers:\n  pv:\n    type: http\n    url: https://example.invalid/sub\n    path: providers/pv.yaml\n" +
	"    health-check:\n      enable: true\n      url: https://www.gstatic.com/generate_204\n      interval: 300\n" +
	"proxy-groups:\n" +
	"  - name: Auto\n    type: url-test\n    proxies:\n      - inline\n    url: https://www.gstatic.com/generate_204\n    interval: 300\n" +
	"  - name: Pick\n    type: select\n    use:\n      - pv\n    proxies:\n      - DIRECT\n" +
	"rules:\n  - MATCH,Auto\n"

// TestLinuxHealthCheckPreviewApplyAndIdempotence is the health-check
// acceptance from the baseline's read-only preset override preservation and
// idempotence contract: preview changes nothing on disk, apply preserves
// every unspecified field, re-applying the same settings is a no-op, a preset
// followed by a partial override keeps the preset's other fields, provider
// applies report the referencing groups, and the security envelope survives
// every write untouched.
func TestLinuxHealthCheckPreviewApplyAndIdempotence(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("user-scope mutation gate refuses root")
	}
	a, configPath := subscriptionScope(t, linuxProbeConfig, "/usr/bin/true")
	original := configBytes(t, configPath)

	// Preview: the plan is visible, the configuration is not.
	preview := RunRequest(t, a, []string{"health-check"}, map[string]string{"interval": "600"}, "group", "Auto")
	if preview.Overall != "PASS" {
		t.Fatalf("preview: overall=%s errors=%v", preview.Overall, preview.Errors)
	}
	legacy := dataLegacy(t, preview)
	mustEqual(t, "state", legacy["state"], "preview")
	before, ok := legacy["before"].(map[string]any)
	if !ok || before["interval"] != 300 {
		t.Fatalf("preview before = %v", legacy["before"])
	}
	after, ok := legacy["after"].(map[string]any)
	if !ok || after["interval"] != 600 {
		t.Fatalf("preview after = %v", legacy["after"])
	}
	if now := configBytes(t, configPath); !bytes.Equal(now, original) {
		t.Fatal("preview modified the configuration on disk")
	}

	// Apply: the group changes, everything unspecified is preserved.
	applied := RunRequest(t, a, []string{"health-check"},
		map[string]string{"interval": "600", "apply": "true"}, "group", "Auto")
	if applied.Overall != "PASS" {
		t.Fatalf("apply: overall=%s errors=%v", applied.Overall, applied.Errors)
	}
	mustEqual(t, "applied state", dataLegacy(t, applied)["state"], "restart-required")
	doc := decodeConfigFile(t, configPath)
	auto := probeGroup(t, doc, "Auto")
	mustEqual(t, "Auto.interval", auto["interval"], 600)
	mustEqual(t, "Auto.url", auto["url"], testURL) // gstatic == testURL, preserved
	if _, has := auto["timeout"]; has {
		t.Fatalf("Auto.timeout fabricated: %v", auto["timeout"])
	}
	pv := anyMap(doc["proxy-providers"])["pv"].(map[string]any)
	mustEqual(t, "pv.interval", anyMap(pv["health-check"])["interval"], 300)
	probeGroup(t, doc, "Pick")
	mustEqual(t, "secret", doc["secret"], fixtureToken)
	mustEqual(t, "external-controller", doc["external-controller"], "127.0.0.1:19090")
	afterApply := configBytes(t, configPath)

	// Idempotence: the same apply again is a no-op.
	repeat := RunRequest(t, a, []string{"health-check"},
		map[string]string{"interval": "600", "apply": "true"}, "group", "Auto")
	if repeat.Overall != "PASS" {
		t.Fatalf("idempotent apply: overall=%s errors=%v", repeat.Overall, repeat.Errors)
	}
	mustEqual(t, "repeat state", dataLegacy(t, repeat)["state"], "unchanged")
	if now := configBytes(t, configPath); !bytes.Equal(now, afterApply) {
		t.Fatal("idempotent apply rewrote the configuration")
	}

	// Preset, then a partial override: the preset's other fields survive.
	preset := RunRequest(t, a, []string{"health-check"},
		map[string]string{"preset": "resilient", "apply": "true"}, "group", "Auto")
	if preset.Overall != "PASS" {
		t.Fatalf("preset: overall=%s errors=%v", preset.Overall, preset.Errors)
	}
	doc = decodeConfigFile(t, configPath)
	auto = probeGroup(t, doc, "Auto")
	mustEqual(t, "preset url", auto["url"], testURL)
	mustEqual(t, "preset interval", auto["interval"], 120)
	mustEqual(t, "preset timeout", auto["timeout"], 5000)
	mustEqual(t, "preset lazy", auto["lazy"], false)
	mustEqual(t, "preset tolerance", auto["tolerance"], 50)
	override := RunRequest(t, a, []string{"health-check"},
		map[string]string{"url": "https://www.example.com/health", "apply": "true"}, "group", "Auto")
	if override.Overall != "PASS" {
		t.Fatalf("override: overall=%s errors=%v", override.Overall, override.Errors)
	}
	doc = decodeConfigFile(t, configPath)
	auto = probeGroup(t, doc, "Auto")
	mustEqual(t, "overridden url", auto["url"], "https://www.example.com/health")
	mustEqual(t, "preserved interval", auto["interval"], 120)
	mustEqual(t, "preserved timeout", auto["timeout"], 5000)
	mustEqual(t, "preserved lazy", auto["lazy"], false)
	mustEqual(t, "preserved tolerance", auto["tolerance"], 50)

	// Provider apply: settings land under the provider and the referencing
	// groups are named.
	provider := RunRequest(t, a, []string{"health-check"},
		map[string]string{"preset": "resilient", "apply": "true"}, "provider", "pv")
	if provider.Overall != "PASS" {
		t.Fatalf("provider apply: overall=%s errors=%v", provider.Overall, provider.Errors)
	}
	providerLegacy := dataLegacy(t, provider)
	affected := stringList(t, "affected_groups", providerLegacy["affected_groups"])
	if len(affected) != 1 || affected[0] != "Pick" {
		t.Fatalf("affected_groups = %v", providerLegacy["affected_groups"])
	}
	doc = decodeConfigFile(t, configPath)
	hc := anyMap(anyMap(doc["proxy-providers"])["pv"])
	mustEqual(t, "pv preset enable", anyMap(hc["health-check"])["enable"], true)
	mustEqual(t, "pv preset interval", anyMap(hc["health-check"])["interval"], 120)
	mustEqual(t, "pv preset timeout", anyMap(hc["health-check"])["timeout"], 5000)

	// The security envelope survived every write.
	mustEqual(t, "final secret", doc["secret"], fixtureToken)
	mustEqual(t, "final controller", doc["external-controller"], "127.0.0.1:19090")
}

// requireNodeInterpreter makes a real Node interpreter visible to the exact
// production lookup (exec.LookPath), honoring MIHOMOCTL_GO_TEST_NODE to pin
// one. The override acceptance executes real trusted JavaScript; a host
// without Node cannot produce that evidence, so the test fails rather than
// skipping.
func requireNodeInterpreter(t *testing.T) {
	t.Helper()
	if pinned := os.Getenv("MIHOMOCTL_GO_TEST_NODE"); pinned != "" {
		if _, err := os.Stat(pinned); err != nil {
			t.Fatalf("MIHOMOCTL_GO_TEST_NODE unusable: %v", err)
		}
		t.Setenv("PATH", filepath.Dir(pinned)+string(os.PathListSeparator)+os.Getenv("PATH"))
	}
	if _, err := exec.LookPath("node"); err != nil {
		t.Fatalf("override acceptance requires a real Node interpreter on PATH (or MIHOMOCTL_GO_TEST_NODE): %v", err)
	}
}

// writeTrustedScript stages a private trusted-script fixture.
func writeTrustedScript(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(privateTempDir(t), name)
	if err := platform.AtomicWrite(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestLinuxOverrideTrustedScriptEndToEnd is the Go/Node override acceptance:
// a trusted script previews and applies a policy-only change through the full
// Run path, a script attempting to replace the listener or authentication is
// refused, a runaway script is bounded by the vm timeout, and the FlClash
// adaptation turns provider-cached node references into use/filter groups
// without inlining cached nodes.
func TestLinuxOverrideTrustedScriptEndToEnd(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("user-scope mutation gate refuses root")
	}
	requireNodeInterpreter(t)

	reorder := writeTrustedScript(t, "reorder.js", `function main(input) {
	const out = Object.assign({}, input);
	out['proxy-groups'] = (input['proxy-groups'] || []).concat([
		{name: 'Extra', type: 'select', proxies: ['old']}
	]);
	out.rules = (input.rules || []).concat(['DOMAIN-SUFFIX,example.org,Extra']);
	return out;
}
`)
	a, configPath := subscriptionScope(t, linuxRoutedConfig, "/usr/bin/true")
	original := configBytes(t, configPath)

	preview := RunRequest(t, a, []string{"override"}, map[string]string{"script": reorder})
	if preview.Overall != "PASS" {
		t.Fatalf("preview: overall=%s errors=%v", preview.Overall, preview.Errors)
	}
	legacy := dataLegacy(t, preview)
	mustEqual(t, "preview state", legacy["state"], "preview")
	sections := stringList(t, "changed_sections", legacy["changed_sections"])
	if strings.Join(sections, ",") != "proxy-groups,rules" {
		t.Fatalf("changed_sections = %v", legacy["changed_sections"])
	}
	if now := configBytes(t, configPath); !bytes.Equal(now, original) {
		t.Fatal("override preview modified the configuration on disk")
	}

	applied := RunRequest(t, a, []string{"override"}, map[string]string{"script": reorder, "apply": "true"})
	if applied.Overall != "PASS" {
		t.Fatalf("apply: overall=%s errors=%v", applied.Overall, applied.Errors)
	}
	mustEqual(t, "applied state", dataLegacy(t, applied)["state"], "restart-required")
	doc := decodeConfigFile(t, configPath)
	probeGroup(t, doc, "Extra")
	rules := anyList(doc["rules"])
	if len(rules) != 2 || rules[1] != "DOMAIN-SUFFIX,example.org,Extra" {
		t.Fatalf("rules = %v", rules)
	}
	mustEqual(t, "secret", doc["secret"], fixtureToken)
	mustEqual(t, "external-controller", doc["external-controller"], "127.0.0.1:19090")
	afterApply := configBytes(t, configPath)

	// A script trying to replace the listener or the authentication secret
	// is refused and leaves the configuration untouched.
	evil := writeTrustedScript(t, "evil.js", `function main(input) {
	const out = Object.assign({}, input);
	out.rules = input.rules;
	out['external-controller'] = '0.0.0.0:9090';
	out.secret = 'evil-secret-0123456789abcdef0123456789';
	return out;
}
`)
	refused := RunRequest(t, a, []string{"override"}, map[string]string{"script": evil, "apply": "true"})
	if refused.Overall != "UNVERIFIED" || len(refused.Errors) != 1 ||
		refused.Errors[0].Code != "override-may-only-change-groups-rules-rule-providers" {
		t.Fatalf("listener/auth override: overall=%s errors=%v", refused.Overall, refused.Errors)
	}
	if now := configBytes(t, configPath); !bytes.Equal(now, afterApply) {
		t.Fatal("refused override modified the configuration")
	}

	// A runaway script is bounded by the vm timeout, not the process clock.
	hang := writeTrustedScript(t, "hang.js", `function main(input) { while (true) {} }
`)
	started := time.Now()
	hung := RunRequest(t, a, []string{"override"}, map[string]string{"script": hang, "apply": "true"})
	if elapsed := time.Since(started); elapsed > 9*time.Second {
		t.Fatalf("runaway script ran %v; the vm timeout must bound it", elapsed)
	}
	if hung.Overall != "FAIL" || len(hung.Errors) != 1 ||
		hung.Errors[0].Code != "override-failed-check-script-input-groups-and-inline-proxies" {
		t.Fatalf("runaway script: overall=%s errors=%v", hung.Overall, hung.Errors)
	}
	if now := configBytes(t, configPath); !bytes.Equal(now, afterApply) {
		t.Fatal("failed override modified the configuration")
	}
}

var linuxFlclashConfig = "external-controller: 127.0.0.1:19090\nsecret: " + fixtureToken + "\n" +
	"proxies:\n  - name: old\n    type: ss\n    server: 127.0.0.1\n    port: 8388\n    cipher: aes-128-gcm\n    password: pw\n" +
	"proxy-providers:\n  pv:\n    type: http\n    url: https://example.invalid/sub\n    path: providers/pv.yaml\n" +
	"proxy-groups:\n  - name: P\n    type: select\n    proxies:\n      - old\n" +
	"rules:\n  - MATCH,P\n"

// TestLinuxOverrideFlClashAdaptationEndToEnd is the FlClash leg of the
// override acceptance: the desktop script sees inline plus provider-cached
// nodes, and the applied configuration keeps only the inline nodes while the
// group's cached references become provider use plus an exact filter.
func TestLinuxOverrideFlClashAdaptationEndToEnd(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("user-scope mutation gate refuses root")
	}
	requireNodeInterpreter(t)

	a, configPath := subscriptionScope(t, linuxFlclashConfig, "/usr/bin/true")
	cache := filepath.Join(a.Scope.CoreHome(), "providers", "pv.yaml")
	if err := platform.PrivateDir(filepath.Dir(cache)); err != nil {
		t.Fatal(err)
	}
	if err := platform.AtomicWrite(cache, []byte("proxies:\n  - name: cached-a\n    type: ss\n    server: 127.0.0.1\n    port: 8388\n    cipher: aes-128-gcm\n    password: pw\n"), 0600); err != nil {
		t.Fatal(err)
	}
	original := configBytes(t, configPath)

	script := writeTrustedScript(t, "flclash.js", `function main(input) {
	const out = Object.assign({}, input);
	const groups = (input['proxy-groups'] || []).map(function (g) { return Object.assign({}, g); });
	groups.push({name: 'Auto', type: 'select', proxies: ['cached-a', 'DIRECT']});
	out['proxy-groups'] = groups;
	out.proxies = input.proxies;
	out.rules = input.rules;
	return out;
}
`)
	preview := RunRequest(t, a, []string{"override"},
		map[string]string{"script": script, "flclash-compat": "true"})
	if preview.Overall != "PASS" {
		t.Fatalf("preview: overall=%s errors=%v", preview.Overall, preview.Errors)
	}
	mustEqual(t, "preview state", dataLegacy(t, preview)["state"], "preview")
	if now := configBytes(t, configPath); !bytes.Equal(now, original) {
		t.Fatal("FlClash preview modified the configuration on disk")
	}

	applied := RunRequest(t, a, []string{"override"},
		map[string]string{"script": script, "flclash-compat": "true", "apply": "true"})
	if applied.Overall != "PASS" {
		t.Fatalf("apply: overall=%s errors=%v", applied.Overall, applied.Errors)
	}
	mustEqual(t, "applied state", dataLegacy(t, applied)["state"], "restart-required")
	doc := decodeConfigFile(t, configPath)
	auto := probeGroup(t, doc, "Auto")
	mustEqual(t, "Auto.use", auto["use"], []any{"pv"})
	mustEqual(t, "Auto.filter", auto["filter"], "^(?:cached-a)$")
	mustEqual(t, "Auto.proxies", auto["proxies"], []any{"DIRECT"})
	inline := anyList(doc["proxies"])
	if len(inline) != 1 {
		t.Fatalf("inline proxies = %v", inline)
	}
	if name := anyMap(inline[0])["name"]; name != "old" {
		t.Fatalf("inline proxy = %v", inline[0])
	}
	ai := probeGroup(t, doc, "Ai+")
	mustEqual(t, "Ai+.type", ai["type"], "select")
	probeGroup(t, doc, "漏网之鱼")
	mustEqual(t, "secret", doc["secret"], fixtureToken)
	mustEqual(t, "external-controller", doc["external-controller"], "127.0.0.1:19090")
}

// TestLinuxUIDashboardAliasParity pins the dashboard alias acceptance: the
// compatibility entry returns the same dashboard payload as ui, and both
// refuse identically when no dashboard is configured.
func TestLinuxUIDashboardAliasParity(t *testing.T) {
	f := newFixtureServer(t)
	a, configPath := fixtureScope(t, f)

	// Configured: identical payloads from both entry points.
	configured := "external-controller: 127.0.0.1:" + itoa(f.port()) + "\n" +
		"secret: " + fixtureToken + "\n" +
		"external-ui: " + filepath.Join(a.Scope.DataRoot, "ui") + "\n" +
		"proxies: [{name: test, type: ss, password: PRIVATE-LOG-CREDENTIAL}]\n"
	if err := platform.AtomicWrite(configPath, []byte(configured), 0600); err != nil {
		t.Fatal(err)
	}
	ui := runRequest(t, a, []string{"ui"})
	dashboard := runRequest(t, a, []string{"dashboard"})
	if ui.Overall != "PASS" || dashboard.Overall != "PASS" {
		t.Fatalf("overall ui=%s dashboard=%s errors=%v/%v", ui.Overall, dashboard.Overall, ui.Errors, dashboard.Errors)
	}
	strip := func(m map[string]any) map[string]any {
		out := map[string]any{}
		for key, value := range m {
			if key == "command" || key == "schema" {
				continue
			}
			out[key] = value
		}
		return out
	}
	uiPayload := strip(dataLegacy(t, ui))
	dashboardPayload := strip(dataLegacy(t, dashboard))
	mustEqual(t, "dashboard payload", dashboardPayload, uiPayload)

	// Unconfigured: identical refusals from both entry points.
	bare := "external-controller: 127.0.0.1:" + itoa(f.port()) + "\n" +
		"secret: " + fixtureToken + "\n" +
		"proxies: [{name: test, type: ss, password: PRIVATE-LOG-CREDENTIAL}]\n"
	if err := platform.AtomicWrite(configPath, []byte(bare), 0600); err != nil {
		t.Fatal(err)
	}
	uiRefusal := runRequest(t, a, []string{"ui"})
	dashboardRefusal := runRequest(t, a, []string{"dashboard"})
	if uiRefusal.Overall != "FAIL" || dashboardRefusal.Overall != "FAIL" {
		t.Fatalf("refusal overall ui=%s dashboard=%s", uiRefusal.Overall, dashboardRefusal.Overall)
	}
	mustEqual(t, "dashboard refusal errors", dashboardRefusal.Errors, uiRefusal.Errors)
	if uiRefusal.Errors[0].Code != "dashboard-not-configured" {
		t.Fatalf("refusal errors = %v", uiRefusal.Errors)
	}
}
