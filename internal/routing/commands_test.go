package routing

import (
	"encoding/json"
	"runtime"
	"strings"
	"testing"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

func TestHandlesGrammar(t *testing.T) {
	handled := [][]string{
		{"controller", "status"}, {"controller", "initialize"}, {"controller", "setup"}, {"controller", "token"},
		{"nodes"}, {"groups"}, {"select"}, {"latency"}, {"connections"}, {"traffic"},
		{"providers"}, {"provider", "refresh"}, {"dns"}, {"mode"},
		{"subscription", "preview"}, {"subscription", "apply"},
		{"health-check"}, {"manual"}, {"override"}, {"ui"}, {"dashboard"},
		{"rules", "status"}, {"rules", "check"},
	}
	for _, command := range handled {
		if !Handles(command) {
			t.Errorf("Handles(%v) = false", command)
		}
	}
	rejected := [][]string{
		{}, {"tui"}, {"start"}, {"status"},
		{"controller"}, {"controller", "restart"},
		{"subscription"}, {"subscription", "discard"},
		{"provider"}, {"rules"}, {"rules", "validate"},
		{"exec"},
	}
	for _, command := range rejected {
		if Handles(command) {
			t.Errorf("Handles(%v) = true", command)
		}
	}
}

func TestControllerStatusEnvelope(t *testing.T) {
	f := newFixtureServer(t)
	a, _ := fixtureScope(t, f)
	envelope := runRequest(t, a, []string{"controller", "status"})
	if envelope.Overall != "PASS" {
		t.Fatalf("overall = %s errors = %v", envelope.Overall, envelope.Errors)
	}
	if envelope.Command != "controller" {
		t.Fatalf("command = %s", envelope.Command)
	}
	legacy := dataLegacy(t, envelope)
	if legacy["schema"] != ControllerSchema {
		t.Fatalf("legacy schema = %v", legacy["schema"])
	}
	if legacy["command"] != "controller" {
		t.Fatalf("legacy command = %v", legacy["command"])
	}
	mustEqual(t, "endpoint", legacy["endpoint"], "127.0.0.1:"+itoa(f.port()))
	mustEqual(t, "authentication", legacy["authentication"], "PASS")
	mustEqual(t, "listener", legacy["listener"], "PASS")
	if envelope.Data["exit"] != 0 || envelope.Data["legacy_overall"] != "PASS" {
		t.Fatalf("bridge data = %v", envelope.Data)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := ""
	for n > 0 {
		digits = string(rune('0'+n%10)) + digits
		n /= 10
	}
	return digits
}

func TestControllerTokenNeverEntersEnvelope(t *testing.T) {
	skipUserScopeAsRoot(t)
	f := newFixtureServer(t)
	a, _ := fixtureScope(t, f)
	// A non-terminal writer must be refused before the secret is printed.
	envelope := runMutationRequest(t, a, []string{"controller", "token"})
	if envelope.Overall != "UNVERIFIED" {
		t.Fatalf("overall = %s", envelope.Overall)
	}
	if len(envelope.Errors) != 1 || envelope.Errors[0].Code != "token-display-requires-terminal-without-json" {
		t.Fatalf("errors = %v", envelope.Errors)
	}
	encoded := mustJSON(t, envelope)
	if strings.Contains(encoded, fixtureToken) {
		t.Fatal("token leaked into the failure envelope")
	}
}

func TestControllerInitializeIdempotent(t *testing.T) {
	skipUserScopeAsRoot(t)
	f := newFixtureServer(t)
	a, configPath := fixtureScope(t, f)
	configured := "external-controller: 127.0.0.1:" + itoa(f.port()) + "\n" +
		"secret: " + fixtureToken + "\n" +
		"profile:\n  store-selected: true\n"
	if err := platform.AtomicWrite(configPath, []byte(configured), 0600); err != nil {
		t.Fatal(err)
	}
	envelope := runMutationRequest(t, a, []string{"controller", "initialize"})
	if envelope.Overall != "PASS" {
		t.Fatalf("overall = %s errors = %v", envelope.Overall, envelope.Errors)
	}
	legacy := dataLegacy(t, envelope)
	if legacy["state"] != "unchanged" {
		t.Fatalf("state = %v", legacy["state"])
	}
	if legacy["endpoint"] != "127.0.0.1:"+itoa(f.port()) {
		t.Fatalf("endpoint = %v", legacy["endpoint"])
	}
	// Idempotent initialize must not touch the configuration.
	text, err := platform.ReadPrivate(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(text) != configured {
		t.Fatalf("config rewritten:\n%s", text)
	}
}

// TestMutationGateOffLinux pins the foundation contract: mutating commands are
// refused before dispatch anywhere except Linux.
func TestMutationGateOffLinux(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("mutation gate is Linux-permeable")
	}
	f := newFixtureServer(t)
	a, _ := fixtureScope(t, f)
	envelope := runRequest(t, a, []string{"mode"}, "rule")
	if envelope.Overall != "UNVERIFIED" {
		t.Fatalf("overall = %s", envelope.Overall)
	}
	if len(envelope.Errors) != 1 || envelope.Errors[0].Code != "linux-required" {
		t.Fatalf("errors = %v", envelope.Errors)
	}
	if f.patch != nil {
		t.Fatal("gated mutation reached the controller")
	}
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestNodesListingKeepsProviderIdentities(t *testing.T) {
	f := newFixtureServer(t)
	a, _ := fixtureScope(t, f)
	envelope := runRequest(t, a, []string{"nodes"})
	legacy := dataLegacy(t, envelope)
	nodes, ok := legacy["nodes"].([]any)
	if !ok {
		t.Fatalf("nodes payload = %v", legacy)
	}
	// Global node rows first (groups are skipped), then the provider node
	// from /providers/proxies.
	var names []string
	for _, row := range nodes {
		if entry, ok := row.(map[string]any); ok {
			if name, ok := entry["name"].(string); ok {
				names = append(names, name)
			}
		}
	}
	want := []string{"Node A", "Node B", "provider node"}
	if strings.Join(names, "|") != strings.Join(want, "|") {
		t.Fatalf("node order = %v", names)
	}
	encoded := mustJSON(t, legacy)
	for _, secret := range []string{fixtureToken, "DO-NOT-PRINT", "PRIVATE-URL"} {
		if strings.Contains(encoded, secret) {
			t.Fatalf("private value %q leaked into nodes payload", secret)
		}
	}
}

func TestGroupsSelectionChainAndAnnotations(t *testing.T) {
	skipUserScopeAsRoot(t)
	f := newFixtureServer(t)
	a, _ := fixtureScope(t, f)
	envelope := runRequest(t, a, []string{"groups"})
	legacy := dataLegacy(t, envelope)
	groups, ok := legacy["groups"].([]any)
	if !ok || len(groups) < 2 {
		t.Fatalf("groups payload = %v", legacy)
	}
	var selector map[string]any
	for _, row := range groups {
		entry := row.(map[string]any)
		if entry["name"] == "Proxy / 中文" {
			selector = entry
		}
	}
	if selector == nil {
		t.Fatalf("selector row missing: %v", legacy)
	}
	if selector["selected"] != "Node A" {
		t.Fatalf("selected = %v", selector["selected"])
	}
	if selector["selectable"] != true {
		t.Fatalf("selectable = %v", selector["selectable"])
	}
	chain, ok := selector["selection_chain"].([]any)
	if !ok || len(chain) == 0 {
		t.Fatalf("selection_chain = %v", selector["selection_chain"])
	}
}

func TestSelectConfirmsAndReportsAffectedGroups(t *testing.T) {
	skipUserScopeAsRoot(t)
	f := newFixtureServer(t)
	a, _ := fixtureScope(t, f)
	envelope := runMutationRequest(t, a, []string{"select"}, "Proxy / 中文", "Node B")
	if envelope.Overall != "PASS" {
		t.Fatalf("overall = %s errors = %v", envelope.Overall, envelope.Errors)
	}
	legacy := dataLegacy(t, envelope)
	if legacy["group"] != "Proxy / 中文" || legacy["selected"] != "Node B" {
		t.Fatalf("select payload = %v", legacy)
	}
	if legacy["existing_connections"] != "unchanged" {
		t.Fatalf("existing_connections = %v", legacy["existing_connections"])
	}
	if f.puts != 1 {
		t.Fatalf("puts = %d", f.puts)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.rows["Proxy / 中文"].(map[string]any)["now"] != "Node B" {
		t.Fatal("fixture row was not updated")
	}
}

func TestSelectRejectsNonMemberNode(t *testing.T) {
	skipUserScopeAsRoot(t)
	f := newFixtureServer(t)
	a, _ := fixtureScope(t, f)
	envelope := runMutationRequest(t, a, []string{"select"}, "Auto", "Node B")
	if envelope.Overall != "FAIL" {
		t.Fatalf("overall = %s", envelope.Overall)
	}
	// Auto is a URLTest group: selecting anything requires a Selector.
	if envelope.Errors[0].Code != "selection-requires-Selector-group" {
		t.Fatalf("errors = %v", envelope.Errors)
	}
}

func TestLatencyMeasuresDelay(t *testing.T) {
	f := newFixtureServer(t)
	a, _ := fixtureScope(t, f)
	envelope := runRequest(t, a, []string{"latency"}, "Node A")
	if envelope.Overall != "PASS" {
		t.Fatalf("overall = %s errors = %v", envelope.Overall, envelope.Errors)
	}
	legacy := dataLegacy(t, envelope)
	if legacy["name"] != "Node A" || legacy["provider"] != nil {
		t.Fatalf("latency payload = %v", legacy)
	}
	if legacy["delay_ms"] != 32 {
		t.Fatalf("delay_ms = %v (%T)", legacy["delay_ms"], legacy["delay_ms"])
	}
	if legacy["target"] != testURL {
		t.Fatalf("target = %v", legacy["target"])
	}
}

func TestLatencyUnknownNodeIsRedacted(t *testing.T) {
	f := newFixtureServer(t)
	a, _ := fixtureScope(t, f)
	envelope := runRequest(t, a, []string{"latency"}, "https://user:pass@example.com/")
	if envelope.Overall != "FAIL" {
		t.Fatalf("overall = %s", envelope.Overall)
	}
	if envelope.Errors[0].Code != "unknown-node" {
		t.Fatalf("errors = %v", envelope.Errors)
	}
	if strings.Contains(mustJSON(t, envelope), "user:pass") {
		t.Fatal("request-shaped node name leaked into the envelope")
	}
}

func TestTrafficSnapshotNumbers(t *testing.T) {
	f := newFixtureServer(t)
	a, _ := fixtureScope(t, f)
	envelope := runRequest(t, a, []string{"traffic"})
	legacy := dataLegacy(t, envelope)
	mustEqual(t, "up", legacy["up"], 10)
	mustEqual(t, "down", legacy["down"], 20)
	mustEqual(t, "upTotal", legacy["upTotal"], 0)
	mustEqual(t, "downTotal", legacy["downTotal"], 0)
}

func TestConnectionsRedactHostsByDefault(t *testing.T) {
	f := newFixtureServer(t)
	a, _ := fixtureScope(t, f)
	envelope := runRequest(t, a, []string{"connections"})
	legacy := dataLegacy(t, envelope)
	rows, ok := legacy["connections"].([]any)
	if !ok || len(rows) != 1 {
		t.Fatalf("connections = %v", legacy)
	}
	row := rows[0].(map[string]any)
	if _, has := row["host"]; has {
		t.Fatal("host must be omitted without --details")
	}
	if row["rule"] != "Match" {
		t.Fatalf("rule = %v", row["rule"])
	}
	encoded := mustJSON(t, legacy)
	if strings.Contains(encoded, "PRIVATE-HOST") {
		t.Fatal("host leaked into connections payload")
	}
}

func TestModePatchAndConfirm(t *testing.T) {
	skipUserScopeAsRoot(t)
	f := newFixtureServer(t)
	a, _ := fixtureScope(t, f)
	envelope := runMutationRequest(t, a, []string{"mode"}, "direct")
	if envelope.Overall != "PASS" {
		t.Fatalf("overall = %s errors = %v", envelope.Overall, envelope.Errors)
	}
	legacy := dataLegacy(t, envelope)
	if legacy["mode"] != "direct" || legacy["scope"] != "runtime-only" {
		t.Fatalf("mode payload = %v", legacy)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	mustEqual(t, "patch", f.patch, map[string]any{"mode": "direct"})
}

func TestDNSQuery(t *testing.T) {
	f := newFixtureServer(t)
	a, _ := fixtureScope(t, f)
	envelope := runRequest(t, a, []string{"dns"}, "example.com")
	legacy := dataLegacy(t, envelope)
	answers, ok := legacy["answers"].([]any)
	if !ok || len(answers) != 1 {
		t.Fatalf("dns payload = %v", legacy)
	}
	answer := answers[0].(map[string]any)
	if answer["data"] != "192.0.2.1" {
		t.Fatalf("answer = %v", answer)
	}
}

func TestProvidersListingAndRefresh(t *testing.T) {
	skipUserScopeAsRoot(t)
	f := newFixtureServer(t)
	a, _ := fixtureScope(t, f)
	envelope := runRequest(t, a, []string{"providers"})
	legacy := dataLegacy(t, envelope)
	providers, ok := legacy["providers"].([]any)
	if !ok || len(providers) != 1 {
		t.Fatalf("providers payload = %v", legacy)
	}
	row := providers[0].(map[string]any)
	mustEqual(t, "provider row", row, map[string]any{
		"name": "provider / fixture", "type": "HTTP", "nodes": 1, "updated": "now",
	})
	refresh := runMutationRequest(t, a, []string{"provider", "refresh"}, "provider / fixture")
	if refresh.Overall != "PASS" {
		t.Fatalf("refresh overall = %s errors = %v", refresh.Overall, refresh.Errors)
	}
	refreshLegacy := dataLegacy(t, refresh)
	if refreshLegacy["provider"] != "provider / fixture" || refreshLegacy["state"] != "refresh-requested" {
		t.Fatalf("refresh payload = %v", refreshLegacy)
	}
	unknown := runMutationRequest(t, a, []string{"provider", "refresh"}, "missing")
	if unknown.Overall != "FAIL" || unknown.Errors[0].Code != "unknown-provider" {
		t.Fatalf("unknown provider errors = %v", unknown.Errors)
	}
}

func TestDashboardRequiresConfiguration(t *testing.T) {
	f := newFixtureServer(t)
	a, _ := fixtureScope(t, f)
	envelope := runRequest(t, a, []string{"ui"})
	if envelope.Overall != "FAIL" || envelope.Errors[0].Code != "dashboard-not-configured" {
		t.Fatalf("ui errors = %v overall = %s", envelope.Errors, envelope.Overall)
	}
	if envelope.Command != "ui" {
		t.Fatalf("command = %s", envelope.Command)
	}
}

func TestControllerErrorsMapToOverall(t *testing.T) {
	f := newFixtureServer(t)
	a, configPath := fixtureScope(t, f)
	// A wrong secret must surface as an authorized-probe failure (rc 1).
	broken := "external-controller: 127.0.0.1:" + itoa(f.port()) + "\nsecret: " + strings.Repeat("b", 48) + "\n"
	if err := platform.AtomicWrite(configPath, []byte(broken), 0600); err != nil {
		t.Fatal(err)
	}
	envelope := runRequest(t, a, []string{"nodes"})
	if envelope.Overall != "FAIL" {
		t.Fatalf("overall = %s errors = %v", envelope.Overall, envelope.Errors)
	}
	if envelope.Errors[0].Code != "controller-authentication-failed" {
		t.Fatalf("errors = %v", envelope.Errors)
	}
}

func TestLoopbackOnlyControllerAddress(t *testing.T) {
	f := newFixtureServer(t)
	a, configPath := fixtureScope(t, f)
	remote := "external-controller: 192.0.2.10:" + itoa(f.port()) + "\nsecret: " + fixtureToken + "\n"
	if err := platform.AtomicWrite(configPath, []byte(remote), 0600); err != nil {
		t.Fatal(err)
	}
	envelope := runRequest(t, a, []string{"nodes"})
	if envelope.Overall != "UNVERIFIED" {
		t.Fatalf("overall = %s", envelope.Overall)
	}
	if envelope.Errors[0].Code != "controller-not-configured-as-loopback" {
		t.Fatalf("errors = %v", envelope.Errors)
	}
}
