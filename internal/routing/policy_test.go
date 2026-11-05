package routing

import (
	"context"
	"strings"
	"testing"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

// mustCode asserts a control error code.
func mustCode(t *testing.T, err error, code string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error %s, got nil", code)
	}
	ce, ok := err.(*controlError)
	if !ok {
		t.Fatalf("error %v (%T) is not a control error", err, err)
	}
	if ce.code != code {
		t.Fatalf("code = %s, want %s", ce.code, code)
	}
}

// mustRuleCode asserts a rule checker code.
func mustRuleCode(t *testing.T, err error, code string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected rule error %s, got nil", code)
	}
	re, ok := err.(*ruleError)
	if !ok {
		t.Fatalf("error %v (%T) is not a rule error", err, err)
	}
	if re.code != code {
		t.Fatalf("rule code = %s, want %s", re.code, code)
	}
}

// writePolicyConfig stores a core configuration the way the manager does.
func writePolicyConfig(t *testing.T, content string) (platform.App, string) {
	t.Helper()
	root := privateTempDir(t)
	scope := platform.Scope{
		Name:        "user",
		ConfigRoot:  root + "/config",
		DataRoot:    root + "/data",
		StateRoot:   root + "/state",
		CacheRoot:   root + "/cache",
		RuntimeRoot: root + "/state/runtime",
	}
	path := scope.ConfigRoot + "/mihomo/config.yaml"
	if err := platform.AtomicWrite(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return platform.App{Scope: scope}, path
}

const manualConfig = `proxy-groups:
  - name: P
    type: url-test
    url: https://example.com/probe
    interval: 300
    proxies:
      - A
      - B
rules:
  - MATCH,P
`

func TestManualPolicyConvertsGroupToSelect(t *testing.T) {
	a, path := writePolicyConfig(t, manualConfig)
	_, updated, summary, err := policyCandidate(context.Background(), a, path, "", "", "P", false)
	if err != nil {
		t.Fatal(err)
	}
	sections, ok := summary["changed_sections"].([]string)
	if !ok || strings.Join(sections, "|") != "proxy-groups|profile" {
		t.Fatalf("changed_sections = %v", summary["changed_sections"])
	}
	if summary["state"] != "preview" {
		t.Fatalf("state = %v", summary["state"])
	}
	groups, ok := summary["groups"].([]any)
	if !ok || len(groups) != 1 {
		t.Fatalf("groups = %v", summary["groups"])
	}
	group := groups[0].(map[string]any)
	if group["name"] != "P" || group["type"] != "select" {
		t.Fatalf("group row = %v", group)
	}
	if summary["rule_count"] != 1 {
		t.Fatalf("rule_count = %v", summary["rule_count"])
	}
	if summary["service"] != "unchanged" {
		t.Fatalf("service = %v", summary["service"])
	}
	text := string(updated)
	if !strings.Contains(text, "store-selected: true") {
		t.Fatalf("profile patch missing:\n%s", text)
	}
	if strings.Contains(text, "interval:") || strings.Contains(text, "url-test") {
		t.Fatalf("probe fields survived:\n%s", text)
	}
	if !strings.Contains(text, "type: select") {
		t.Fatalf("group type not rewritten:\n%s", text)
	}
}

func TestManualPolicyUnchangedWhenAlreadySelect(t *testing.T) {
	a, path := writePolicyConfig(t, "proxy-groups:\n  - name: P\n    type: select\n    proxies:\n      - A\n")
	original, updated, summary, err := policyCandidate(context.Background(), a, path, "", "", "P", false)
	if err != nil {
		t.Fatal(err)
	}
	if string(original) != string(updated) {
		t.Fatalf("candidate modified an already-select group:\n%s", updated)
	}
	if summary["state"] != "unchanged" {
		t.Fatalf("state = %v", summary["state"])
	}
	if sections, ok := summary["changed_sections"].([]string); !ok || len(sections) != 0 {
		t.Fatalf("changed_sections = %v", summary["changed_sections"])
	}
}

func TestManualPolicyGroupErrors(t *testing.T) {
	a, path := writePolicyConfig(t, manualConfig)
	_, _, _, err := policyCandidate(context.Background(), a, path, "", "", "Missing", false)
	mustCode(t, err, "manual-requires-existing-policy-group")

	duplicate := "proxy-groups:\n  - name: P\n    type: select\n    proxies:\n      - A\n" +
		"  - name: P\n    type: select\n    proxies:\n      - B\n"
	a, path = writePolicyConfig(t, duplicate)
	_, _, _, err = policyCandidate(context.Background(), a, path, "", "", "P", false)
	mustCode(t, err, "manual-requires-existing-policy-group")

	a, path = writePolicyConfig(t, "proxy-groups:\n  - name: P\n    type: relay\n    proxies:\n      - A\n")
	_, _, _, err = policyCandidate(context.Background(), a, path, "", "", "P", false)
	mustCode(t, err, "manual-requires-existing-policy-group")
}

func TestManualPolicyRejectsInvalidProfile(t *testing.T) {
	a, path := writePolicyConfig(t, "profile: 5\n"+manualConfig)
	_, _, _, err := policyCandidate(context.Background(), a, path, "", "", "P", false)
	mustCode(t, err, "config-profile-invalid")
}

func TestFlclashInputAdaptsProviderCaches(t *testing.T) {
	home := privateTempDir(t)
	cache := "proxies:\n  - name: N1\n    type: ss\n  - name: N2\n    type: ss\n"
	if err := platform.AtomicWrite(home+"/providers/p1.yaml", []byte(cache), 0600); err != nil {
		t.Fatal(err)
	}
	data := map[string]any{
		"proxies":         []any{},
		"proxy-providers": map[string]any{"p1": map[string]any{"type": "file", "path": "providers/p1.yaml"}},
		"proxy-groups":    []any{map[string]any{"name": "G", "type": "select", "proxies": []any{"A"}}},
	}
	adapted, providerNodes, err := flclashInput(data, home)
	if err != nil {
		t.Fatal(err)
	}
	nodes := anyList(adapted["proxies"])
	if len(nodes) != 2 {
		t.Fatalf("adapted proxies = %v", nodes)
	}
	if got := providerNodes["N1"]; len(got) != 1 || got[0] != "p1" {
		t.Fatalf("providerNodes[N1] = %v", got)
	}
	groups := anyList(adapted["proxy-groups"])
	names := map[string]bool{}
	for _, g := range groups {
		if gm, ok := g.(map[string]any); ok {
			names[gm["name"].(string)] = true
		}
	}
	if !names["Ai+"] || !names["漏网之鱼"] {
		t.Fatalf("desktop groups missing: %v", names)
	}
}

func TestFlclashInputRejectsMissingCacheAndInvalidCache(t *testing.T) {
	home := privateTempDir(t)
	data := map[string]any{
		"proxies":         []any{},
		"proxy-providers": map[string]any{"p1": map[string]any{"type": "http"}},
	}
	_, _, err := flclashInput(data, home)
	mustCode(t, err, "flclash-provider-needs-local-cache")

	if err := platform.AtomicWrite(home+"/providers/bad.yaml", []byte("proxies: oops\n"), 0600); err != nil {
		t.Fatal(err)
	}
	data["proxy-providers"] = map[string]any{"p1": map[string]any{"type": "file", "path": "providers/bad.yaml"}}
	_, _, err = flclashInput(data, home)
	mustCode(t, err, "flclash-provider-cache-invalid")
}
