package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// Envelope data must decode through JSON so numbers are float64, exactly what
// the real CLI produces; the counting helpers depend on that typing.
func TestPreviewSummaryCountsJSONNumbers(t *testing.T) {
	raw := `{"state":"preview","policy":"provider","nodes":114,"added":114,
	         "groups":8,"removed_groups":2,"rules":61}`
	var preview map[string]any
	if err := json.Unmarshal([]byte(raw), &preview); err != nil {
		t.Fatal(err)
	}
	lines := previewSummary(preview)
	if !strings.Contains(lines[1], "节点 114（新增 114、替换 0、移除 0）｜分组 8（移除 2）｜规则 61（移除 0）") {
		t.Fatalf("counts wrong: %q", lines[1])
	}
}

func TestClearingWarnings(t *testing.T) {
	if warnings := clearingWarnings(map[string]any{"removed_groups": 2.0}); len(warnings) != 1 {
		t.Fatalf("expected one warning, got %v", warnings)
	}
	if warnings := clearingWarnings(map[string]any{"removed_groups": 0.0, "removed_rules": 0.0}); len(warnings) != 0 {
		t.Fatalf("expected no warnings, got %v", warnings)
	}
}

func TestEnvelopeLinesRendersChecksAndErrors(t *testing.T) {
	env := Envelope{
		Command: "health", Scope: "user", Overall: "UNVERIFIED",
		Data: map[string]any{"overall": "UNVERIFIED"},
		Checks: []Check{{Name: "runtime", Status: "PASS", Evidence: "confirmed", Detail: "pid 1"}},
		Errors: []ErrDoc{{Code: "some-failure", Detail: "safe detail"}},
	}
	lines := strings.Join(envelopeLines(env), "\n")
	for _, want := range []string{"结论 未确认", "通过 runtime [直接观测] pid 1", "错误 some-failure"} {
		if !strings.Contains(lines, want) {
			t.Fatalf("missing %q in:\n%s", want, lines)
		}
	}
}

func TestDemoCLIEnvelopeUsesProductionTypes(t *testing.T) {
	cli := &demoCli{}
	env, err := cli.Run("subscription", "preview", "--policy", "provider")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := env.Data["nodes"].(float64); !ok {
		t.Fatalf("demo numbers must be float64 like production, got %T", env.Data["nodes"])
	}
}
