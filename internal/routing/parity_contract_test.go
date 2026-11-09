package routing

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

// TestUninitializedInstallationRefusesBridge pins the uninitialized-scope
// contract from the parity baseline: with no manager document at all, every
// bridged command refuses with bridge-unavailable and names the two supported
// ways forward — never a bare config-missing.
func TestUninitializedInstallationRefusesBridge(t *testing.T) {
	root := privateTempDir(t)
	a := platform.App{Scope: platform.Scope{
		Name:        "user",
		ConfigRoot:  filepath.Join(root, "config"),
		DataRoot:    filepath.Join(root, "data"),
		StateRoot:   filepath.Join(root, "state"),
		CacheRoot:   filepath.Join(root, "cache"),
		RuntimeRoot: filepath.Join(root, "state", "runtime"),
	}}
	for _, command := range [][]string{
		{"controller", "status"},
		{"nodes"},
		{"groups"},
	} {
		envelope := RunRequest(t, a, command, nil)
		if envelope.Overall != "UNVERIFIED" {
			t.Fatalf("%v: overall = %s errors = %v", command, envelope.Overall, envelope.Errors)
		}
		if len(envelope.Errors) != 1 {
			t.Fatalf("%v: errors = %v", command, envelope.Errors)
		}
		if envelope.Errors[0].Code != "bridge-unavailable" {
			t.Fatalf("%v: code = %q", command, envelope.Errors[0].Code)
		}
		if envelope.Errors[0].Detail != "initialize V1 (mihomoctl init) or keep the 0.9.x configuration" {
			t.Fatalf("%v: detail = %q", command, envelope.Errors[0].Detail)
		}
		if encoded := mustJSON(t, envelope); strings.Contains(encoded, "config-missing") {
			t.Fatalf("%v: config-missing leaked: %s", command, encoded)
		}
	}
}

// TestGroupsEmptyArraysNeverNull pins the groups payload contract: the
// affected_groups and automatic_candidates fields render as [] when empty,
// never null — the exact shape the parity baseline emits.
func TestGroupsEmptyArraysNeverNull(t *testing.T) {
	f := newFixtureServer(t)
	a, _ := fixtureScope(t, f)
	envelope := runRequest(t, a, []string{"groups"})
	if envelope.Overall != "PASS" {
		t.Fatalf("overall = %s errors = %v", envelope.Overall, envelope.Errors)
	}
	legacy := dataLegacy(t, envelope)
	groups, ok := legacy["groups"].([]any)
	if !ok || len(groups) == 0 {
		t.Fatalf("groups payload = %v", legacy["groups"])
	}
	for _, row := range groups {
		entry, ok := row.(map[string]any)
		if !ok {
			t.Fatalf("group row = %v", row)
		}
		// The contract is the rendered shape: the fields must serialize as
		// arrays (empty or not), never as JSON null.
		encodedRow := mustJSON(t, entry)
		for _, field := range []string{"affected_groups", "automatic_candidates"} {
			if strings.Contains(encodedRow, `"`+field+`":null`) {
				t.Fatalf("group %v: %s rendered as null:\n%s", entry["name"], field, encodedRow)
			}
		}
	}
	encoded := mustJSON(t, legacy)
	for _, field := range []string{"affected_groups", "automatic_candidates"} {
		if strings.Contains(encoded, `"`+field+`":null`) {
			t.Fatalf("%s rendered as null:\n%s", field, encoded)
		}
	}
}
