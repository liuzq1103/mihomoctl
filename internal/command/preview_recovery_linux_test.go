//go:build linux

package command_test

import (
	"path/filepath"
	"reflect"
	"testing"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

// A subscription preview describes a change and performs none. Replaying a
// recovery journal while previewing would replace the live configuration the
// preview describes, so the command layer refuses a pending recovery exactly
// as it does for a dry run — before any lock is taken and before any journal
// is replayed.
func TestExecuteSubscriptionPreviewRefusesPendingRecovery(t *testing.T) {
	base, scope := dryRunScope(t)
	original := []byte("external-controller: 127.0.0.1:19090\n")
	published := []byte("external-controller: 127.0.0.1:19091\n")
	config := filepath.Join(scope.ConfigRoot, "mihomo", "config.yaml")
	if err := platform.AtomicWrite(config, original, 0600); err != nil {
		t.Fatal(err)
	}
	// The crashed publication: the candidate stands at the path and the
	// journal that would roll it back is still pending.
	if err := platform.AtomicWrite(config, published, 0600); err != nil {
		t.Fatal(err)
	}
	id := "preview-fixture-0123456789ab"
	directory := filepath.Join(scope.StateRoot, "backups", id)
	if err := platform.PrivateDir(directory); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(directory, "0-config.yaml")
	if err := platform.AtomicWrite(backup, original, 0600); err != nil {
		t.Fatal(err)
	}
	journal := map[string]any{
		"id": id, "name": "preview-fixture", "state": "pending", "staging": "",
		"journal": []map[string]any{{
			"op": "publish", "path": config, "type": "file", "mode": "600",
			"backup": backup, "backup_sha256": platform.Hash(original),
			"existed": true, "published_sha256": platform.Hash(published),
		}},
	}
	if err := platform.WriteJSON(filepath.Join(directory, "journal.json"), journal); err != nil {
		t.Fatal(err)
	}
	before := dryRunSnapshot(t, base)
	env := dryRunExecute(t, []string{"subscription", "preview"})
	if env.Overall != "UNVERIFIED" || len(env.Errors) != 1 || env.Errors[0].Code != "transaction-recovery-required" {
		t.Fatalf("the preview must refuse pending recovery: %+v", env)
	}
	if after := dryRunSnapshot(t, base); !reflect.DeepEqual(before, after) {
		t.Fatal("the preview changed the scope, replayed the journal, or staged a plan")
	}
}
