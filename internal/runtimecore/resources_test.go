package runtimecore

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

func sparseResource(t *testing.T, p string, size int64) {
	t.Helper()
	if e := platform.PrivateDir(filepath.Dir(p)); e != nil {
		t.Fatal(e)
	}
	f, e := os.OpenFile(p, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0600)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	if e = f.Truncate(size); e != nil {
		t.Fatal(e)
	}
	if size > 4 {
		if _, e = f.WriteAt([]byte{0xff, 0, 0x7f, 0x81}, size-4); e != nil {
			t.Fatal(e)
		}
	}
}
func TestLargeBinaryGeodataStagedWithoutTextLimit(t *testing.T) {
	a := testApp(t)
	source := filepath.Join(a.Scope.CoreHome(), "GeoSite.dat")
	sparseResource(t, source, 20<<20)
	staging := filepath.Join(filepath.Dir(a.Scope.ConfigRoot), "staging")
	if e := platform.PrivateDir(staging); e != nil {
		t.Fatal(e)
	}
	proofs, e := stageResources(context.Background(), a, map[string]any{}, staging)
	if e != nil || len(proofs) != 1 {
		t.Fatal(proofs, e)
	}
	st, e := os.Stat(filepath.Join(staging, "GeoSite.dat"))
	if e != nil || st.Size() != 20<<20 {
		t.Fatal(st, e)
	}
	if e = verifyResources(context.Background(), a, proofs); e != nil {
		t.Fatal(e)
	}
	f, e := os.OpenFile(source, os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	f.WriteAt([]byte("changed"), 0)
	f.Close()
	requireCode(t, verifyResources(context.Background(), a, proofs), "validation-inputs-changed")
}
func TestRoleSpecificLimitsAndResourcePathConfinement(t *testing.T) {
	a := testApp(t)
	source := filepath.Join(a.Scope.CoreHome(), "GeoIP.dat")
	sparseResource(t, source, geodataLimit+1)
	staging := filepath.Join(filepath.Dir(a.Scope.ConfigRoot), "staging")
	if e := platform.PrivateDir(staging); e != nil {
		t.Fatal(e)
	}
	_, e := stageResources(context.Background(), a, map[string]any{}, staging)
	requireCode(t, e, "validation-resource-too-large")
	if e = os.Remove(source); e != nil {
		t.Fatal(e)
	}
	provider := filepath.Join(a.Scope.CoreHome(), "providers", "nodes.yaml")
	sparseResource(t, provider, providerLimit+1)
	cfg := map[string]any{"proxy-providers": map[string]any{"nodes": map[string]any{"type": "file", "path": "providers/nodes.yaml"}}}
	_, e = stageResources(context.Background(), a, cfg, staging)
	requireCode(t, e, "validation-resource-too-large")
	for _, path := range []string{"../outside", "cache.db", "candidate.yaml", "Country.mmdb/nodes", "nested/../nodes"} {
		cfg["proxy-providers"].(map[string]any)["nodes"].(map[string]any)["path"] = path
		_, e = stageResources(context.Background(), a, cfg, staging)
		requireCode(t, e, "validation-resource-path-unsafe")
	}
	_, _, e = hashResource(context.Background(), a, provider, "unbounded")
	requireCode(t, e, "validation-resource-role-invalid")
}
func TestBinaryTransferCancellationAndLimit(t *testing.T) {
	a := testApp(t)
	source := filepath.Join(a.Scope.CoreHome(), "binary.dat")
	sparseResource(t, source, 4096)
	target := filepath.Join(filepath.Dir(a.Scope.ConfigRoot), "stage", "binary.dat")
	_, _, e := transferResource(context.Background(), a, source, target, 2048)
	requireCode(t, e, "validation-resource-too-large")
	if _, e = os.Stat(target); !os.IsNotExist(e) {
		t.Fatal("published oversized resource")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, e = transferResource(ctx, a, source, target, 8192)
	if e != context.Canceled {
		t.Fatal(e)
	}
	entries, _ := os.ReadDir(filepath.Dir(target))
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".resource-") {
			t.Fatal("left partial resource")
		}
	}
}
func TestCoreListAcceptsDeliveryV1ReceiptAndRejectsFractionalFormat(t *testing.T) {
	a := testApp(t)
	binary := filepath.Join(a.Scope.DataRoot, "cores", "v1.19.33-reviewed", "mihomo")
	if e := platform.AtomicWrite(binary, []byte("executable fixture"), 0700); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(filepath.Dir(binary), "receipt.json")
	receipt := map[string]any{"format": 1, "project": "mihomoctl-go", "plan": map[string]any{"version": "v1.19.33", "asset": "mihomo-linux-amd64-compatible-v1.19.33.gz", "sha256": strings.Repeat("a", 64), "url": "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.33/asset.gz", "provenance": "maintainer-pin"}, "binary_sha256": platform.Hash([]byte("executable fixture")), "installed_at": "2026-11-05T00:00:00Z", "note": "digest comparison, not an upstream signature"}
	if e := platform.WriteJSON(path, receipt); e != nil {
		t.Fatal(e)
	}
	doc, e := Run(context.Background(), a, platform.Request{Command: []string{"core", "list"}})
	if e != nil || len(doc.Data["installs"].([]map[string]any)) != 1 {
		t.Fatal(doc, e)
	}
	receipt["format"] = 1.5
	if e = platform.WriteJSON(path, receipt); e != nil {
		t.Fatal(e)
	}
	_, e = Run(context.Background(), a, platform.Request{Command: []string{"core", "list"}})
	requireCode(t, e, "core-receipt-invalid")
	receipt["format"] = 1
	receipt["project"] = "mihomo-userctl"
	if e = platform.WriteJSON(path, receipt); e != nil {
		t.Fatal(e)
	}
	_, e = Run(context.Background(), a, platform.Request{Command: []string{"core", "list"}})
	requireCode(t, e, "core-receipt-invalid")
	receipt["project"] = "mihomoctl-go"
	receipt["binary_sha256"] = strings.Repeat("b", 64)
	if e = platform.WriteJSON(path, receipt); e != nil {
		t.Fatal(e)
	}
	_, e = Run(context.Background(), a, platform.Request{Command: []string{"core", "list"}})
	requireCode(t, e, "core-receipt-digest-mismatch")
}

func TestAggregateValidationResourceBudget(t *testing.T) {
	a := testApp(t)
	sparseResource(t, filepath.Join(a.Scope.CoreHome(), "GeoIP.dat"), 12)
	sparseResource(t, filepath.Join(a.Scope.CoreHome(), "ASN.mmdb"), 12)
	staging := filepath.Join(filepath.Dir(a.Scope.ConfigRoot), "stage")
	if e := platform.PrivateDir(staging); e != nil {
		t.Fatal(e)
	}
	_, e := stageResourcesBudget(context.Background(), a, map[string]any{}, staging, 20)
	requireCode(t, e, "validation-resource-too-large")
}
func TestFileJournalCanRecoverMultipleLargeTextSnapshots(t *testing.T) {
	a := testApp(t)
	p := filepath.Join(a.Scope.ConfigRoot, "large.txt")
	before := []byte(strings.Repeat("a", 9<<20))
	after := []byte(strings.Repeat("b", 9<<20))
	if e := platform.AtomicWrite(p, after, 0600); e != nil {
		t.Fatal(e)
	}
	j := journal{Version: 1, Files: []fileSnapshot{{Path: p, Before: before, Existed: true, After: after}}}
	raw, e := json.Marshal(j)
	if e != nil {
		t.Fatal(e)
	}
	if len(raw) <= platform.Limit {
		t.Fatal("test did not exceed YAML limit")
	}
	if e = platform.AtomicWrite(journalPath(a), raw, 0600); e != nil {
		t.Fatal(e)
	}
	if e = recoverTransaction(a); e != nil {
		t.Fatal(e)
	}
	got, e := platform.ReadPrivate(p)
	if e != nil || !bytesEqual(got, before) {
		t.Fatal("large snapshot not restored", e)
	}
}
