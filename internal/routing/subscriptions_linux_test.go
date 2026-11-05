//go:build linux

package routing

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

// subscriptionScope builds a private user scope whose core configuration and
// manager point at the given validation binary, mirroring an initialized
// managed installation.
func subscriptionScope(t *testing.T, config, binary string) (platform.App, string) {
	t.Helper()
	root := privateTempDir(t)
	scope := platform.Scope{
		Name:        "user",
		ConfigRoot:  filepath.Join(root, "config"),
		DataRoot:    filepath.Join(root, "data"),
		StateRoot:   filepath.Join(root, "state"),
		CacheRoot:   filepath.Join(root, "cache"),
		RuntimeRoot: filepath.Join(root, "state", "runtime"),
	}
	configPath := filepath.Join(scope.ConfigRoot, "mihomo", "config.yaml")
	if err := platform.AtomicWrite(configPath, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	manager := "version: 1\ncore:\n  binary: " + binary + "\n  config: " + configPath + "\n  backend: process\n"
	if err := platform.AtomicWrite(scope.ManagerPath(), []byte(manager), 0600); err != nil {
		t.Fatal(err)
	}
	return platform.App{Scope: scope}, configPath
}

var linuxFreshConfig = "external-controller: 127.0.0.1:19090\nsecret: " + fixtureToken + "\nrules:\n  - MATCH,DIRECT\n"

var linuxRoutedConfig = "external-controller: 127.0.0.1:19090\nsecret: " + fixtureToken + "\n" +
	"proxies:\n  - name: old\n    type: ss\n    password: pw\n" +
	"proxy-groups:\n  - name: P\n    type: select\n    proxies:\n      - old\n" +
	"rules:\n  - MATCH,P\n"

const linuxNodeSubscription = "proxies:\n  - name: a\n    type: ss\n    password: pw\n  - name: b\n    type: ss\n    password: pw\n"

// stagedRoot is the private staging directory of the scope.
func stagedRoot(t *testing.T, a platform.App) string {
	t.Helper()
	return filepath.Join(a.Scope.StateRoot, "subscriptions")
}

// stagedFiles lists the staged artifacts currently on disk.
func stagedFiles(t *testing.T, a platform.App) []string {
	t.Helper()
	entries, err := os.ReadDir(stagedRoot(t, a))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

// writeSubscriptionFile stages a private subscription document on disk.
func writeSubscriptionFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(privateTempDir(t), "sub.yaml")
	if err := platform.AtomicWrite(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

// legacyOf extracts the legacy payload of a bridged envelope.
func legacyOf(t *testing.T, envelope platform.Envelope) map[string]any {
	t.Helper()
	legacy, ok := envelope.Data["legacy"].(map[string]any)
	if !ok {
		t.Fatalf("missing legacy payload: %v", envelope.Data)
	}
	return legacy
}

func TestLinuxGuidedSubscriptionInputAndApply(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("user-scope mutation gate refuses root")
	}
	a, configPath := subscriptionScope(t, linuxFreshConfig, "/usr/bin/true")
	subscription := writeSubscriptionFile(t, linuxNodeSubscription)

	envelope, err := SubscriptionInput(context.Background(), a, subscription, "file", "simple")
	if err != nil {
		t.Fatal(err)
	}
	if envelope.Overall != "PASS" {
		t.Fatalf("overall = %s errors = %v", envelope.Overall, envelope.Errors)
	}
	legacy := legacyOf(t, envelope)
	if legacy["guided"] != true {
		t.Fatalf("guided = %v", legacy["guided"])
	}
	if legacy["policy"] != "provider" || legacy["requested_policy"] != "provider" {
		t.Fatalf("policy = %v/%v", legacy["policy"], legacy["requested_policy"])
	}
	if legacy["nodes"] != 2 || legacy["added"] != 2 || legacy["replaced"] != 0 {
		t.Fatalf("counts = %v", legacy)
	}
	if legacy["rules"] != 1 || legacy["groups"] != 1 {
		t.Fatalf("preset shape = %v", legacy)
	}
	identifier, _ := legacy["id"].(string)
	digest, _ := legacy["sha256"].(string)
	if len(identifier) != 32 || len(digest) != 64 {
		t.Fatalf("id/sha256 = %q/%q", identifier, digest)
	}

	// The staged candidate and plan carry the guided preset.
	root := stagedRoot(t, a)
	candidate, err := platform.ReadPrivate(filepath.Join(root, identifier+".candidate.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(candidate)
	for _, want := range []string{"name: Proxy", "type: select", "MATCH,Proxy", "external-controller: 127.0.0.1:19090"} {
		if !strings.Contains(text, want) {
			t.Fatalf("candidate missing %q:\n%s", want, text)
		}
	}
	planRaw, err := platform.ReadPrivate(filepath.Join(root, identifier+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var plan map[string]any
	if err := json.Unmarshal(planRaw, &plan); err != nil {
		t.Fatal(err)
	}
	absolute, _ := filepath.Abs(configPath)
	if plan["schema"] != float64(1) || plan["id"] != identifier || plan["config"] != absolute ||
		plan["candidate_sha256"] != digest || plan["policy"] != "provider" || plan["nodes"] != float64(2) {
		t.Fatalf("plan = %v", plan)
	}
	if plan["original_sha256"] != hashSHA256([]byte(linuxFreshConfig)) {
		t.Fatalf("plan original digest = %v", plan["original_sha256"])
	}

	// Apply through the full CLI path: mutation gate, digest checks, atomic
	// write, receipt, cleanup.
	applied := RunRequest(t, a, []string{"subscription", "apply"}, map[string]string{"sha256": digest}, identifier)
	if applied.Overall != "PASS" {
		t.Fatalf("apply overall = %s errors = %v", applied.Overall, applied.Errors)
	}
	appliedLegacy := legacyOf(t, applied)
	if appliedLegacy["state"] != "restart-required" || appliedLegacy["sha256"] != digest {
		t.Fatalf("apply payload = %v", appliedLegacy)
	}
	committed, err := platform.ReadPrivate(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if hashSHA256(committed) != digest {
		t.Fatal("committed configuration does not match the reviewed digest")
	}
	receipt, err := platform.ReadPrivate(configPath + ".userctl-state.json")
	if err != nil || !strings.Contains(string(receipt), "restart-required") {
		t.Fatalf("receipt = %q err = %v", receipt, err)
	}
	if files := stagedFiles(t, a); len(files) != 0 {
		t.Fatalf("staged artifacts survived apply: %v", files)
	}

	// Discarding an applied preview is a no-op that still succeeds.
	discard, err := SubscriptionDiscard(context.Background(), a, identifier)
	if err != nil || discard.Overall != "PASS" {
		t.Fatalf("discard overall = %s err = %v errors = %v", discard.Overall, err, discard.Errors)
	}
}

func TestLinuxSubscriptionPreservesRoutingOnNodesMerge(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("user-scope mutation gate refuses root")
	}
	a, configPath := subscriptionScope(t, linuxRoutedConfig, "/usr/bin/true")
	subscription := writeSubscriptionFile(t, "proxies:\n  - name: new\n    type: ss\n    password: pw\n")

	envelope, err := SubscriptionInput(context.Background(), a, subscription, "file", "simple")
	if err != nil {
		t.Fatal(err)
	}
	if envelope.Overall != "PASS" {
		t.Fatalf("overall = %s errors = %v", envelope.Overall, envelope.Errors)
	}
	legacy := legacyOf(t, envelope)
	// An existing routing setup never takes the guided path.
	if legacy["guided"] != false {
		t.Fatalf("guided = %v", legacy["guided"])
	}
	if legacy["policy"] != "nodes" {
		t.Fatalf("policy = %v", legacy["policy"])
	}
	if legacy["replaced"] != 0 || legacy["added"] != 1 {
		t.Fatalf("counts = %v", legacy)
	}
	identifier, _ := legacy["id"].(string)
	digest, _ := legacy["sha256"].(string)

	applied := RunRequest(t, a, []string{"subscription", "apply"}, map[string]string{"sha256": digest}, identifier)
	if applied.Overall != "PASS" {
		t.Fatalf("apply overall = %s errors = %v", applied.Overall, applied.Errors)
	}
	committed, err := platform.ReadPrivate(configPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(committed)
	// The routing policy is preserved verbatim; only the node list grew.
	for _, want := range []string{"name: old", "name: new", "name: P", "type: select", "MATCH,P"} {
		if !strings.Contains(text, want) {
			t.Fatalf("committed config missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "MATCH,Proxy") {
		t.Fatalf("guided preset leaked into a preserved-routing merge:\n%s", text)
	}
}

func TestLinuxGuidedRefusesAdvancedRouting(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("user-scope mutation gate refuses root")
	}
	a, configPath := subscriptionScope(t, linuxRoutedConfig, "/usr/bin/true")
	providerFile := filepath.Join(a.Scope.CoreHome(), "providers", "p1.yaml")
	if err := platform.AtomicWrite(providerFile, []byte("proxies:\n  - name: pv\n    type: ss\n"), 0600); err != nil {
		t.Fatal(err)
	}
	manager, err := loadCoreManager(a)
	if err != nil {
		t.Fatal(err)
	}
	subs := newSubscriptions(a, manager, configPath, "", nil)
	// The guided check is a race guard inside the lock: a configuration that
	// drifted after the caller's guided decision must be refused.
	_, err = subs.previewRaw(context.Background(), []byte(linuxNodeSubscription), "provider", "provider", true)
	mustCode(t, err, "existing-routing-preserved-use-advanced")
	if files := stagedFiles(t, a); len(files) != 0 {
		t.Fatalf("refused preview left artifacts: %v", files)
	}
}

func TestLinuxSubscriptionStaleRefusal(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("user-scope mutation gate refuses root")
	}
	a, configPath := subscriptionScope(t, linuxFreshConfig, "/usr/bin/true")
	subscription := writeSubscriptionFile(t, linuxNodeSubscription)
	envelope, err := SubscriptionInput(context.Background(), a, subscription, "file", "simple")
	if err != nil {
		t.Fatal(err)
	}
	legacy := legacyOf(t, envelope)
	identifier := legacy["id"].(string)
	digest := legacy["sha256"].(string)

	// The configuration drifts between preview and apply.
	drifted := linuxFreshConfig + "# drift\n"
	if err := platform.AtomicWrite(configPath, []byte(drifted), 0600); err != nil {
		t.Fatal(err)
	}
	stale := RunRequest(t, a, []string{"subscription", "apply"}, map[string]string{"sha256": digest}, identifier)
	if stale.Overall != "FAIL" || stale.Errors[0].Code != "subscription-config-changed" {
		t.Fatalf("stale apply = %s %v", stale.Overall, stale.Errors)
	}
	current, err := platform.ReadPrivate(configPath)
	if err != nil || string(current) != drifted {
		t.Fatalf("stale apply touched the configuration: %q", current)
	}
	// The staged plan survives a refusal so the operator can retry.
	if files := stagedFiles(t, a); len(files) != 2 {
		t.Fatalf("refused apply lost staged artifacts: %v", files)
	}

	// A tampered digest is refused the same way.
	tampered := RunRequest(t, a, []string{"subscription", "apply"}, map[string]string{"sha256": strings.Repeat("0", 64)}, identifier)
	if tampered.Overall != "FAIL" || tampered.Errors[0].Code != "subscription-candidate-changed" {
		t.Fatalf("tampered apply = %s %v", tampered.Overall, tampered.Errors)
	}
}

func TestLinuxSubscriptionValidationRollbackAndRecovery(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("user-scope mutation gate refuses root")
	}
	subscription := writeSubscriptionFile(t, linuxNodeSubscription)

	// A failing validator blocks the preview itself and leaves no artifacts.
	a, _ := subscriptionScope(t, linuxFreshConfig, "/usr/bin/false")
	envelope, err := SubscriptionInput(context.Background(), a, subscription, "file", "simple")
	if err != nil {
		t.Fatal(err)
	}
	if envelope.Overall != "UNVERIFIED" || envelope.Errors[0].Code != "core-config-invalid" {
		t.Fatalf("failing validation = %s %v", envelope.Overall, envelope.Errors)
	}
	if files := stagedFiles(t, a); len(files) != 0 {
		t.Fatalf("failed preview left artifacts: %v", files)
	}

	// A preview staged with a passing validator can still fail at apply time
	// when the validator breaks: the configuration must stay untouched and the
	// staged plan must survive for a retry after recovery.
	a, configPath := subscriptionScope(t, linuxFreshConfig, "/usr/bin/true")
	envelope, err = SubscriptionInput(context.Background(), a, subscription, "file", "simple")
	if err != nil {
		t.Fatal(err)
	}
	legacy := legacyOf(t, envelope)
	identifier := legacy["id"].(string)
	digest := legacy["sha256"].(string)
	beforeApply, err := platform.ReadPrivate(configPath)
	if err != nil {
		t.Fatal(err)
	}

	broken := "version: 1\ncore:\n  binary: /usr/bin/false\n  config: " + configPath + "\n  backend: process\n"
	if err := platform.AtomicWrite(a.Scope.ManagerPath(), []byte(broken), 0600); err != nil {
		t.Fatal(err)
	}
	failed := RunRequest(t, a, []string{"subscription", "apply"}, map[string]string{"sha256": digest}, identifier)
	if failed.Overall != "UNVERIFIED" || failed.Errors[0].Code != "core-config-invalid" {
		t.Fatalf("apply with broken validator = %s %v", failed.Overall, failed.Errors)
	}
	afterFailure, err := platform.ReadPrivate(configPath)
	if err != nil || string(afterFailure) != string(beforeApply) {
		t.Fatalf("failed apply modified the configuration:\n%s", afterFailure)
	}
	if files := stagedFiles(t, a); len(files) != 2 {
		t.Fatalf("failed apply lost staged artifacts: %v", files)
	}

	// Recovery: once validation passes again the same plan commits.
	recovered := "version: 1\ncore:\n  binary: /usr/bin/true\n  config: " + configPath + "\n  backend: process\n"
	if err := platform.AtomicWrite(a.Scope.ManagerPath(), []byte(recovered), 0600); err != nil {
		t.Fatal(err)
	}
	retry := RunRequest(t, a, []string{"subscription", "apply"}, map[string]string{"sha256": digest}, identifier)
	if retry.Overall != "PASS" {
		t.Fatalf("recovery apply = %s %v", retry.Overall, retry.Errors)
	}
	committed, err := platform.ReadPrivate(configPath)
	if err != nil || hashSHA256(committed) != digest {
		t.Fatal("recovered apply did not commit the reviewed candidate")
	}
}

func TestLinuxSubscriptionDiscard(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("user-scope mutation gate refuses root")
	}
	a, _ := subscriptionScope(t, linuxFreshConfig, "/usr/bin/true")
	subscription := writeSubscriptionFile(t, linuxNodeSubscription)
	envelope, err := SubscriptionInput(context.Background(), a, subscription, "file", "simple")
	if err != nil {
		t.Fatal(err)
	}
	legacy := legacyOf(t, envelope)
	identifier := legacy["id"].(string)

	discard, err := SubscriptionDiscard(context.Background(), a, identifier)
	if err != nil || discard.Overall != "PASS" {
		t.Fatalf("discard = %s err = %v errors = %v", discard.Overall, err, discard.Errors)
	}
	if payload := legacyOf(t, discard); payload["state"] != "discarded" || payload["id"] != identifier {
		t.Fatalf("discard payload = %v", payload)
	}
	if files := stagedFiles(t, a); len(files) != 0 {
		t.Fatalf("discard left artifacts: %v", files)
	}
	// Discarding twice mirrors unlink(missing_ok=True).
	if again, err := SubscriptionDiscard(context.Background(), a, identifier); err != nil || again.Overall != "PASS" {
		t.Fatalf("second discard = %s err = %v errors = %v", again.Overall, err, again.Errors)
	}
	invalid, err := SubscriptionDiscard(context.Background(), a, "not-an-id")
	if err != nil {
		t.Fatal(err)
	}
	if invalid.Overall != "UNVERIFIED" || invalid.Errors[0].Code != "subscription-plan-invalid" {
		t.Fatalf("invalid discard = %s %v", invalid.Overall, invalid.Errors)
	}
}

func TestLinuxSubscriptionInputCancellation(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("user-scope mutation gate refuses root")
	}
	a, _ := subscriptionScope(t, linuxFreshConfig, "/usr/bin/true")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	envelope, err := SubscriptionInput(ctx, a, "https://example.com/subscription", "url", "simple")
	if err != nil {
		t.Fatal(err)
	}
	if envelope.Overall != "UNVERIFIED" || envelope.Errors[0].Code != "subscription-download-cancelled" {
		t.Fatalf("cancelled input = %s %v", envelope.Overall, envelope.Errors)
	}
	// A cancelled download must never stage anything.
	if files := stagedFiles(t, a); len(files) != 0 {
		t.Fatalf("cancelled download staged artifacts: %v", files)
	}
}

func TestLinuxSubscriptionInputFileRefusals(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("user-scope mutation gate refuses root")
	}
	a, _ := subscriptionScope(t, linuxFreshConfig, "/usr/bin/true")

	missing, err := SubscriptionInput(context.Background(), a, filepath.Join(privateTempDir(t), "absent.yaml"), "file", "simple")
	if err != nil {
		t.Fatal(err)
	}
	if missing.Overall == "PASS" {
		t.Fatalf("absent file accepted: %v", missing.Errors)
	}

	oversized := filepath.Join(privateTempDir(t), "huge.yaml")
	if err := platform.AtomicWrite(oversized, []byte("proxies: ["+strings.Repeat("a,", limit/2+10)+"x]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(oversized)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() <= limit {
		t.Skipf("could not build an oversized document (limit=%d)", limit)
	}
	tooBig, err := SubscriptionInput(context.Background(), a, oversized, "file", "simple")
	if err != nil {
		t.Fatal(err)
	}
	if tooBig.Overall != "UNVERIFIED" || tooBig.Errors[0].Code != "subscription-size-invalid" {
		t.Fatalf("oversized file = %s %v", tooBig.Overall, tooBig.Errors)
	}

	// A non-https URL is refused before any connection is attempted.
	badURL, err := SubscriptionInput(context.Background(), a, "http://example.com/sub", "url", "simple")
	if err != nil {
		t.Fatal(err)
	}
	if badURL.Overall != "FAIL" || badURL.Errors[0].Code != "subscription-requires-https-url-without-userinfo" {
		t.Fatalf("http url = %s %v", badURL.Overall, badURL.Errors)
	}
}

// TestLinuxRuntimeStateCompatibility proves the routing ownership proof reads
// exactly the state document the runtime core writes.
func TestLinuxRuntimeStateCompatibility(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	a, configPath := subscriptionScope(t, linuxFreshConfig, exe)

	// Build the document with runtimecore's field names and shapes.
	self, err := inspectGoIdentity(os.Getpid())
	if err != nil {
		t.Skipf("kernel identity unavailable: %v", err)
	}
	state := map[string]any{
		"version":   1,
		"namespace": "mihomoctl-go",
		"scope":     "user",
		"config":    configPath,
		"home":      a.Scope.CoreHome(),
		"identity": map[string]any{
			"pid":        self.PID,
			"uid":        self.UID,
			"start_time": self.Start,
			"boot_id":    self.Boot,
			"exe":        self.Exe,
			"argv":       self.Args,
		},
	}
	if err := platform.WriteJSON(a.Scope.RuntimeState(), state); err != nil {
		t.Fatal(err)
	}

	owner := newRuntimeOwner(a, map[string]any{"core": map[string]any{
		"binary": self.Exe, "config": configPath, "backend": "process",
	}})
	if owner == nil {
		t.Fatal("newRuntimeOwner rejected the runtimecore document")
	}
	id, err := owner.runningIdentity(context.Background())
	if err != nil {
		t.Fatalf("runningIdentity rejected the runtimecore document: %v", err)
	}
	if id.PID != self.PID || id.Exe != self.Exe || !equalStringSlices(id.Args, self.Args) {
		t.Fatalf("identity = %+v want %+v", id, self)
	}

	// A foreign namespace is refused: only the managed runtime counts.
	foreign := map[string]any{
		"version": 1, "namespace": "something-else", "scope": "user",
		"config": configPath, "home": a.Scope.CoreHome(),
		"identity": state["identity"],
	}
	if err := platform.WriteJSON(a.Scope.RuntimeState(), foreign); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.runningIdentity(context.Background()); err == nil {
		t.Fatal("foreign namespace accepted")
	}
}

// TestLinuxSubscriptionRealCoreValidation exercises the full preview/apply
// against a real managed core binary when one is provided.
func TestLinuxSubscriptionRealCoreValidation(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("user-scope mutation gate refuses root")
	}
	binary := os.Getenv("MIHOMOCTL_GO_TEST_CORE")
	if binary == "" {
		t.Skip("set MIHOMOCTL_GO_TEST_CORE to a managed core binary for real validation")
	}
	if _, err := os.Stat(binary); err != nil {
		t.Skipf("configured core unavailable: %v", err)
	}
	a, configPath := subscriptionScope(t, linuxFreshConfig, binary)
	// Real-core nodes need complete proxy payloads (cipher, server, port);
	// the fake /usr/bin/true validator accepted the minimal form.
	subscription := writeSubscriptionFile(t,
		"proxies:\n"+
			"  - name: a\n    type: ss\n    cipher: aes-128-gcm\n    password: pw\n    server: 127.0.0.1\n    port: 8388\n"+
			"  - name: b\n    type: ss\n    cipher: aes-128-gcm\n    password: pw\n    server: 127.0.0.1\n    port: 8389\n")
	envelope, err := SubscriptionInput(context.Background(), a, subscription, "file", "simple")
	if err != nil {
		t.Fatal(err)
	}
	if envelope.Overall != "PASS" {
		t.Fatalf("real-core preview = %s %v", envelope.Overall, envelope.Errors)
	}
	legacy := legacyOf(t, envelope)
	identifier := legacy["id"].(string)
	digest := legacy["sha256"].(string)
	applied := RunRequest(t, a, []string{"subscription", "apply"}, map[string]string{"sha256": digest}, identifier)
	if applied.Overall != "PASS" {
		t.Fatalf("real-core apply = %s %v", applied.Overall, applied.Errors)
	}
	committed, err := platform.ReadPrivate(configPath)
	if err != nil || hashSHA256(committed) != digest {
		t.Fatal("real-core apply did not commit the reviewed candidate")
	}
}
