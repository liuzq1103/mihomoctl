//go:build linux

package routing

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/liuzq1103/mihomoctl/internal/platform"
	"github.com/liuzq1103/mihomoctl/internal/runtimecore"
)

// linuxCompleteNodeSubscription is a real-core-grade subscription. The nodes
// use the core's built-in direct type so the health probes (a proxied request
// through the default group) behave exactly like the DIRECT baseline without
// needing a live upstream server in the test environment.
const linuxCompleteNodeSubscription = "proxies:\n" +
	"  - name: a\n    type: direct\n" +
	"  - name: b\n    type: direct\n"

// homeFakeCore stages a script under the real home tree that validates
// candidates (-t exits 0) but always fails to run as a core. The trusted
// executable walk refuses everything under a 1777 /tmp, so the home tree is
// the only place a test-owned fake binary is acceptable.
func homeFakeCore(t *testing.T) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil || home == "" || home == "/root" {
		t.Skipf("no user home tree for a fake core: %v", err)
	}
	directory := filepath.Join(home, ".mihomoctl-go-test")
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Skipf("home tree unwritable: %v", err)
	}
	script := filepath.Join(directory, "fake-core.sh")
	body := "#!/bin/sh\nif [ \"$1\" = \"-t\" ]; then exit 0; fi\nexit 7\n"
	if err := os.WriteFile(script, []byte(body), 0700); err != nil {
		t.Skipf("fake core unwritable: %v", err)
	}
	if err := os.Chmod(script, 0700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(script) })
	return script
}

// activationCredentials are the authenticated local-listener credentials the
// runtime core's manager model requires for every profile.
const (
	activationUser     = "unit-user"
	activationPassword = "unit-secret"
)

// activationScope builds the runtimecore-native installation shape the
// activation boundary resolves against: the managed configuration carries an
// authenticated loopback listener, and the manager's default profile binds it
// by name with matching private credentials (validateManager requires a
// listener role on every profile and resolve proves the listener exists).
// The scope lives under the real home tree, like runtimecore's own tests:
// its trust walks refuse everything under a 1777 /tmp.
func activationScope(t *testing.T, controllerPort, listenerPort int, binary string) (platform.App, string) {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil || home == "" || home == "/root" {
		t.Skipf("no user home tree for an activation scope: %v", err)
	}
	root, err := os.MkdirTemp(home, ".mihomoctl-go-routing-test-")
	if err != nil {
		t.Skipf("home tree unwritable: %v", err)
	}
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	scope := platform.Scope{
		Name:        "user",
		ConfigRoot:  filepath.Join(root, "config"),
		DataRoot:    filepath.Join(root, "data"),
		StateRoot:   filepath.Join(root, "state"),
		CacheRoot:   filepath.Join(root, "cache"),
		RuntimeRoot: filepath.Join(root, "state", "runtime"),
	}
	configPath := filepath.Join(scope.ConfigRoot, "mihomo", "config.yaml")
	credentialsPath := filepath.Join(scope.ConfigRoot, "credentials", "default.yaml")
	config := fmt.Sprintf("mode: rule\nlisteners:\n  - name: proxy\n    type: mixed\n    listen: 127.0.0.1\n    port: %d\n    users:\n      - username: %s\n        password: %s\nexternal-controller: 127.0.0.1:%d\nsecret: %s\nrules:\n  - MATCH,DIRECT\n",
		listenerPort, activationUser, activationPassword, controllerPort, fixtureToken)
	manager := "version: 1\ndefault_profile: default\nprofiles:\n  default:\n    http_listener: proxy\n    socks_listener: proxy\n    credentials_file: " + credentialsPath + "\n    no_proxy:\n      - localhost\n      - 127.0.0.1\n      - ::1\ntun:\n  enabled: false\n  device: mihomo0\ncore:\n  binary: " + binary + "\n  config: " + configPath + "\n  backend: process\n"
	credentials := "username: " + activationUser + "\npassword: " + activationPassword + "\n"
	if err := platform.AtomicWrite(configPath, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	if err := platform.AtomicWrite(scope.ManagerPath(), []byte(manager), 0600); err != nil {
		t.Fatal(err)
	}
	if err := platform.AtomicWrite(credentialsPath, []byte(credentials), 0600); err != nil {
		t.Fatal(err)
	}
	return platform.App{Scope: scope}, configPath
}

// activationOriginal re-reads the committed base configuration bytes.
func activationOriginal(t *testing.T, configPath string) string {
	t.Helper()
	raw, err := platform.ReadPrivate(configPath)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// freeLoopbackPort reserves a loopback port briefly to avoid collisions
// between concurrently staged fixtures.
func freeLoopbackPort(t *testing.T) int {
	t.Helper()
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no free loopback port: %v", err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	if err := probe.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

// TestLinuxSaveAndStartFailureRestoresConfigAndKeepsPlan proves the worst
// case of the save-and-activate boundary: the candidate validates but the
// core cannot actually run. The original files must come back byte-identical,
// the restart receipt must be gone, and the staged plan must stay on disk for
// a retry — the same contract as the original transaction rollback.
func TestLinuxSaveAndStartFailureRestoresConfigAndKeepsPlan(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("user-scope mutation gate refuses root")
	}
	fake := homeFakeCore(t)
	a, configPath := activationScope(t, 19090+os.Getpid()%1000, 18789+os.Getpid()%1000, fake)
	original := activationOriginal(t, configPath)
	subscription := writeSubscriptionFile(t, linuxCompleteNodeSubscription)

	preview, err := SubscriptionInput(context.Background(), a, subscription, "file", "simple")
	if err != nil {
		t.Fatal(err)
	}
	if preview.Overall != "PASS" {
		t.Fatalf("preview = %s %v", preview.Overall, preview.Errors)
	}
	legacy := legacyOf(t, preview)
	identifier := legacy["id"].(string)
	digest := legacy["sha256"].(string)

	saved, err := SubscriptionSaveAndStart(context.Background(), a, identifier, digest)
	if err != nil {
		t.Fatalf("SubscriptionSaveAndStart error: %v", err)
	}
	if saved.Overall == "PASS" {
		t.Fatalf("activation unexpectedly passed with a failing core: %v", saved.Data)
	}
	if raw := activationOriginal(t, configPath); raw != original {
		t.Fatalf("config changed after failed activation:\n%s", raw)
	}
	if _, err := os.Lstat(receiptPath(configPath)); !os.IsNotExist(err) {
		t.Fatal("restart receipt survived a failed activation")
	}
	// The staged plan is retained for a retry.
	planFiles := stagedFiles(t, a)
	found := false
	for _, name := range planFiles {
		if strings.HasPrefix(name, identifier+".") {
			found = true
		}
	}
	if !found {
		t.Fatalf("staged plan dropped after failed activation: %v", planFiles)
	}
	if encoded := fmt.Sprint(saved.Data); strings.Contains(encoded, fixtureToken) {
		t.Fatal("token disclosed in failure envelope")
	}
}

// TestLinuxSaveAndStartRealCore runs the full native capability against a
// real managed core: preview, durable commit, start, verified activation,
// staged-artifact cleanup, then a stop that leaves no runtime behind.
func TestLinuxSaveAndStartRealCore(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("user-scope mutation gate refuses root")
	}
	binary := os.Getenv("MIHOMOCTL_GO_TEST_CORE")
	if binary == "" {
		t.Skip("set MIHOMOCTL_GO_TEST_CORE to a managed core binary for real activation")
	}
	if _, err := os.Stat(binary); err != nil {
		t.Skipf("configured core unavailable: %v", err)
	}
	controllerPort := freeLoopbackPort(t)
	listenerPort := freeLoopbackPort(t)
	a, configPath := activationScope(t, controllerPort, listenerPort, binary)

	// Never leave a started core behind, whatever the test does next.
	stopCore := func() {
		request := platform.Request{
			Command: []string{"stop"},
			Options: map[string][]string{},
			Input:   strings.NewReader(""),
			Output:  &strings.Builder{},
			Stderr:  &strings.Builder{},
		}
		if _, err := runtimecore.Run(context.Background(), a, request); err != nil {
			t.Logf("cleanup stop: %v", err)
		}
	}
	t.Cleanup(stopCore)

	subscription := writeSubscriptionFile(t, linuxCompleteNodeSubscription)
	preview, err := SubscriptionInput(context.Background(), a, subscription, "file", "simple")
	if err != nil {
		t.Fatal(err)
	}
	if preview.Overall != "PASS" {
		t.Fatalf("preview = %s %v", preview.Overall, preview.Errors)
	}
	legacy := legacyOf(t, preview)
	identifier := legacy["id"].(string)
	digest := legacy["sha256"].(string)

	saved, err := SubscriptionSaveAndStart(context.Background(), a, identifier, digest)
	if err != nil {
		t.Fatalf("SubscriptionSaveAndStart error: %v", err)
	}
	if saved.Overall != "PASS" {
		// With MIHOMOCTL_GO_TEST_CORE set this is a real verdict, not a
		// skip: the coordinator's health-probe fix (Proxy-Connection:
		// close) removed the last known environment flake, so a failure
		// here is a routing or runtime regression and must fail the run.
		for _, failure := range saved.Errors {
			t.Logf("activation error: %+v", failure)
		}
		t.Fatalf("save-and-start against the real core did not verify: %+v", saved.Errors)
	}
	activated := legacyOf(t, saved)
	if activated["state"] != "ready" || activated["activation_state"] != "verified" ||
		activated["runtime_state"] != "running" || activated["restart_required"] != false {
		t.Fatalf("activation receipt = %v", activated)
	}
	if pid, ok := numericValue(activated["pid"]); !ok || pid <= 1 {
		t.Fatalf("activation pid = %v", activated["pid"])
	}
	committed, err := platform.ReadPrivate(configPath)
	if err != nil || hashSHA256(committed) != digest {
		t.Fatal("activated configuration is not the reviewed candidate")
	}
	if _, err := os.Lstat(receiptPath(configPath)); !os.IsNotExist(err) {
		t.Fatal("restart receipt survived a verified activation")
	}
	if files := stagedFiles(t, a); len(files) != 0 {
		t.Fatalf("staged artifacts survived activation: %v", files)
	}
}
