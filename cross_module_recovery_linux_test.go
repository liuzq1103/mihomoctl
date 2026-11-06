//go:build linux

package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/liuzq1103/mihomoctl/internal/command"
	"github.com/liuzq1103/mihomoctl/internal/platform"
)

const rootRegressionToken = "root-regression-controller-" + "0123456789abcdef0123456789abcdef"
const rootRegressionPassword = "root-regression-profile-password"

type rootRegressionFixture struct {
	App                         platform.App
	ConfigPath, CredentialsPath string
	Config, Manager             map[string]any
}

func rootRegressionNonRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("requires a non-root Linux account; never exercise system scope")
	}
}

func newRootRegressionFixture(t *testing.T, controllerPort int) *rootRegressionFixture {
	t.Helper()
	rootRegressionNonRoot(t)
	// Core trust checks inspect every ancestor. /tmp is world writable, so put
	// the owned executable fixture below the acting account's real home.
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.MkdirTemp(home, ".mihomoctl-go-root-regression-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(root); err != nil {
			t.Error(err)
		}
	})
	for key, leaf := range map[string]string{
		"XDG_CONFIG_HOME": "config", "XDG_DATA_HOME": "data", "XDG_STATE_HOME": "state",
		"XDG_CACHE_HOME": "cache", "XDG_RUNTIME_DIR": "run",
	} {
		t.Setenv(key, filepath.Join(root, leaf))
	}
	scope, err := platform.NewScope(false)
	if err != nil {
		t.Fatal(err)
	}
	exe, err := os.Readlink("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	f := &rootRegressionFixture{App: platform.App{Scope: scope},
		ConfigPath:      filepath.Join(scope.ConfigRoot, "mihomo", "config.yaml"),
		CredentialsPath: filepath.Join(scope.ConfigRoot, "credentials", "default.yaml")}
	proxyPort := 18789
	if proxyPort == controllerPort {
		proxyPort++
	}
	f.Config = map[string]any{
		"mode": "rule", "external-controller": fmt.Sprintf("127.0.0.1:%d", controllerPort), "secret": rootRegressionToken,
		"listeners": []any{map[string]any{"name": "proxy", "type": "mixed", "listen": "127.0.0.1", "port": proxyPort,
			"users": []any{map[string]any{"username": "fixture-user", "password": rootRegressionPassword}}}},
		"rules": []string{"MATCH,DIRECT"}, "profile": map[string]any{"store-selected": false},
	}
	f.Manager = map[string]any{
		"version": 1, "core": map[string]any{"binary": exe, "config": f.ConfigPath, "backend": "process"},
		"default_profile": "default", "profiles": map[string]any{"default": map[string]any{
			"http_listener": "proxy", "socks_listener": "proxy", "credentials_file": f.CredentialsPath,
		}},
	}
	if err := platform.WriteYAML(f.CredentialsPath, map[string]any{"username": "fixture-user", "password": rootRegressionPassword}); err != nil {
		t.Fatal(err)
	}
	f.writeConfig(t)
	f.writeManager(t)
	return f
}

func (f *rootRegressionFixture) writeConfig(t *testing.T) {
	t.Helper()
	if err := platform.WriteYAML(f.ConfigPath, f.Config); err != nil {
		t.Fatal(err)
	}
}

func (f *rootRegressionFixture) writeManager(t *testing.T) {
	t.Helper()
	if err := platform.WriteYAML(f.App.Scope.ManagerPath(), f.Manager); err != nil {
		t.Fatal(err)
	}
}

func rootRegressionRead(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := platform.ReadPrivate(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func rootRegressionWrite(t *testing.T, path string, raw []byte) {
	t.Helper()
	if err := platform.AtomicWrite(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
}

func rootRoutingCrash(t *testing.T, f *rootRegressionFixture, before, after []byte) string {
	t.Helper()
	id := "root-cross-module-0123456789ab"
	dir := filepath.Join(f.App.Scope.StateRoot, "backups", id)
	backup := filepath.Join(dir, "0-config.yaml")
	staging := filepath.Join(f.App.Scope.StateRoot, "staging", id+"-fixture")
	if err := platform.PrivateDir(staging); err != nil {
		t.Fatal(err)
	}
	rootRegressionWrite(t, backup, before)
	journal := filepath.Join(dir, "journal.json")
	if err := platform.WriteJSON(journal, map[string]any{
		"id": id, "name": "root-cross-module", "state": "pending", "staging": staging,
		"journal": []any{map[string]any{
			"op": "publish", "path": f.ConfigPath, "type": "file", "mode": "0600",
			"uid": os.Geteuid(), "gid": os.Getegid(), "backup": backup, "existed": true,
			"published_sha256": platform.Hash(after),
		}},
	}); err != nil {
		t.Fatal(err)
	}
	rootRegressionWrite(t, f.ConfigPath, after)
	return journal
}

func rootRuntimeCrash(t *testing.T, f *rootRegressionFixture, before, after []byte) string {
	t.Helper()
	journal := filepath.Join(f.App.Scope.StateRoot, "transaction.json")
	// []byte deliberately encodes as base64, matching runtimecore.fileSnapshot.
	if err := platform.WriteJSON(journal, map[string]any{"Version": 1, "Files": []any{map[string]any{
		"Path": f.ConfigPath, "Before": before, "After": after, "Existed": true, "Delete": false,
	}}}); err != nil {
		t.Fatal(err)
	}
	rootRegressionWrite(t, f.ConfigPath, after)
	return journal
}

func rootRecoveryReadBlocked(t *testing.T, f *rootRegressionFixture, journals ...string) {
	t.Helper()
	snapshot := rootRegressionRead(t, f.ConfigPath)
	saved := make(map[string][]byte)
	for _, path := range journals {
		saved[path] = rootRegressionRead(t, path)
	}
	env := command.Execute(context.Background(), false, platform.Request{Command: []string{"status"}})
	if env.Overall != "UNVERIFIED" || len(env.Errors) != 1 || env.Errors[0].Code != "transaction-recovery-required" || len(env.Data) != 0 {
		t.Fatalf("status exposed uncommitted configuration: %+v", env)
	}
	if !bytes.Equal(rootRegressionRead(t, f.ConfigPath), snapshot) {
		t.Fatal("read-only status recovered or changed the uncommitted config")
	}
	for path, raw := range saved {
		if !bytes.Equal(rootRegressionRead(t, path), raw) {
			t.Fatal("read-only status altered the recovery journal")
		}
	}
}

func rootRecoveryClean(t *testing.T, f *rootRegressionFixture, journals ...string) {
	t.Helper()
	if err := platform.CheckPending(f.App.Scope); err != nil {
		t.Fatal("recovery remains pending:", err)
	}
	for _, path := range journals {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("replayed journal still exists: %s (%v)", path, err)
		}
	}
	info, err := os.Stat(f.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(owner.Uid) != os.Geteuid() || info.Mode().Perm() != 0600 {
		t.Fatal("recovery lost private ownership or 0600 permissions")
	}
}

func rootRegressionPatch(t *testing.T, raw []byte, mode string) []byte {
	t.Helper()
	result, err := platform.PatchYAML(raw, map[string]any{"mode": mode})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func rootRegressionShellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}

// The owned core never launches a daemon: validation records which config was
// visible and can deliberately refuse -t after proving recovery happened.
func rootRecoveryValidator(t *testing.T, f *rootRegressionFixture, expected []byte, reject bool, journals ...string) string {
	t.Helper()
	expectedPath := filepath.Join(f.App.Scope.DataRoot, "expected-config.yaml")
	marker := filepath.Join(f.App.Scope.DataRoot, "validation-observed-recovery")
	rootRegressionWrite(t, expectedPath, expected)
	text := "#!/bin/sh\numask 077\n[ \"$1\" = '-t' ] || exit 94\n"
	for _, path := range journals {
		text += "[ ! -e " + rootRegressionShellQuote(path) + " ] || exit 95\n"
	}
	text += "cmp -s " + rootRegressionShellQuote(f.ConfigPath) + " " + rootRegressionShellQuote(expectedPath) + " || exit 96\n"
	text += "printf 'recovered-before-validation\\n' > " + rootRegressionShellQuote(marker) + "\n"
	if reject {
		text += "exit 97\n"
	} else {
		text += "exit 0\n"
	}
	binary := filepath.Join(f.App.Scope.DataRoot, "owned-validation-core")
	if err := platform.AtomicWrite(binary, []byte(text), 0700); err != nil {
		t.Fatal(err)
	}
	platform.Map(f.Manager["core"])["binary"] = binary
	f.writeManager(t)
	return marker
}

func TestCrossModuleRoutingRecoveryBeforeRuntimeStart(t *testing.T) {
	f := newRootRegressionFixture(t, 19090)
	original := rootRegressionRead(t, f.ConfigPath)
	after := rootRegressionPatch(t, original, "global")
	journal := rootRoutingCrash(t, f, original, after)
	marker := rootRecoveryValidator(t, f, original, true, journal)
	rootRecoveryReadBlocked(t, f, journal)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	env := command.Execute(ctx, false, platform.Request{Command: []string{"start"}})
	if env.Overall != "FAIL" || len(env.Errors) != 1 || env.Errors[0].Code != "core-config-invalid" {
		t.Fatalf("runtime did not reach the intentional validation refusal: %+v", env)
	}
	if string(rootRegressionRead(t, marker)) != "recovered-before-validation\n" {
		t.Fatal("runtime validation observed uncommitted routing state")
	}
	if !bytes.Equal(rootRegressionRead(t, f.ConfigPath), original) {
		t.Fatal("runtime mutation failed to restore the abandoned routing edit")
	}
	rootRecoveryClean(t, f, journal)
	if _, err := os.Lstat(f.App.Scope.RuntimeState()); !os.IsNotExist(err) {
		t.Fatal("the refusing validator unexpectedly launched a runtime")
	}
}

func TestCrossModuleRuntimeRecoveryBeforeRoutingMutation(t *testing.T) {
	f := newRootRegressionFixture(t, 19090)
	original := rootRegressionRead(t, f.ConfigPath)
	after := rootRegressionPatch(t, original, "global")
	journal := rootRuntimeCrash(t, f, original, after)
	marker := rootRecoveryValidator(t, f, original, false, journal)
	rootRecoveryReadBlocked(t, f, journal)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	env := command.Execute(ctx, false, platform.Request{Command: []string{"controller", "initialize"}})
	if string(rootRegressionRead(t, marker)) != "recovered-before-validation\n" {
		t.Fatal("routing validation did not observe recovered runtime state")
	}
	rootRecoveryClean(t, f, journal)
	if env.Overall != "PASS" {
		t.Fatalf("runtime recovery completed, but routing used a candidate read before recovery: %+v", env)
	}
	config, err := platform.ReadYAML(f.ConfigPath, true)
	if err != nil {
		t.Fatal(err)
	}
	if platform.String(config["mode"]) != "rule" || !platform.Bool(platform.Map(config["profile"])["store-selected"]) {
		t.Fatal("routing committed a candidate derived from uncommitted runtime state")
	}
}

func TestCrossModuleSharedLockRecoversRoutingThenRuntime(t *testing.T) {
	f := newRootRegressionFixture(t, 19090)
	original := rootRegressionRead(t, f.ConfigPath)
	runtimeAfter := rootRegressionPatch(t, original, "global")
	routingAfter := rootRegressionPatch(t, original, "direct")
	runtimeJournal := rootRuntimeCrash(t, f, original, runtimeAfter)
	routingJournal := rootRoutingCrash(t, f, runtimeAfter, routingAfter)
	rootRecoveryReadBlocked(t, f, routingJournal, runtimeJournal)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	called := false
	err := platform.WithLock(ctx, f.App.Scope, func() error {
		called = true
		// Runtime's expected After is routing's Before. Reversing hook order
		// therefore conflicts rather than accidentally yielding a passing test.
		if !bytes.Equal(rootRegressionRead(t, f.ConfigPath), original) {
			return fmt.Errorf("mutation callback saw uncommitted bytes")
		}
		if err := platform.CheckPending(f.App.Scope); err != nil {
			return err
		}
		fd, err := syscall.Open(filepath.Join(f.App.Scope.RuntimeRoot, "manager.lock"), syscall.O_RDWR|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		defer syscall.Close(fd)
		err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			syscall.Flock(fd, syscall.LOCK_UN)
			return fmt.Errorf("mutation callback ran without the shared kernel lock")
		}
		if err != syscall.EWOULDBLOCK && err != syscall.EAGAIN {
			return err
		}
		return nil
	})
	if err != nil || !called {
		t.Fatalf("shared recovery did not precede the locked mutation: callback=%v err=%v", called, err)
	}
	rootRecoveryClean(t, f, routingJournal, runtimeJournal)
}
