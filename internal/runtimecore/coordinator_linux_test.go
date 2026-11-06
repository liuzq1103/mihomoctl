//go:build linux

package runtimecore_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/liuzq1103/mihomoctl/internal/command"
	"github.com/liuzq1103/mihomoctl/internal/platform"
	"github.com/liuzq1103/mihomoctl/internal/runtimecore"
)

func coordinatorApp(t *testing.T) platform.App {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("user-scope command coordinator requires non-root")
	}
	home, e := os.UserHomeDir()
	if e != nil {
		t.Fatal(e)
	}
	root, e := os.MkdirTemp(home, ".mihomoctl-go-coordinator-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	for key, leaf := range map[string]string{"XDG_CONFIG_HOME": "config", "XDG_DATA_HOME": "data", "XDG_STATE_HOME": "state", "XDG_CACHE_HOME": "cache", "XDG_RUNTIME_DIR": "run"} {
		t.Setenv(key, filepath.Join(root, leaf))
	}
	s, e := platform.NewScope(false)
	if e != nil {
		t.Fatal(e)
	}
	a := platform.App{Scope: s}
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(exe)
	if e != nil {
		t.Fatal(e)
	}
	binary := filepath.Join(root, "core")
	if e = platform.AtomicWrite(binary, raw, 0700); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	doc, e := runtimecore.Run(ctx, a, platform.Request{Command: []string{"init"}, Options: map[string][]string{"core": {binary}}})
	if e != nil || doc.Overall != "PASS" {
		t.Fatal(doc, e)
	}
	return a
}
func runtimeCoordinatorJournal(t *testing.T, a platform.App, path string, before, after []byte) {
	t.Helper()
	if e := platform.WriteJSON(filepath.Join(a.Scope.StateRoot, "transaction.json"), map[string]any{"Version": 1, "Files": []any{map[string]any{"Path": path, "Before": before, "After": after, "Existed": true, "Delete": false}}}); e != nil {
		t.Fatal(e)
	}
}
func routingCoordinatorJournal(t *testing.T, a platform.App, path string, before, after []byte) (string, string) {
	t.Helper()
	// Follow beginFileTransaction exactly: the journal name is the ID label,
	// its random suffix is six bytes encoded as twelve lowercase hex digits,
	// and MkdirTemp creates a direct staging child prefixed with that full ID.
	name := "coordinator-routing-before-runtime"
	random := make([]byte, 6)
	if _, e := rand.Read(random); e != nil {
		t.Fatal(e)
	}
	id := name + "-" + hex.EncodeToString(random)
	dir := filepath.Join(a.Scope.StateRoot, "backups", id)
	backup := filepath.Join(dir, "0-"+filepath.Base(path))
	stagingRoot := filepath.Join(a.Scope.StateRoot, "staging")
	if e := platform.PrivateDir(stagingRoot); e != nil {
		t.Fatal(e)
	}
	staging, e := os.MkdirTemp(stagingRoot, id+"-")
	if e != nil {
		t.Fatal(e)
	}
	if e := platform.AtomicWrite(backup, before, 0600); e != nil {
		t.Fatal(e)
	}
	st, e := os.Stat(path)
	if e != nil {
		t.Fatal(e)
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("cannot capture routing fixture file ownership")
	}
	record := map[string]any{"op": "publish", "path": path, "type": "file", "mode": fmt.Sprintf("%o", st.Mode().Perm()), "uid": owner.Uid, "gid": owner.Gid, "backup": backup, "existed": true, "published_sha256": platform.Hash(after)}
	if e := platform.WriteJSON(filepath.Join(dir, "journal.json"), map[string]any{"id": id, "name": name, "state": "pending", "staging": staging, "journal": []any{record}}); e != nil {
		t.Fatal(e)
	}
	return dir, staging
}
func assertRecoveredMarker(t *testing.T, a platform.App, path string, want []byte) {
	t.Helper()
	got, e := platform.ReadPrivate(path)
	if e != nil || !bytes.Equal(got, want) {
		t.Fatalf("coordinator failed to restore file before handler (%v)", e)
	}
	if e = platform.CheckPending(a.Scope); e != nil {
		t.Fatal("coordinator left pending journals", e)
	}
}
func TestCommandCoordinatorRecoversRuntimeBeforeRoutingMutation(t *testing.T) {
	a := coordinatorApp(t)
	configPath, e := a.CoreConfigPath()
	if e != nil {
		t.Fatal(e)
	}
	raw, e := platform.ReadPrivate(configPath)
	if e != nil {
		t.Fatal(e)
	}
	candidate, e := platform.PatchYAML(raw, map[string]any{"profile": map[string]any{"store-selected": false}})
	if e != nil {
		t.Fatal(e)
	}
	if e = platform.AtomicWrite(configPath, candidate, 0600); e != nil {
		t.Fatal(e)
	}
	marker := filepath.Join(a.Scope.ConfigRoot, "runtime-marker")
	before, after := []byte("before-runtime"), []byte("after-runtime")
	if e = platform.AtomicWrite(marker, after, 0600); e != nil {
		t.Fatal(e)
	}
	runtimeCoordinatorJournal(t, a, marker, before, after)
	read := command.Execute(context.Background(), false, platform.Request{Command: []string{"core", "list"}})
	if read.Overall == "PASS" || len(read.Errors) == 0 || read.Errors[0].Code != "transaction-recovery-required" {
		t.Fatal("command read exposed pending runtime state", read)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	doc := command.Execute(ctx, false, platform.Request{Command: []string{"controller", "initialize"}})
	if doc.Overall != "PASS" {
		t.Fatal("routing mutation did not recover runtime first", doc)
	}
	assertRecoveredMarker(t, a, marker, before)
}
func TestCommandCoordinatorRestoresRoutingBeforeRuntimeOnSameFile(t *testing.T) {
	a := coordinatorApp(t)
	marker := filepath.Join(a.Scope.ConfigRoot, "shared-marker")
	original, runtimePublished, routingPublished := []byte("original"), []byte("runtime-published"), []byte("routing-published")
	if e := platform.AtomicWrite(marker, routingPublished, 0600); e != nil {
		t.Fatal(e)
	}
	runtimeCoordinatorJournal(t, a, marker, original, runtimePublished)
	backupDir, staging := routingCoordinatorJournal(t, a, marker, runtimePublished, routingPublished)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	doc := command.Execute(ctx, false, platform.Request{Command: []string{"profile", "set-default"}, Args: []string{"default"}})
	if doc.Overall != "PASS" {
		t.Fatal("cross-module coordinator did not honor routing-then-runtime recovery", doc)
	}
	assertRecoveredMarker(t, a, marker, original)
	for _, path := range []string{backupDir, staging} {
		if _, e := os.Lstat(path); !os.IsNotExist(e) {
			t.Fatalf("recovery did not clean its owned routing fixture directory %s: %v", path, e)
		}
	}
}
