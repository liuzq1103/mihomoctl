//go:build linux

package command_test

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/liuzq1103/mihomoctl/internal/command"
	"github.com/liuzq1103/mihomoctl/internal/delivery"
	"github.com/liuzq1103/mihomoctl/internal/platform"
)

func dryRunScope(t *testing.T) (string, platform.Scope) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("public user-scope mutation fixture requires a non-root UID")
	}
	base := t.TempDir()
	for key, leaf := range map[string]string{
		"XDG_CONFIG_HOME": "config", "XDG_DATA_HOME": "data", "XDG_STATE_HOME": "state",
		"XDG_CACHE_HOME": "cache", "XDG_RUNTIME_DIR": "run",
	} {
		t.Setenv(key, filepath.Join(base, leaf))
	}
	s, err := platform.NewScope(false)
	if err != nil {
		t.Fatal(err)
	}
	return base, s
}

func dryRunSource(t *testing.T, base string) string {
	t.Helper()
	source := filepath.Join(base, "source")
	if err := platform.AtomicWrite(filepath.Join(source, "bin", "mihomoctl"), []byte("fixture executable\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := delivery.WriteManifest(source, delivery.Manifest{Version: delivery.Version, Kind: "basic", Arch: runtime.GOARCH}); err != nil {
		t.Fatal(err)
	}
	return source
}

type dryRunFile struct {
	Mode          fs.FileMode
	Modified      time.Time
	Device, Inode uint64
	Contents      string
}

// Snapshot every path, including directories and lock files, rather than just
// checking the launcher survived. A preview must not change file identity either.
func dryRunSnapshot(t *testing.T, base string) map[string]dryRunFile {
	t.Helper()
	files := map[string]dryRunFile{}
	err := filepath.WalkDir(base, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		stat := info.Sys().(*syscall.Stat_t)
		entry := dryRunFile{Mode: info.Mode(), Modified: info.ModTime(), Device: uint64(stat.Dev), Inode: stat.Ino}
		if !d.IsDir() {
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			entry.Contents = string(b)
		}
		files[path] = entry
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func dryRunExecute(t *testing.T, argv []string) platform.Envelope {
	t.Helper()
	p, err := command.Parse(argv, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return command.Execute(ctx, p.System, p.Request)
}

func TestExecuteDryRunPreservesPendingUninstall(t *testing.T) {
	base, scope := dryRunScope(t)
	source := dryRunSource(t, base)
	bin := filepath.Join(base, "bin")
	app := platform.App{Scope: scope}
	if _, err := delivery.Bootstrap(context.Background(), app, source, bin, false); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(scope.DataRoot, "install")
	var receipt delivery.Receipt
	b, err := platform.ReadPrivate(filepath.Join(root, "receipt.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = delivery.StrictJSON(b, &receipt); err != nil {
		t.Fatal(err)
	}
	current, err := os.ReadFile(filepath.Join(root, "current"))
	if err != nil {
		t.Fatal(err)
	}
	entries := map[string]any{}
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || path == root {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		entry := map[string]any{"directory": d.IsDir()}
		if !d.IsDir() {
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			entry["sha256"] = platform.Hash(b)
		}
		entries[filepath.ToSlash(rel)] = entry
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	token, err := platform.Token()
	if err != nil {
		t.Fatal(err)
	}
	journal := filepath.Join(scope.StateRoot, "delivery-uninstall.json")
	quarantine := filepath.Join(scope.DataRoot, ".install-remove-"+token)
	// Match delivery's format-3 prepared journal, including its inode identity
	// and complete manifest/receipt inventory. No relaxed or invalid fixture.
	err = platform.WriteJSON(journal, map[string]any{
		"format": 3, "project": delivery.Project, "root": root, "receipt": receipt,
		"entries": entries, "token": token, "quarantine": quarantine, "phase": "prepared",
		"receipt_sha256": platform.Hash(b), "current_generation": strings.TrimSpace(string(current)),
		"device": uint64(stat.Dev), "inode": stat.Ino,
	})
	if err != nil {
		t.Fatal(err)
	}
	// This read validates the complete journal against the real installation.
	status, err := delivery.Run(context.Background(), app, platform.Request{Command: []string{"installation", "status"}})
	if err != nil || status.Data["status"] != "uninstalling" {
		t.Fatalf("invalid uninstall fixture: %+v, %v", status, err)
	}
	before := dryRunSnapshot(t, base)
	for _, argv := range [][]string{
		{"installation", "install", "--source", source, "--bin-dir", bin, "--dry-run"},
		{"installation", "uninstall", "--dry-run"},
		{"service", "uninstall", "--dry-run"},
	} {
		t.Run(strings.Join(argv[:2], "-"), func(t *testing.T) {
			env := dryRunExecute(t, argv)
			if env.Overall != "UNVERIFIED" || len(env.Errors) != 1 || env.Errors[0].Code != "transaction-recovery-required" {
				t.Errorf("preview must refuse pending recovery: %+v", env)
			}
			if after := dryRunSnapshot(t, base); !reflect.DeepEqual(before, after) {
				t.Fatal("dry-run changed launcher, installation tree, journal, or scope files")
			}
		})
	}
	// Prove recovery would actually remove this fixture if the public gate
	// entered WithLock. Only this explicit mutation may complete the deletion.
	env := dryRunExecute(t, []string{"installation", "recover"})
	if env.Overall != "PASS" || env.Data["status"] != "not-installed" {
		t.Fatalf("explicit recovery failed: %+v", env)
	}
	for _, path := range []string{receipt.BinPath, root, quarantine, journal} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Errorf("explicit recovery retained %s: %v", path, err)
		}
	}
}

func TestExecuteDryRunAbsentStateCreatesNoDirectoriesOrLock(t *testing.T) {
	for _, name := range []string{"installation-install", "installation-uninstall", "service-uninstall"} {
		t.Run(name, func(t *testing.T) {
			base, scope := dryRunScope(t)
			source := dryRunSource(t, base)
			argv := strings.Split(name, "-")
			argv = append(argv, "--dry-run")
			if name == "installation-install" {
				argv = append(argv, "--source", source, "--bin-dir", filepath.Join(base, "bin"))
			}
			before := dryRunSnapshot(t, base)
			env := dryRunExecute(t, argv)
			if name == "service-uninstall" {
				if len(env.Errors) != 1 || env.Errors[0].Code != "config-invalid" {
					t.Errorf("expected missing configuration without mutation: %+v", env)
				}
			} else if env.Overall != "PASS" || env.Data["dry_run"] != true {
				t.Errorf("expected successful installation preview: %+v", env)
			}
			if after := dryRunSnapshot(t, base); !reflect.DeepEqual(before, after) {
				t.Error("absent-state dry-run changed the filesystem")
			}
			for _, path := range []string{scope.ConfigRoot, scope.DataRoot, scope.StateRoot, scope.CacheRoot, scope.RuntimeRoot, filepath.Join(scope.RuntimeRoot, "manager.lock"), filepath.Join(base, "bin")} {
				if _, err := os.Lstat(path); !os.IsNotExist(err) {
					t.Errorf("preview created %s: %v", path, err)
				}
			}
		})
	}
}
