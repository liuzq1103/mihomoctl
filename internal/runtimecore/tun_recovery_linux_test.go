//go:build linux

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

// These exercise the real persistent recovery engine and real root-owned file
// permissions, with controlled systemd/kernel boundaries. They do not create
// accounts, services, network devices, routes, or capabilities on the host.
func TestTunCompoundRecoveryBoundary(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root-owned isolated files; no host service or network changes")
	}
	for _, restoreEnabled := range []bool{false, true} {
		name := "interrupted-enable"
		if restoreEnabled {
			name = "interrupted-disable"
		}
		t.Run(name, func(t *testing.T) {
			a, m := fixture(t)
			a.Scope.System = true
			a.Scope.Name = "system"
			m.Core.Backend = "systemd"
			m.Tun.Enabled = restoreEnabled
			binary := m.Core.Binary
			if e := platform.AtomicWrite(binary, []byte("root-owned recovery fixture"), 0700); e != nil {
				t.Fatal(e)
			}
			beforeManager, _ := marshalYAML(m)
			beforeConfig := []byte("mode: rule\ntun:\n  enable: false\n")
			if restoreEnabled {
				beforeConfig = []byte("mode: rule\ntun:\n  enable: true\n")
			}
			for path, raw := range map[string][]byte{a.Scope.ManagerPath(): beforeManager, m.Core.Config: beforeConfig} {
				if e := platform.AtomicWrite(path, raw, 0600); e != nil {
					t.Fatal(e)
				}
			}
			if restoreEnabled {
				if e := platform.WriteJSON(tunReceiptPath(a), tunReceipt{"mihomo0", 7, 0}); e != nil {
					t.Fatal(e)
				}
			}
			next := m
			next.Tun.Enabled = !restoreEnabled
			nextManager, _ := marshalYAML(next)
			operation := "tun-enable"
			if restoreEnabled {
				operation = "tun-disable"
			}
			receipt := []byte(nil)
			if !restoreEnabled {
				receipt, _ = json.Marshal(tunReceipt{"mihomo0", 8, 0})
			}
			planned := map[string][]byte{a.Scope.ManagerPath(): nextManager, m.Core.Config: []byte("mode: direct\n"), tunReceiptPath(a): receipt}
			original := &identity{PID: 123456, UID: 123, Start: "1", Boot: "previous-boot", Exe: binary, Args: []string{binary, "-d", serviceHome(a), "-f", serviceConfig(a, m)}}
			c := &compoundRecord{Version: 1, Namespace: "mihomoctl-go", Scope: a.Scope, Operation: operation, Phase: "files-published", Before: m, Next: next, Original: original, Reload: true, BinaryHash: map[string]string{binary: platform.Hash([]byte("root-owned recovery fixture"))}}
			for _, path := range sortedKeys(planned) {
				f, e := snapshotCompoundFile(a, path, planned[path])
				if e != nil {
					t.Fatal(e)
				}
				c.Files = append(c.Files, f)
			}
			if e := writeCompound(a, c); e != nil {
				t.Fatal(e)
			}
			if e := applyFiles(a, planned); e != nil {
				t.Fatal(e)
			}
			calls := []string{}
			attempts := 0
			effects := compoundRecoveryEffects{Stop: func(context.Context, platform.App, *compoundRecord) error {
				calls = append(calls, "stop-owned-service")
				return nil
			}, TunAbsent: func(context.Context, platform.App, *compoundRecord) error {
				calls = append(calls, "observe-device-absent")
				return nil
			}, Reload: func(context.Context, platform.App) error { calls = append(calls, "reload-restored-unit"); return nil }, Start: func(context.Context, platform.App) error {
				raw, e := readSystemConfig(m.Core.Config)
				if e != nil || !bytesEqual(raw, beforeConfig) {
					t.Fatal("started before original config restored", e)
				}
				calls = append(calls, "restart-original-runtime")
				attempts++
				return nil
			}, SealTun: func(ctx context.Context, a platform.App, manager manager) error {
				calls = append(calls, "verify-fd-and-routes")
				raw, _ := json.Marshal(tunReceipt{tunDevice(manager), 9 + attempts, 0})
				if e := applyFiles(a, map[string][]byte{tunReceiptPath(a): raw}); e != nil {
					return e
				}
				if attempts == 1 {
					return platform.Fail("tun-activation-unverified")
				}
				return nil
			}}
			e := recoverCompoundWith(context.Background(), a, effects)
			if restoreEnabled {
				requireCode(t, e, "tun-activation-unverified")
				if _, e = os.Stat(compoundPath(a)); e != nil {
					t.Fatal("failed recovery lost journal", e)
				}
				if e = recoverCompoundWith(context.Background(), a, effects); e != nil {
					t.Fatal(e)
				}
				raw, e := platform.ReadPrivate(tunReceiptPath(a))
				if e != nil {
					t.Fatal(e)
				}
				var receipt tunReceipt
				if json.Unmarshal(raw, &receipt) != nil || receipt.Index != 11 {
					t.Fatal("new kernel device index not committed", string(raw))
				}
			} else if e != nil {
				t.Fatal(e)
			}
			if _, e = os.Stat(compoundPath(a)); !os.IsNotExist(e) {
				t.Fatal("recovery not committed", e)
			}
			wanted := "stop-owned-service,observe-device-absent,reload-restored-unit,restart-original-runtime"
			if !strings.HasPrefix(strings.Join(calls, ","), wanted) {
				t.Fatal(calls)
			}
			restored, e := loadManager(a)
			if e != nil || restored.Tun.Enabled != restoreEnabled {
				t.Fatal(restored, e)
			}
			if filepath.Dir(compoundPath(a)) != a.Scope.StateRoot {
				t.Fatal("journal is volatile")
			}
		})
	}
}
