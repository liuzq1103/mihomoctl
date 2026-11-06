package runtimecore

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

// CommitAndStart is the private routing/TUI save-and-activate boundary. Call it
// without holding the shared operation lock. It rechecks the reviewed base,
// journals configuration and runtime intent, then verifies real activation.
// Failure restores the original files and the original running/stopped state.
func CommitAndStart(ctx context.Context, a platform.App, configPath string, before, after []byte) (map[string]any, error) {
	var result map[string]any
	e := platform.WithLock(ctx, a.Scope, func() error {
		if e := preventLockInheritance(a); e != nil {
			return e
		}
		if e := recoverCompound(ctx, a); e != nil {
			return e
		}
		if e := recoverTransaction(a); e != nil {
			return e
		}
		x, e := resolve(a, "")
		if e != nil {
			return e
		}
		if configPath != x.Manager.Core.Config || !absolute(configPath) {
			return platform.Usage("config-outside-scope")
		}
		if !bytes.Equal(x.Text, before) {
			return platform.Usage("config-changed-during-policy-edit")
		}
		candidate, e := platform.DecodeYAML(after)
		if e != nil {
			return e
		}
		if _, _, e = parseEndpoints(candidate, a.Scope.System, x.Manager.Allow); e != nil {
			return e
		}
		// A subscription/policy save cannot smuggle listener, auth, DNS, controller
		// or TUN changes through this runtime boundary.
		for _, key := range []string{"port", "socks-port", "mixed-port", "redir-port", "tproxy-port", "bind-address", "allow-lan", "lan-allowed-ips", "lan-disallowed-ips", "authentication", "skip-auth-prefixes", "external-controller", "external-controller-tls", "external-controller-unix", "external-controller-pipe", "external-controller-cors", "external-doh-server", "secret", "tun", "listeners", "dns"} {
			old, oldOK := x.Config[key]
			new, newOK := candidate[key]
			oldJSON, _ := json.Marshal(old)
			newJSON, _ := json.Marshal(new)
			if oldOK != newOK || !bytes.Equal(oldJSON, newJSON) {
				return platform.Usage("configuration-security-envelope-changed")
			}
		}
		if e = validateCore(ctx, a, x.Manager.Core.Binary, after); e != nil {
			return e
		}
		id, e := runningIdentity(ctx, a, x.Manager)
		if e != nil {
			return e
		}
		managerBytes, e := platform.ReadPrivate(a.Scope.ManagerPath())
		if e != nil {
			return e
		}
		receipt := configPath + ".userctl-state.json"
		if !a.Scope.Contains(receipt) {
			return platform.Usage("config-outside-scope")
		}
		files := map[string][]byte{a.Scope.ManagerPath(): managerBytes, configPath: after, receipt: nil}
		if e = applyCompound(ctx, a, "configuration-start", x.Manager, x.Manager, files, id, func(active context.Context) error {
			if e := lifecycle(active, a, "start"); e != nil {
				return e
			}
			if active.Err() != nil {
				return active.Err()
			}
			if x.Manager.Tun.Enabled {
				if e := sealTunReceipt(active, a, x.Manager); e != nil {
					return e
				}
			}
			current, e := readManagedFile(a, configPath)
			if e != nil {
				return e
			}
			if !bytes.Equal(current, after) {
				return platform.Usage("config-changed-during-activation")
			}
			live, e := resolve(a, "")
			if e != nil {
				return e
			}
			health, e := healthResolved(active, a, live, nil)
			if e != nil {
				return e
			}
			if health.Overall != "PASS" {
				return platform.Fail("health-blocked")
			}
			identity, e := runningIdentity(active, a, live.Manager)
			if e != nil || identity == nil {
				return platform.Fail("runtime-identity-unverified")
			}
			result = map[string]any{"state": "running", "service": "started", "sha256": platform.Hash(after), "config": configPath, "pid": identity.PID, "restart_required": false, "verified": true}
			return nil
		}); e != nil {
			return e
		}
		return nil
	})
	return result, e
}
