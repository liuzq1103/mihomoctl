package runtimecore

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

func coreCommand(ctx context.Context, a platform.App, r platform.Request) (platform.Envelope, error) {
	doc := platform.Document(r.Name(), a.Scope.Name, nil)
	m, e := loadManager(a)
	if e != nil {
		if r.Name() != "core-list" {
			return doc, e
		}
		if _, stat := os.Lstat(a.Scope.ManagerPath()); !os.IsNotExist(stat) {
			return doc, e
		}
		m = manager{}
	}
	if r.Name() == "core-list" {
		rows := []map[string]any{}
		root := filepath.Join(a.Scope.DataRoot, "cores")
		if e = platform.CheckPath(root); e != nil {
			return doc, e
		}
		entries, e := os.ReadDir(root)
		if e != nil && !os.IsNotExist(e) {
			return doc, e
		}
		for _, entry := range entries {
			if !entry.IsDir() || len(entry.Name()) > 0 && entry.Name()[0] == '.' {
				continue
			}
			path := filepath.Join(root, entry.Name())
			if e = platform.CheckPath(path); e != nil {
				return doc, e
			}
			binary := filepath.Join(path, "mihomo")
			receipt, e := platform.ReadPrivate(filepath.Join(path, "receipt.json"))
			if e != nil {
				return doc, e
			}
			var rec map[string]any
			if !json.Valid(receipt) {
				return doc, platform.Usage("core-receipt-invalid")
			}
			rec, e = platform.DecodeYAML(receipt)
			format, integer := rec["format"].(int)
			if e != nil || !integer || format != 1 || platform.String(rec["project"]) != "mihomoctl-go" || !digestPattern.MatchString(platform.String(rec["binary_sha256"])) {
				return doc, platform.Usage("core-receipt-invalid")
			}
			if e = trustedExecutable(binary, a.Scope.System); e != nil {
				return doc, e
			}
			digest, _, e := hashResource(ctx, a, binary, "executable")
			if e != nil {
				return doc, e
			}
			if digest != platform.String(rec["binary_sha256"]) {
				return doc, platform.Usage("core-receipt-digest-mismatch")
			}
			row := map[string]any{"path": binary, "name": entry.Name(), "active": m.Core.Binary == binary, "receipt": rec}
			rows = append(rows, row)
		}
		doc.Data = map[string]any{"binary": m.Core.Binary, "active": m.Core.Binary, "adopted": m.Core.Adopted, "installed": rows, "installs": rows}
		return doc, nil
	}
	p := r.Get("path")
	if p == "" {
		return doc, platform.Usage("core-path-required")
	}
	p, e = filepath.Abs(p)
	if e != nil {
		return doc, e
	}
	if e = trustedExecutable(p, a.Scope.System); e != nil {
		return doc, e
	}
	id, e := runningIdentity(ctx, a, m)
	if e != nil {
		return doc, e
	}
	x, e := resolve(a, "")
	if e != nil {
		return doc, e
	}
	if e = validateCore(ctx, a, p, x.Text); e != nil {
		return doc, e
	}
	v, e := coreVersion(ctx, a, p)
	if e != nil {
		return doc, e
	}
	m.Core.Binary = p
	m.Core.Adopted = true
	b, e := marshalYAML(m)
	if e != nil {
		return doc, e
	}
	files := map[string][]byte{a.Scope.ManagerPath(): b}
	if m.Core.Backend == "systemd" {
		if e = requireOwnedUnit(a, x.Manager); e != nil {
			return doc, e
		}
		unit, e := unitText(a, m)
		if e != nil {
			return doc, e
		}
		files[unitPath(a)] = []byte(unit)
	}
	if e = applyCompound(ctx, a, "core-adopt", x.Manager, m, files, id, func(active context.Context) error {
		if id != nil {
			return lifecycle(active, a, "start")
		}
		return nil
	}); e != nil {
		return doc, e
	}
	doc.Data = map[string]any{"binary": p, "adopted": true, "version": v}
	return doc, nil
}
func coreVersion(ctx context.Context, a platform.App, p string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, p, "-v")
	cmd.Env = cleanEnvironment(true, nil)
	dir, e := os.MkdirTemp("", "mihomoctl-go-version-")
	if e != nil {
		return "", e
	}
	defer os.RemoveAll(dir)
	if e = validationIdentity(ctx, cmd, a, dir); e != nil {
		return "", e
	}
	b, e := cmd.Output()
	if e != nil {
		return "", platform.Fail("core-version-failed")
	}
	match := regexp.MustCompile(`^Mihomo Meta (v?[0-9]+\.[0-9]+\.[0-9]+)(?:\s|$)`).FindSubmatch(b)
	if match == nil {
		return "", platform.Usage("core-version-unrecognized")
	}
	return string(match[1]), nil
}
func resetTargets(a platform.App, m manager) ([]string, error) {
	paths := map[string]bool{a.Scope.ManagerPath(): true, m.Core.Config: true, generatedPath(a): true}
	for _, p := range m.Profiles {
		if p.Credentials != "" {
			paths[p.Credentials] = true
		}
	}
	credentialsDir := filepath.Join(a.Scope.ConfigRoot, "credentials")
	if e := platform.CheckPath(credentialsDir); e != nil {
		return nil, e
	}
	entries, e := os.ReadDir(credentialsDir)
	if e != nil && !os.IsNotExist(e) {
		return nil, e
	}
	for _, entry := range entries {
		paths[filepath.Join(credentialsDir, entry.Name())] = true
	}
	if filepath.Dir(m.Core.Config) == filepath.Join(a.Scope.ConfigRoot, "mihomo") {
		entries, e := os.ReadDir(filepath.Dir(m.Core.Config))
		if e != nil && !os.IsNotExist(e) {
			return nil, e
		}
		base := filepath.Base(m.Core.Config)
		for _, entry := range entries {
			n := entry.Name()
			if strings.HasPrefix(n, base+".before-policy-") || n == base+".userctl-state.json" || n == base+".mihomoctl-go-state.json" {
				paths[filepath.Join(filepath.Dir(m.Core.Config), n)] = true
			}
		}
	}
	for n, b := range m.Bindings {
		if b.Adapter == "systemd" {
			if _, e := ownedIntegration(a, n, b); e != nil {
				return nil, e
			}
			env, drop := integrationPaths(a, n, b)
			paths[env] = true
			paths[drop] = true
			paths[integrationReceiptPath(a, n)] = true
		}
	}
	// Reset only known managed files; never traverse arbitrary paths or remove
	// binaries, logs, historical backups, or foreign service drop-ins.
	out := sortedKeys(paths)
	for _, p := range out {
		if !transactionPath(a, p) {
			return nil, platform.Usage("reset-target-unsafe")
		}
		if e := platform.CheckPath(p); e != nil {
			return nil, e
		}
		if _, e := os.Lstat(p); e == nil {
			if _, e = readManagedFile(a, p); e != nil {
				return nil, e
			}
		} else if !os.IsNotExist(e) {
			return nil, e
		}
	}
	return out, nil
}
func resetPreview(ctx context.Context, a platform.App, r platform.Request) (map[string]any, error) {
	m, e := loadManager(a)
	if e != nil {
		return nil, e
	}
	core := r.Get("core")
	if core == "" {
		core = m.Core.Binary
	}
	core, e = filepath.Abs(core)
	if e != nil {
		return nil, e
	}
	if e = trustedExecutable(core, a.Scope.System); e != nil {
		return nil, e
	}
	paths, e := resetTargets(a, m)
	if e != nil {
		return nil, e
	}
	proof := map[string]any{"scope": a.Scope, "core": core}
	fingerprints := map[string]any{}
	for _, p := range append(append([]string{}, paths...), a.Scope.RuntimeState(), unitPath(a), core) {
		if e = platform.CheckPath(p); e != nil {
			return nil, e
		}
		st, e := os.Lstat(p)
		if os.IsNotExist(e) {
			fingerprints[p] = nil
			continue
		}
		if e != nil {
			return nil, e
		}
		var digest string
		if p == core {
			digest, _, e = hashResource(ctx, a, p, "executable")
		} else {
			var raw []byte
			raw, e = readManagedFile(a, p)
			if e == nil {
				digest = platform.Hash(raw)
			}
		}
		if e != nil {
			return nil, e
		}
		fingerprints[p] = []any{st.Mode(), st.ModTime().UnixNano(), st.Size(), digest}
	}
	proof["inputs"] = fingerprints
	b, e := json.Marshal(proof)
	if e != nil {
		return nil, e
	}
	return map[string]any{"state": "preview", "scope": a.Scope.Name, "core": core, "removed": paths, "replaced": []string{a.Scope.ManagerPath(), filepath.Join(a.Scope.ConfigRoot, "mihomo", "config.yaml"), filepath.Join(a.Scope.ConfigRoot, "credentials", m.Default+".yaml")}, "preserved": []string{filepath.Join(a.Scope.DataRoot, "cores"), filepath.Join(a.Scope.StateRoot, "logs"), filepath.Join(a.Scope.StateRoot, "backups")}, "plan_sha256": platform.Hash(b)}, nil
}
func reset(ctx context.Context, a platform.App, r platform.Request) (platform.Envelope, error) {
	name := "reset-apply"
	if r.Has("dry-run") {
		name = "reset-preview"
	}
	doc := platform.Document(name, a.Scope.Name, nil)
	if r.Has("apply") == r.Has("dry-run") {
		return doc, platform.Usage("reset-preview-required")
	}
	preview, e := resetPreview(ctx, a, r)
	if e != nil {
		return doc, e
	}
	doc.Data = preview
	if !r.Has("apply") {
		return doc, nil
	}
	digest := r.Get("plan-sha256")
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(digest) {
		return doc, platform.Usage("reset-preview-required")
	}
	if subtle.ConstantTimeCompare([]byte(digest), []byte(preview["plan_sha256"].(string))) != 1 {
		return doc, platform.Usage("reset-preview-stale")
	}
	oldManager, e := loadManager(a)
	if e != nil {
		return doc, e
	}
	wasRunning, e := runningIdentity(ctx, a, oldManager)
	if e != nil {
		return doc, e
	}
	x, resolveErr := resolve(a, "")
	if resolveErr != nil {
		if wasRunning != nil {
			return doc, platform.Usage("reset-runtime-unverified")
		}
		x.Manager = oldManager
	}
	if oldManager.Tun.Enabled {
		return doc, platform.Usage("tun-enabled")
	}
	rr := platform.Request{Options: map[string][]string{"core": {preview["core"].(string)}, "_profile": {oldManager.Default}}}
	m, files, result, e := initialPlan(ctx, a, rr)
	if e != nil {
		return doc, e
	}
	for _, p := range preview["removed"].([]string) {
		if _, ok := files[p]; !ok {
			if !a.Scope.Contains(p) {
				old, e := platform.ReadPrivate(p)
				if e != nil && !os.IsNotExist(e) {
					return doc, e
				}
				if e == nil && !stringsHasMarker(old) {
					return doc, platform.Usage("integration-artifact-unowned")
				}
			}
			files[p] = nil
		}
	}
	if x.Manager.Core.Backend == "systemd" {
		if _, e = os.Lstat(unitPath(a)); e == nil {
			if e = requireOwnedUnit(a, x.Manager); e != nil {
				return doc, e
			}
			m.Core.Backend = "systemd"
			b, e := marshalYAML(m)
			if e != nil {
				return doc, e
			}
			files[a.Scope.ManagerPath()] = b
			unit, e := unitText(a, m)
			if e != nil {
				return doc, e
			}
			files[unitPath(a)] = []byte(unit)
		}
	}
	if e = applyCompound(ctx, a, "reset", oldManager, m, files, wasRunning, func(ctx context.Context) error {
		if a.Scope.System {
			return prepareServiceFiles(ctx, a, resolved{Manager: m, Text: files[m.Core.Config]})
		}
		return nil
	}); e != nil {
		return doc, e
	}
	result["state"] = "restart-required"
	result["service"] = "unchanged"
	result["removed"] = preview["removed"]
	doc.Data = result
	return doc, nil
}
func stringsHasMarker(b []byte) bool {
	return len(b) >= len(unitMarker)+1 && string(b[:len(unitMarker)+1]) == unitMarker+"\n"
}
