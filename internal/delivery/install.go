package delivery

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

// Installation has exactly one mutable activation record (current). Every
// generation contains a verified manifest. Receipt and launcher are immutable.
// No core, manager configuration, service or runtime state is touched here.
type Receipt struct {
	Format         int    `json:"format"`
	Project        string `json:"project"`
	BinPath        string `json:"bin_path"`
	LauncherSHA256 string `json:"launcher_sha256"`
	InstallationID string `json:"installation_id,omitempty"`
}

type pending struct {
	Format int    `json:"format"`
	Old    string `json:"old"`
	New    string `json:"new"`
}

var generationPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

func installRoot(a platform.App) string { return filepath.Join(a.Scope.DataRoot, "install") }
func quote(s string) string             { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
func launcher(root string) []byte {
	return []byte("#!/bin/sh\n# owned by mihomoctl-go installation protocol 1\nset -eu\nroot=" + quote(root) + "\nIFS= read -r generation < \"$root/current\"\ncase \"$generation\" in ''|*[!a-f0-9]*) echo 'invalid mihomoctl-go generation' >&2; exit 1;; esac\n[ \"${#generation}\" -eq 64 ] || exit 1\nexec \"$root/generations/$generation/bin/mihomoctl\" \"$@\"\n")
}
func readReceipt(a platform.App) (Receipt, error) {
	var rec Receipt
	root := installRoot(a)
	b, e := platform.ReadPrivate(filepath.Join(root, "receipt.json"))
	if e != nil {
		return rec, fail("managed-installation-receipt-required")
	}
	if e = StrictJSON(b, &rec); e != nil {
		return rec, e
	}
	if rec.Format != 1 || rec.Project != Project || !filepath.IsAbs(rec.BinPath) || filepath.Base(rec.BinPath) != "mihomoctl" || rec.LauncherSHA256 != platform.Hash(launcher(root)) {
		return rec, fail("installation-receipt-invalid")
	}
	if rec.InstallationID != "" && !shaPattern.MatchString(rec.InstallationID) {
		return rec, fail("installation-receipt-invalid")
	}
	b, e = platform.ReadPrivate(rec.BinPath)
	if e != nil || platform.Hash(b) != rec.LauncherSHA256 {
		return rec, fail("installation-launcher-drift")
	}
	return rec, nil
}
func readCurrent(root string) (string, error) {
	b, e := platform.ReadPrivate(filepath.Join(root, "current"))
	if e != nil {
		return "", e
	}
	g := strings.TrimSuffix(string(b), "\n")
	if !generationPattern.MatchString(g) {
		return "", fail("installation-current-invalid")
	}
	return g, nil
}
func generation(root, g string) (string, Manifest, error) {
	var m Manifest
	if !generationPattern.MatchString(g) {
		return "", m, fail("installation-generation-invalid")
	}
	p := filepath.Join(root, "generations", g)
	b, e := platform.ReadPrivate(filepath.Join(p, "release-manifest.json"))
	if e != nil {
		return p, m, e
	}
	if platform.Hash(b) != g {
		return p, m, fail("installation-generation-manifest-drift")
	}
	m, e = LoadManifest(p)
	if e == nil {
		e = VerifyTree(p, m)
	}
	return p, m, e
}
func removePending(root string) error {
	if e := os.Remove(filepath.Join(root, "pending.json")); e != nil && !os.IsNotExist(e) {
		return e
	}
	return syncDir(root)
}

// Recover is called only while holding the shared mutation lock. A switch to a
// fully verified new generation is committed; a switch not yet made is aborted.
// Unexpected activation records fail closed and retain the journal for inspection.
func recoverInstall(a platform.App) error {
	root := installRoot(a)
	p := filepath.Join(root, "pending.json")
	if e := platform.CheckPath(p); e != nil {
		return e
	}
	if _, e := os.Lstat(p); os.IsNotExist(e) {
		return nil
	} else if e != nil {
		return e
	}
	if _, e := readReceipt(a); e != nil {
		return e
	}
	b, e := platform.ReadPrivate(p)
	if e != nil {
		return e
	}
	var tx pending
	if e = StrictJSON(b, &tx); e != nil {
		return e
	}
	if tx.Format != 1 || !generationPattern.MatchString(tx.New) || (tx.Old != "" && !generationPattern.MatchString(tx.Old)) || tx.New == tx.Old {
		return fail("installation-journal-invalid")
	}
	cur, e := readCurrent(root)
	if e != nil {
		if tx.Old == "" {
			if _, se := os.Lstat(filepath.Join(root, "current")); os.IsNotExist(se) {
				if _, _, e = generation(root, tx.New); e != nil {
					return e
				}
				if e = platform.AtomicWrite(filepath.Join(root, "current"), []byte(tx.New+"\n"), 0600); e != nil {
					return e
				}
				return removePending(root)
			}
		}
		return e
	}
	if cur == tx.New {
		if _, _, e = generation(root, tx.New); e == nil {
			return removePending(root)
		}
		if tx.Old == "" {
			return fail("installation-recovery-unverified")
		}
		if _, _, oldErr := generation(root, tx.Old); oldErr != nil {
			return fail("installation-recovery-unverified")
		}
		if e = platform.AtomicWrite(filepath.Join(root, "current"), []byte(tx.Old+"\n"), 0600); e != nil {
			return fail("installation-rollback-failed")
		}
		return removePending(root)
	}
	if cur != tx.Old {
		return fail("installation-journal-conflict")
	}
	if _, _, e = generation(root, cur); e != nil {
		return e
	}
	return removePending(root)
}

type installHooks struct {
	afterJournal func() error
	afterSwitch  func() error
}

func installTree(a platform.App, source string, reinstall, allowDowngrade, dry bool, hooks installHooks) (map[string]any, error) {
	if _, e := readReceipt(a); e != nil {
		return nil, e
	}
	root := installRoot(a)
	if !dry {
		if e := recoverInstall(a); e != nil {
			return nil, e
		}
	} else if _, e := os.Lstat(filepath.Join(root, "pending.json")); !os.IsNotExist(e) {
		return nil, fail("installation-recovery-required")
	}
	old, e := readCurrent(root)
	if e != nil {
		return nil, e
	}
	_, current, e := generation(root, old)
	if e != nil {
		return nil, e
	}
	m, e := LoadManifest(source)
	if e != nil {
		return nil, e
	}
	if e = VerifyTree(source, m); e != nil {
		return nil, e
	}
	if e = native(m); e != nil {
		return nil, e
	}
	cmp, e := CompareVersions(m.Version, current.Version)
	if e != nil {
		return nil, e
	}
	if cmp < 0 && !allowDowngrade {
		return nil, fail("installation-downgrade-refused")
	}
	if cmp == 0 && !reinstall {
		return nil, fail("installation-reinstall-required")
	}
	data := map[string]any{"from_version": current.Version, "to_version": m.Version, "dry_run": dry, "active_core_preserved": true, "source_trust": "local caller-selected content; manifest hashes verify consistency"}
	data["version"] = m.Version
	data["replaces"] = current.Version
	data["replaced"] = current.Version
	data["install_root"] = root
	data["source_kind"] = "go-" + m.Kind + "-bundle"
	if rec, e := readReceipt(a); e == nil {
		data["bin_link"] = rec.BinPath
	}
	if dry {
		return data, nil
	}
	newID, e := stageGeneration(root, source, m)
	if e != nil {
		return nil, e
	}
	if newID == old {
		data["changed"] = false
		return data, nil
	}
	if _, e = readReceipt(a); e != nil {
		return nil, e
	}
	check, e := readCurrent(root)
	if e != nil || check != old {
		return nil, fail("installation-changed-during-update")
	}
	tx := pending{1, old, newID}
	if e = platform.WriteJSON(filepath.Join(root, "pending.json"), tx); e != nil {
		return nil, e
	}
	rollback := func(original error) error {
		if re := platform.AtomicWrite(filepath.Join(root, "current"), []byte(old+"\n"), 0600); re != nil {
			return fail("installation-rollback-failed")
		}
		if re := removePending(root); re != nil {
			return fail("installation-rollback-failed")
		}
		return original
	}
	if hooks.afterJournal != nil {
		if e = hooks.afterJournal(); e != nil {
			return nil, rollback(e)
		}
	}
	if e = platform.AtomicWrite(filepath.Join(root, "current"), []byte(newID+"\n"), 0600); e != nil {
		return nil, rollback(e)
	}
	if hooks.afterSwitch != nil {
		if e = hooks.afterSwitch(); e != nil {
			return nil, rollback(e)
		}
	}
	// A cleanup failure leaves a journal that the next invocation can verify and finish.
	if e = removePending(root); e != nil {
		return nil, e
	}
	data["changed"] = true
	data["generation"] = newID
	data["previous_generation"] = old
	return data, nil
}

func stageGeneration(root, source string, m Manifest) (string, error) {
	gens := filepath.Join(root, "generations")
	if e := platform.PrivateDir(gens); e != nil {
		return "", e
	}
	stage, e := os.MkdirTemp(gens, ".stage-*")
	if e != nil {
		return "", e
	}
	defer os.RemoveAll(stage)
	for n, f := range m.Files {
		p := filepath.Join(source, filepath.FromSlash(n))
		h, size, e := fileDigest(p)
		if e != nil {
			return "", e
		}
		if h != f.SHA256 || size != f.Size {
			return "", fail("source-changed-during-update")
		}
		b, e := readBoundedFile(p, MaxExpanded)
		if e != nil {
			return "", e
		}
		if platform.Hash(b) != f.SHA256 {
			return "", fail("source-changed-during-update")
		}
		if e = platform.AtomicWrite(filepath.Join(stage, filepath.FromSlash(n)), b, os.FileMode(f.Mode)); e != nil {
			return "", e
		}
	}
	b, e := json.MarshalIndent(m, "", "  ")
	if e != nil {
		return "", e
	}
	b = append(b, '\n')
	if e = platform.AtomicWrite(filepath.Join(stage, "release-manifest.json"), b, 0600); e != nil {
		return "", e
	}
	if e = VerifyTree(stage, m); e != nil {
		return "", e
	}
	id := platform.Hash(b)
	dest := filepath.Join(gens, id)
	if e = platform.CheckPath(dest); e != nil {
		return "", e
	}
	if _, e = os.Lstat(dest); e == nil {
		_, stored, e := generation(root, id)
		if e != nil {
			return "", e
		}
		if stored.Version != m.Version {
			return "", fail("installation-generation-conflict")
		}
		return id, nil
	} else if !os.IsNotExist(e) {
		return "", e
	}
	if e = os.Rename(stage, dest); e != nil {
		return "", e
	}
	if e = syncDir(gens); e != nil {
		return "", e
	}
	return id, nil
}

// Bootstrap is for an explicit first installation. Updates always require an
// existing managed receipt. It refuses to overwrite any existing command.
func Bootstrap(ctx context.Context, a platform.App, source, binDir string, dry bool) (map[string]any, error) {
	m, e := LoadManifest(source)
	if e != nil {
		return nil, e
	}
	if e = VerifyTree(source, m); e != nil {
		return nil, e
	}
	if e = native(m); e != nil {
		return nil, e
	}
	if !filepath.IsAbs(binDir) || strings.ContainsAny(binDir, "\n\r\x00") {
		return nil, usage("installation-bin-dir-invalid")
	}
	if pending, e := optionalExists(uninstallJournal(a)); e != nil {
		return nil, e
	} else if pending {
		if dry {
			return nil, fail("uninstall-recovery-required")
		}
		if e = platform.WithLock(ctx, a.Scope, func() error { return recoverUninstall(a) }); e != nil {
			return nil, e
		}
	}
	root := installRoot(a)
	bin := filepath.Join(binDir, "mihomoctl")
	data := map[string]any{"version": m.Version, "bin_path": bin, "dry_run": dry, "active_core_preserved": true}
	if e = platform.CheckPath(bin); e != nil {
		return nil, e
	}
	if _, e = os.Lstat(bin); !os.IsNotExist(e) {
		return nil, fail("installation-command-exists")
	}
	if _, e = os.Lstat(root); !os.IsNotExist(e) {
		return nil, fail("installation-root-exists")
	}
	if dry {
		return data, nil
	}
	e = platform.WithLock(ctx, a.Scope, func() error {
		if e := recoverUninstall(a); e != nil {
			return e
		}
		if _, e := os.Lstat(root); !os.IsNotExist(e) {
			return fail("installation-root-exists")
		}
		if _, e := os.Lstat(bin); !os.IsNotExist(e) {
			return fail("installation-command-exists")
		}
		if e := platform.PrivateDir(root); e != nil {
			return e
		}
		id, e := stageGeneration(root, source, m)
		if e != nil {
			return e
		}
		if m.Core != nil {
			data["core"] = map[string]any{"binary": filepath.Join(root, "generations", id, "core", "mihomo"), "version": m.Core.Version, "activated": false, "provenance": m.Core.Provenance,
				"program_owned": true, "uninstall_policy": "Install and adopt an independent core with core install --asset before uninstalling this program."}
		}
		if e = platform.CheckPath(binDir); e != nil {
			return e
		}
		if e = os.MkdirAll(binDir, 0755); e != nil {
			return e
		}
		// Exclusive create ensures concurrent or foreign installers cannot be overwritten.
		content := launcher(root)
		f, e := os.OpenFile(bin, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0700)
		if e != nil {
			return e
		}
		_, e = f.Write(content)
		if e == nil {
			e = f.Sync()
		}
		ce := f.Close()
		if e == nil {
			e = ce
		}
		if e != nil {
			return e
		}
		installationID, e := platform.Token()
		if e != nil {
			return e
		}
		rec := Receipt{Format: 1, Project: Project, BinPath: bin, LauncherSHA256: platform.Hash(content), InstallationID: installationID}
		if e = platform.WriteJSON(filepath.Join(root, "receipt.json"), rec); e != nil {
			return e
		}
		if e = platform.WriteJSON(filepath.Join(root, "pending.json"), pending{1, "", id}); e != nil {
			return e
		}
		if e = platform.AtomicWrite(filepath.Join(root, "current"), []byte(id+"\n"), 0600); e != nil {
			return e
		}
		return removePending(root)
	})
	return data, e
}

func update(ctx context.Context, a platform.App, r platform.Request) (map[string]any, error) {
	source := r.Get("source")
	if source == "" {
		source = r.Arg(0)
	}
	if source == "" && !r.Has("latest") {
		return nil, usage("update-source-or-latest-required")
	}
	if source != "" && r.Has("latest") {
		return nil, usage("update-source-conflict")
	}
	// Receipt checks precede any acquisition, including previews.
	if _, e := readReceipt(a); e != nil {
		return nil, e
	}
	if r.Has("latest") {
		kind := r.Get("kind")
		if kind == "" {
			kind = "basic"
		}
		if kind != "basic" && kind != "offline" {
			return nil, usage("release-kind-invalid")
		}
		meta, e := (Downloader{}).Metadata(ctx, "latest")
		if e != nil {
			return nil, e
		}
		if !shaPattern.MatchString(r.Get("sha256")) {
			return nil, fail("reviewed-digest-required")
		}
		if r.Has("dry-run") {
			cur, e := readCurrent(installRoot(a))
			if e != nil {
				return nil, e
			}
			_, m, e := generation(installRoot(a), cur)
			if e != nil {
				return nil, e
			}
			v := strings.TrimPrefix(meta.Tag, "v")
			cmp, e := CompareVersions(v, m.Version)
			if e != nil {
				return nil, e
			}
			if cmp < 0 && !r.Has("allow-downgrade") {
				return nil, fail("installation-downgrade-refused")
			}
			if cmp == 0 && !r.Has("reinstall") {
				return nil, fail("installation-reinstall-required")
			}
			return map[string]any{"dry_run": true, "version": v, "observed_version": v, "sha256": r.Get("sha256"), "asset": AssetName(v, runtime.GOARCH, kind), "artifact_verified": false, "active_core_preserved": true}, nil
		}
		dir, e := os.MkdirTemp("", "mihomoctl-go-latest-*")
		if e != nil {
			return nil, e
		}
		defer os.RemoveAll(dir)
		source, e = (Downloader{}).Fetch(ctx, meta, dir, r.Get("sha256"), kind)
		if e != nil {
			return nil, e
		}
	}
	if e := platform.CheckPath(source); e != nil {
		return nil, e
	}
	st, e := os.Stat(source)
	if e != nil {
		return nil, e
	}
	if !st.IsDir() {
		if r.Get("sha256") != "" {
			h, _, e := fileDigest(source)
			if e != nil {
				return nil, e
			}
			if h != r.Get("sha256") {
				return nil, fail("artifact-digest-mismatch")
			}
		}
		dir, e := os.MkdirTemp("", "mihomoctl-go-update-*")
		if e != nil {
			return nil, e
		}
		defer os.RemoveAll(dir)
		f, e := platform.OpenRegular(source)
		if e != nil {
			return nil, e
		}
		e = ExtractTarGzip(f, dir)
		f.Close()
		if e != nil {
			return nil, e
		}
		source = dir
	}
	if r.Has("dry-run") {
		return installTree(a, source, r.Has("reinstall"), r.Has("allow-downgrade"), true, installHooks{})
	}
	var data map[string]any
	e = platform.WithLock(ctx, a.Scope, func() error {
		var e error
		data, e = installTree(a, source, r.Has("reinstall"), r.Has("allow-downgrade"), false, installHooks{})
		return e
	})
	return data, e
}

func Uninstall(ctx context.Context, a platform.App, dry bool) (map[string]any, error) {
	return uninstallProgram(ctx, a, dry)
}

func installationStatus(a platform.App) (map[string]any, error) {
	if pending, e := optionalExists(uninstallJournal(a)); e != nil {
		return nil, e
	} else if pending {
		journal, e := loadRemoval(a)
		if e != nil {
			return nil, e
		}
		if e = validateRemovalStatus(a, journal); e != nil {
			return nil, e
		}
		return map[string]any{"installed": false, "status": "uninstalling", "recovery_required": true, "version": nil}, nil
	}
	if exists, e := optionalExists(installRoot(a)); e != nil {
		return nil, e
	} else if !exists {
		return notInstalled(), nil
	}
	rec, e := readReceipt(a)
	if e != nil {
		return nil, e
	}
	id, e := readCurrent(installRoot(a))
	if e != nil {
		return nil, e
	}
	_, m, e := generation(installRoot(a), id)
	if e != nil {
		return nil, e
	}
	// Status validates retained program generations and refuses undeclared
	// program-root files as well as drift in the active receipt/generation.
	if _, e = collectRemoval(a); e != nil {
		return nil, e
	}
	return map[string]any{"installed": true, "receipt": rec, "generation": id, "version": m.Version}, nil
}
