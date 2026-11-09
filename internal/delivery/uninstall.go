package delivery

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

type removalEntry struct {
	Directory bool   `json:"directory"`
	SHA256    string `json:"sha256,omitempty"`
	// The device/inode pair identifies the recorded object itself. Identical
	// bytes from a replacement file are a different object.
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
}

// The journal lives outside the program root, so it survives deletion of the
// receipt, current pointer, and generations. Its exact inventory authorizes only
// files verified before the first deletion; recovery refuses added/changed paths.
type removalJournal struct {
	Format      int                     `json:"format"`
	Project     string                  `json:"project"`
	Root        string                  `json:"root"`
	Receipt     Receipt                 `json:"receipt"`
	Entries     map[string]removalEntry `json:"entries"`
	Token       string                  `json:"token"`
	Quarantine  string                  `json:"quarantine"`
	Phase       string                  `json:"phase"`
	ReceiptHash string                  `json:"receipt_sha256"`
	Current     string                  `json:"current_generation"`
	Device      uint64                  `json:"device"`
	Inode       uint64                  `json:"inode"`
	// The launcher lives outside the program root, so its identity is recorded
	// separately. Its bytes are reproducible, and only the object itself proves
	// that it is still the launcher this installation owns.
	LauncherDevice uint64 `json:"launcher_device"`
	LauncherInode  uint64 `json:"launcher_inode"`
}

type uninstallHooks struct {
	checkpoint func(string) error
}

func uninstallJournal(a platform.App) string {
	return filepath.Join(a.Scope.StateRoot, "delivery-uninstall.json")
}

func optionalExists(p string) (bool, error) {
	if e := platform.CheckPath(p); e != nil {
		return false, e
	}
	_, e := os.Lstat(p)
	if os.IsNotExist(e) {
		return false, nil
	}
	return e == nil, e
}

func notInstalled() map[string]any {
	return map[string]any{"installed": false, "status": "not-installed", "version": nil, "active_core_preserved": true}
}

func removalReceipt(a platform.App, rec Receipt) error {
	if rec.Format != 1 || rec.Project != Project || !filepath.IsAbs(rec.BinPath) ||
		filepath.Clean(rec.BinPath) != rec.BinPath || filepath.Base(rec.BinPath) != "mihomoctl" ||
		rec.LauncherSHA256 != platform.Hash(launcher(installRoot(a))) {
		return fail("uninstall-receipt-invalid")
	}
	if rec.InstallationID != "" && !shaPattern.MatchString(rec.InstallationID) {
		return fail("uninstall-receipt-invalid")
	}
	if within(installRoot(a), rec.BinPath) || within(rec.BinPath, installRoot(a)) {
		return fail("uninstall-launcher-path-conflict")
	}
	return platform.CheckPath(rec.BinPath)
}

func within(root, p string) bool {
	rel, e := filepath.Rel(root, p)
	return e == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}

// Validate every generation, including inactive code retained by earlier updates.
// Undeclared files or unexpected top-level entries are not treated as program-owned.
func collectRemoval(a platform.App) (removalJournal, error) {
	root := installRoot(a)
	j := removalJournal{Format: 4, Project: Project, Root: root, Entries: map[string]removalEntry{}}
	rec, e := readReceipt(a)
	if e != nil {
		return j, e
	}
	j.Receipt = rec
	if e = removalReceipt(a, rec); e != nil {
		return j, e
	}
	current, e := readCurrent(root)
	if e != nil {
		return j, e
	}
	if _, _, e = generation(root, current); e != nil {
		return j, e
	}
	j.Current = current
	j.Token, e = platform.Token()
	if e != nil {
		return j, e
	}
	j.Quarantine = filepath.Join(a.Scope.DataRoot, ".install-remove-"+j.Token)
	j.Phase = "prepared"
	j.Device, j.Inode, e = removalIdentity(root)
	if e != nil {
		return j, e
	}
	// Record the launcher object this installation published, not the object
	// that happens to sit at the path now. The launcher script is fully
	// reproducible, so a same-byte replacement must never be deleted as if it
	// were ours.
	device, inode, e := removalObjectIdentity(rec.BinPath)
	if e != nil {
		return j, e
	}
	if device != rec.LauncherDevice || inode != rec.LauncherInode {
		return j, fail("uninstall-launcher-drift")
	}
	j.LauncherDevice, j.LauncherInode = rec.LauncherDevice, rec.LauncherInode
	children, e := os.ReadDir(root)
	if e != nil {
		return j, e
	}
	for _, child := range children {
		switch child.Name() {
		case "receipt.json", "current", "generations":
		default:
			return j, fail("uninstall-unowned-entry")
		}
	}
	gens, e := os.ReadDir(filepath.Join(root, "generations"))
	if e != nil {
		return j, e
	}
	for _, gen := range gens {
		if !gen.IsDir() || !generationPattern.MatchString(gen.Name()) {
			return j, fail("uninstall-unowned-generation")
		}
		if _, _, e = generation(root, gen.Name()); e != nil {
			return j, e
		}
	}
	e = filepath.WalkDir(root, func(p string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if e := platform.CheckPath(p); e != nil {
			return e
		}
		if d.IsDir() {
			if _, _, e := removalIdentity(p); e != nil {
				return e
			}
		} else {
			info, e := d.Info()
			if e != nil || !info.Mode().IsRegular() {
				return fail("uninstall-special-file-refused")
			}
		}
		if p == root {
			return nil
		}
		rel, e := filepath.Rel(root, p)
		if e != nil {
			return e
		}
		entry := removalEntry{Directory: d.IsDir()}
		entry.Device, entry.Inode, e = removalObjectIdentity(p)
		if e != nil {
			return e
		}
		if !d.IsDir() {
			entry.SHA256, _, e = fileDigest(p)
			if e != nil {
				return e
			}
		}
		j.Entries[filepath.ToSlash(rel)] = entry
		return nil
	})
	j.ReceiptHash = j.Entries["receipt.json"].SHA256
	return j, e
}

func loadRemoval(a platform.App) (removalJournal, error) {
	var j removalJournal
	b, e := platform.ReadPrivate(uninstallJournal(a))
	if e != nil {
		return j, e
	}
	if e = StrictJSON(b, &j); e != nil {
		return j, e
	}
	if j.Format != 4 || j.Project != Project || j.Root != installRoot(a) || len(j.Entries) == 0 {
		return j, fail("uninstall-journal-invalid")
	}
	if !shaPattern.MatchString(j.Token) ||
		j.Quarantine != filepath.Join(a.Scope.DataRoot, ".install-remove-"+j.Token) ||
		(j.Phase != "prepared" && j.Phase != "quarantined") ||
		!shaPattern.MatchString(j.ReceiptHash) || !generationPattern.MatchString(j.Current) || j.Inode == 0 ||
		j.LauncherDevice == 0 || j.LauncherInode == 0 {
		return j, fail("uninstall-journal-invalid")
	}
	if e = removalReceipt(a, j.Receipt); e != nil {
		return j, e
	}
	for n, entry := range j.Entries {
		if !safeName(n) || (entry.Directory && entry.SHA256 != "") ||
			(!entry.Directory && !shaPattern.MatchString(entry.SHA256)) ||
			entry.Device == 0 || entry.Inode == 0 {
			return j, fail("uninstall-journal-invalid")
		}
		if n != "receipt.json" && n != "current" && n != "generations" && !strings.HasPrefix(n, "generations/") {
			return j, fail("uninstall-journal-invalid")
		}
	}
	if _, ok := j.Entries["receipt.json"]; !ok {
		return j, fail("uninstall-journal-invalid")
	}
	if _, ok := j.Entries["current"]; !ok {
		return j, fail("uninstall-journal-invalid")
	}
	if j.Entries["receipt.json"].Directory || j.Entries["receipt.json"].SHA256 != j.ReceiptHash ||
		j.Entries["current"].Directory || j.Entries["current"].SHA256 != platform.Hash([]byte(j.Current+"\n")) ||
		j.Entries["generations/"+j.Current+"/release-manifest.json"].SHA256 != j.Current {
		return j, fail("uninstall-journal-identity-invalid")
	}
	return j, nil
}

func verifyRemovalSnapshot(root string, j removalJournal, complete bool) error {
	device, inode, e := removalIdentity(root)
	if e != nil {
		return e
	}
	if device != j.Device || inode != j.Inode {
		return fail("uninstall-root-identity-changed")
	}
	seen := 0
	e = filepath.WalkDir(root, func(p string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if e := platform.CheckPath(p); e != nil {
			return e
		}
		if d.IsDir() {
			if _, _, e := removalIdentity(p); e != nil {
				return e
			}
		}
		if p == root {
			return nil
		}
		rel, e := filepath.Rel(root, p)
		if e != nil {
			return e
		}
		entry, ok := j.Entries[filepath.ToSlash(rel)]
		if !ok || entry.Directory != d.IsDir() {
			return fail("uninstall-inventory-drift")
		}
		// The recorded object must still be the object on disk. Identical bytes
		// in a replacement file are not authorization to delete it.
		device, inode, e := removalObjectIdentity(p)
		if e != nil {
			return e
		}
		if device != entry.Device || inode != entry.Inode {
			return fail("uninstall-inventory-drift")
		}
		if !d.IsDir() {
			h, _, e := fileDigest(p)
			if e != nil {
				return e
			}
			if h != entry.SHA256 {
				return fail("uninstall-inventory-drift")
			}
		}
		seen++
		return nil
	})
	if e != nil {
		return e
	}
	if complete && seen != len(j.Entries) {
		return fail("uninstall-inventory-drift")
	}
	if complete {
		b, e := platform.ReadPrivate(filepath.Join(root, "receipt.json"))
		if e != nil || platform.Hash(b) != j.ReceiptHash {
			return fail("uninstall-receipt-drift")
		}
		var rec Receipt
		if e = StrictJSON(b, &rec); e != nil || rec != j.Receipt {
			return fail("uninstall-receipt-drift")
		}
		current, e := readCurrent(root)
		if e != nil || current != j.Current {
			return fail("uninstall-current-drift")
		}
	}
	return nil
}

// The launcher script is fully reproducible, so its bytes prove nothing about
// ownership. Only the recorded object does. A launcher that is present but no
// longer the recorded object is a foreign file and is never deleted.
func removalLauncherOwned(j removalJournal) (bool, error) {
	exists, e := optionalExists(j.Receipt.BinPath)
	if e != nil {
		return false, e
	}
	if !exists {
		return false, nil
	}
	device, inode, e := removalObjectIdentity(j.Receipt.BinPath)
	if e != nil {
		return false, e
	}
	if device != j.LauncherDevice || inode != j.LauncherInode {
		return false, fail("uninstall-launcher-drift")
	}
	b, e := platform.ReadPrivate(j.Receipt.BinPath)
	if e != nil || platform.Hash(b) != j.Receipt.LauncherSHA256 {
		return false, fail("uninstall-launcher-drift")
	}
	return true, nil
}

// protectConfiguredCore refuses the uninstall when a file the active
// configuration depends on lives inside the program tree the uninstall
// deletes. The core binary, the active configuration and the profile
// credentials are all preserved by contract, so their location decides whether
// the removal may proceed at all.
func protectConfiguredCore(a platform.App, roots ...string) error {
	refuse := func(code, detail, p string) error {
		for _, root := range roots {
			if p != "" && within(root, p) {
				return &platform.Error{Code: code, Exit: 1, Detail: detail}
			}
		}
		return nil
	}
	refuseCore := func(p string) error {
		return refuse("uninstall-core-inside-program-root", "Install and explicitly adopt a core under managed cores storage before removing the program. The configured or running core was preserved.", p)
	}
	refuseConfig := func(p string) error {
		return refuse("uninstall-config-inside-program-root", "The active configuration or profile credentials live inside the managed program tree. Move them to the retained configuration storage before removing the program. They were preserved.", p)
	}
	if m, e := a.LoadManager(); e == nil {
		core := platform.Map(m["core"])
		if e := refuseCore(platform.String(core["binary"])); e != nil {
			return e
		}
		if e := refuseConfig(platform.String(core["config"])); e != nil {
			return e
		}
		profiles := platform.Map(m["profiles"])
		names := make([]string, 0, len(profiles))
		for name := range profiles {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			profile := platform.Map(profiles[name])
			if e := refuseConfig(platform.String(profile["credentials_file"])); e != nil {
				return e
			}
		}
	} else if exists, se := optionalExists(a.Scope.ManagerPath()); se != nil || exists {
		return fail("uninstall-manager-unverified")
	}
	if exists, e := optionalExists(a.Scope.RuntimeState()); e != nil {
		return e
	} else if exists {
		b, e := platform.ReadPrivate(a.Scope.RuntimeState())
		if e != nil {
			return fail("uninstall-runtime-state-unverified")
		}
		var state map[string]any
		if e = StrictJSON(b, &state); e != nil || platform.String(state["namespace"]) != Project || platform.String(state["scope"]) != a.Scope.Name {
			return fail("uninstall-runtime-state-unverified")
		}
		p := platform.String(platform.Map(state["identity"])["exe"])
		if p == "" || !filepath.IsAbs(p) {
			return fail("uninstall-runtime-state-unverified")
		}
		if e = refuseCore(p); e != nil {
			return e
		}
	}
	return nil
}

func validateRemovalStatus(a platform.App, j removalJournal) error {
	rootExists, e := optionalExists(j.Root)
	if e != nil {
		return e
	}
	quarantined, e := optionalExists(j.Quarantine)
	if e != nil {
		return e
	}
	if j.Phase == "prepared" {
		if rootExists == quarantined {
			return fail("uninstall-journal-conflict")
		}
		target := j.Quarantine
		if rootExists {
			target = j.Root
		}
		if e = verifyRemovalSnapshot(target, j, true); e != nil {
			return e
		}
	} else {
		if rootExists {
			return fail("uninstall-new-installation-conflict")
		}
		if quarantined {
			if e = verifyRemovalSnapshot(j.Quarantine, j, false); e != nil {
				return e
			}
		}
	}
	if _, e = removalLauncherOwned(j); e != nil {
		return e
	}
	return nil
}

func recoverUninstall(a platform.App) error {
	return recoverUninstallWithHooks(a, uninstallHooks{})
}

func recoverUninstallWithHooks(a platform.App, hooks uninstallHooks) error {
	exists, e := optionalExists(uninstallJournal(a))
	if e != nil || !exists {
		return e
	}
	j, e := loadRemoval(a)
	if e != nil {
		return e
	}
	if e = validateRemovalStatus(a, j); e != nil {
		return e
	}
	rootExists, e := optionalExists(j.Root)
	if e != nil {
		return e
	}
	quarantined, e := optionalExists(j.Quarantine)
	if e != nil {
		return e
	}
	if e = protectConfiguredCore(a, j.Root, j.Quarantine); e != nil {
		return e
	}
	if j.Phase == "prepared" {
		if rootExists && quarantined {
			return fail("uninstall-journal-conflict")
		}
		if !rootExists && !quarantined {
			return fail("uninstall-root-missing")
		}
		target := j.Quarantine
		if rootExists {
			target = j.Root
		}
		if e = verifyRemovalSnapshot(target, j, true); e != nil {
			return e
		}
		if rootExists {
			if e = os.Rename(j.Root, j.Quarantine); e != nil {
				return e
			}
			if e = syncDir(filepath.Dir(j.Root)); e != nil {
				return e
			}
			if hooks.checkpoint != nil {
				if e = hooks.checkpoint("root-quarantined"); e != nil {
					return e
				}
			}
		}
		j.Phase = "quarantined"
		if e = platform.WriteJSON(uninstallJournal(a), j); e != nil {
			return e
		}
		quarantined = true
	} else if rootExists {
		// Never apply an old deletion journal to a new installation, even when
		// its manifest and launcher happen to have exactly the same bytes.
		return fail("uninstall-new-installation-conflict")
	}
	if quarantined {
		if e = verifyRemovalSnapshot(j.Quarantine, j, false); e != nil {
			return e
		}
	}
	owned, e := removalLauncherOwned(j)
	if e != nil {
		return e
	}
	if owned {
		if e = os.Remove(j.Receipt.BinPath); e != nil {
			return e
		}
		if e = syncDir(filepath.Dir(j.Receipt.BinPath)); e != nil {
			return e
		}
	}
	checkpoint := func(phase string) error {
		if hooks.checkpoint != nil {
			return hooks.checkpoint(phase)
		}
		return nil
	}
	if e = checkpoint("launcher-removed"); e != nil {
		return e
	}
	if quarantined {
		names := make([]string, 0, len(j.Entries))
		for n := range j.Entries {
			names = append(names, n)
		}
		// Children always precede their directories. Do not recursively delete
		// a path whose contents could have changed since the preflight.
		sort.Slice(names, func(i, k int) bool { return names[i] > names[k] })
		for _, n := range names {
			p := filepath.Join(j.Quarantine, filepath.FromSlash(n))
			if e = platform.CheckPath(p); e != nil {
				return e
			}
			exists, e := optionalExists(p)
			if e != nil {
				return e
			}
			if !exists {
				continue
			}
			if !j.Entries[n].Directory {
				h, _, e := fileDigest(p)
				if e != nil || h != j.Entries[n].SHA256 {
					return fail("uninstall-inventory-drift")
				}
			}
			// Re-check the recorded object immediately before unlinking it, so a
			// replacement file with identical bytes is refused rather than deleted.
			device, inode, e := removalObjectIdentity(p)
			if e != nil {
				return e
			}
			if device != j.Entries[n].Device || inode != j.Entries[n].Inode {
				return fail("uninstall-inventory-drift")
			}
			if e = os.Remove(p); e != nil {
				return e
			}
			if e = syncDir(filepath.Dir(p)); e != nil {
				return e
			}
			if e = checkpoint("entry-removed"); e != nil {
				return e
			}
		}
		if e = os.Remove(j.Quarantine); e != nil {
			return e
		}
		if e = syncDir(filepath.Dir(j.Quarantine)); e != nil {
			return e
		}
	}
	if e = checkpoint("root-removed"); e != nil {
		return e
	}
	if e = os.Remove(uninstallJournal(a)); e != nil {
		return e
	}
	return syncDir(filepath.Dir(uninstallJournal(a)))
}

func uninstallProgram(ctx context.Context, a platform.App, dry bool) (map[string]any, error) {
	if dry {
		return uninstallLocked(a, true, uninstallHooks{})
	}
	var result map[string]any
	e := platform.WithLock(ctx, a.Scope, func() error {
		var e error
		result, e = uninstallLocked(a, false, uninstallHooks{})
		return e
	})
	return result, e
}

func uninstallLocked(a platform.App, dry bool, hooks uninstallHooks) (map[string]any, error) {
	pending, e := optionalExists(uninstallJournal(a))
	if e != nil {
		return nil, e
	}
	if pending {
		if dry {
			return nil, fail("uninstall-recovery-required")
		}
		if e = recoverUninstallWithHooks(a, hooks); e != nil {
			return nil, e
		}
		result := notInstalled()
		result["changed"] = true
		result["recovered"] = true
		return result, nil
	}
	exists, e := optionalExists(installRoot(a))
	if e != nil {
		return nil, e
	}
	if !exists {
		result := notInstalled()
		result["dry_run"], result["changed"] = dry, false
		return result, nil
	}
	if !dry {
		if e = recoverInstall(a); e != nil {
			return nil, e
		}
	}
	j, e := collectRemoval(a)
	if e != nil {
		return nil, e
	}
	// Deleting a configured core inside the program generations would break
	// runtime preservation. Require an explicit adopt into separate core storage.
	if e = protectConfiguredCore(a, j.Root, j.Quarantine); e != nil {
		return nil, e
	}
	result := map[string]any{
		"dry_run": dry, "installed": !dry, "active_core_preserved": true,
		"removed":  []string{j.Receipt.BinPath, j.Root},
		"retained": []string{a.Scope.ConfigRoot, filepath.Join(a.Scope.DataRoot, "cores"), a.Scope.StateRoot},
	}
	if dry {
		result["installed"] = true
		return result, nil
	}
	// Validate serialized size before publication; the private journal is the
	// durable ownership authority once the installation receipt is removed.
	b, e := json.MarshalIndent(j, "", "  ")
	if e != nil || len(b) > 2<<20 {
		return nil, fail("uninstall-inventory-too-large")
	}
	if e = platform.WriteJSON(uninstallJournal(a), j); e != nil {
		return nil, e
	}
	if hooks.checkpoint != nil {
		if e = hooks.checkpoint("journal-published"); e != nil {
			return nil, e
		}
	}
	if e = recoverUninstallWithHooks(a, hooks); e != nil {
		return nil, e
	}
	result["installed"], result["changed"], result["status"] = false, true, "not-installed"
	return result, nil
}
