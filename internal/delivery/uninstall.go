package delivery

import (
	"context"
	"os"
	"path/filepath"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

func uninstallJournal(a platform.App) string {
	return filepath.Join(a.Scope.StateRoot, "delivery-uninstall.json")
}

func uninstallStage(a platform.App) string {
	return filepath.Join(a.Scope.DataRoot, ".install-uninstall-partial")
}

func validUninstallJournal(a platform.App, j uninstallPending) error {
	if j.Format != 2 || j.Root != installRoot(a) || j.Stage != uninstallStage(a) ||
		!filepath.IsAbs(j.Launcher) || filepath.Base(j.Launcher) != "mihomoctl" ||
		!generationPattern.MatchString(j.ReceiptHash) || !generationPattern.MatchString(j.LauncherHash) {
		return fail("uninstall-journal-invalid")
	}
	return nil
}

func validateOwnedTree(root string) error {
	if e := platform.CheckPath(root); e != nil {
		return e
	}
	st, e := os.Lstat(root)
	if e != nil || !st.IsDir() {
		return fail("installation-root-invalid")
	}
	return filepath.WalkDir(root, func(p string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		info, ie := d.Info()
		if ie != nil {
			return ie
		}
		if !d.IsDir() && !info.Mode().IsRegular() {
			return fail("installation-tree-unowned")
		}
		return nil
	})
}

func optionalExists(path string) (bool, error) {
	if _, e := os.Lstat(path); os.IsNotExist(e) {
		return false, nil
	} else if e != nil {
		return false, e
	}
	return true, nil
}

func notInstalled() map[string]any {
	return map[string]any{"installed": false, "status": "not-installed", "version": nil, "active_core_preserved": true}
}

func uninstallProgram(ctx context.Context, a platform.App, dry bool) (map[string]any, error) {
	root := installRoot(a)
	rootExists, e := optionalExists(root)
	if e != nil {
		return nil, e
	}
	stageExists, e := optionalExists(uninstallStage(a))
	if e != nil {
		return nil, e
	}
	journalExists, e := optionalExists(uninstallJournal(a))
	if e != nil {
		return nil, e
	}
	if !rootExists && !journalExists {
		if stageExists {
			return nil, fail("uninstall-partial-without-journal")
		}
		return notInstalled(), nil
	}
	rec, e := readReceipt(a)
	if e != nil {
		return nil, e
	}
	current, e := readCurrent(root)
	if e != nil {
		return nil, e
	}
	if _, _, e = generation(root, current); e != nil {
		return nil, e
	}
	if e = validateOwnedTree(root); e != nil {
		return nil, e
	}
	data := map[string]any{
		"dry_run": dry, "installed": true, "active_core_preserved": true,
		"removed":  []string{rec.BinPath, root},
		"retained": []string{a.Scope.ConfigRoot, a.Scope.DataRoot, a.Scope.StateRoot, filepath.Join(a.Scope.DataRoot, "cores")},
	}
	if dry {
		return data, nil
	}
	receiptBytes, e := platform.ReadPrivate(filepath.Join(root, "receipt.json"))
	if e != nil {
		return nil, e
	}
	journal := uninstallPending{2, root, uninstallStage(a), rec.BinPath, rec.LauncherSHA256, platform.Hash(receiptBytes)}
	if e = validUninstallJournal(a, journal); e != nil {
		return nil, e
	}
	e = platform.WithLock(ctx, a.Scope, func() error {
		if e := recoverUninstall(a); e != nil {
			return e
		}
		if e = startUninstall(a, journal); e != nil {
			return e
		}
		if exists, e := optionalExists(root); e != nil || exists {
			return fail("uninstall-installation-root-remains")
		}
		if exists, e := optionalExists(rec.BinPath); e != nil || exists {
			return fail("uninstall-launcher-remains")
		}
		return nil
	})
	if e != nil {
		return nil, e
	}
	data["changed"] = true
	data["installed"] = false
	data["status"] = "not-installed"
	return data, nil
}

func startUninstall(a platform.App, journal uninstallPending) error {
	if e := platform.WriteJSON(uninstallJournal(a), journal); e != nil {
		return e
	}
	return recoverUninstall(a)
}

func recoverUninstall(a platform.App) error {
	p := uninstallJournal(a)
	exists, e := optionalExists(p)
	if e != nil {
		return e
	}
	if !exists {
		return nil
	}
	raw, e := platform.ReadPrivate(p)
	if e != nil {
		return e
	}
	var journal uninstallPending
	if e := StrictJSON(raw, &journal); e != nil {
		return fail("uninstall-journal-invalid")
	}
	if e := validUninstallJournal(a, journal); e != nil {
		return e
	}
	launcherExists, e := optionalExists(journal.Launcher)
	if e != nil {
		return e
	}
	if launcherExists {
		b, e := platform.ReadPrivate(journal.Launcher)
		if e != nil || platform.Hash(b) != journal.LauncherHash {
			return fail("uninstall-launcher-drift")
		}
	}
	rootExists, e := optionalExists(journal.Root)
	if e != nil {
		return e
	}
	if !rootExists && !launcherExists {
		if e := os.Remove(p); e != nil && !os.IsNotExist(e) {
			return e
		}
		return syncDir(filepath.Dir(p))
	}
	if rootExists {
		if e := validateOwnedTree(journal.Root); e != nil {
			return e
		}
	}
	if launcherExists {
		if e := os.Remove(journal.Launcher); e != nil && !os.IsNotExist(e) {
			return e
		}
		if e := syncDir(filepath.Dir(journal.Launcher)); e != nil {
			return e
		}
	}
	if rootExists {
		var dirs []string
		e := filepath.WalkDir(journal.Root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if path != journal.Root {
					dirs = append(dirs, path)
				}
				return nil
			}
			info, ie := d.Info()
			if ie != nil || !info.Mode().IsRegular() {
				return fail("installation-tree-unowned")
			}
			return os.Remove(path)
		})
		if e != nil {
			return e
		}
		for i := len(dirs) - 1; i >= 0; i-- {
			_ = os.Remove(dirs[i])
		}
		if e := os.Remove(journal.Root); e != nil {
			return e
		}
	}
	if e := os.Remove(p); e != nil && !os.IsNotExist(e) {
		return e
	}
	return syncDir(filepath.Dir(p))
}
