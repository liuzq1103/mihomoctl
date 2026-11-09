package delivery

import (
	"os"
	"path/filepath"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

// The receipt lives inside the program root, so it is removed together with
// the root. A copy of it lives outside the root, in the state directory, and
// that copy is the record that outlives the program tree: it names the
// launcher this installation published and the object that launcher is.
// Without it, an installation whose program root was lost leaves its launcher
// behind, the status reports an installation that does not exist, and every
// later installation is refused because the command is already there.
type installationRecord struct {
	Format  int     `json:"format"`
	Project string  `json:"project"`
	Receipt Receipt `json:"receipt"`
}

func installationRecordPath(a platform.App) string {
	return filepath.Join(a.Scope.StateRoot, "delivery-install.json")
}

// writeInstallationRecord copies the receipt outside the program root. The
// copy is written before the bootstrap journal is removed, so a crash in that
// window leaves the journal that still describes the publication.
func writeInstallationRecord(a platform.App, rec Receipt) error {
	if e := removalReceipt(a, rec); e != nil {
		return e
	}
	if e := platform.WriteJSON(installationRecordPath(a), installationRecord{Format: 1, Project: Project, Receipt: rec}); e != nil {
		return e
	}
	return syncDir(a.Scope.StateRoot)
}

// loadInstallationRecord reads the copy of the receipt that lives outside the
// program root. A record that does not describe a launcher of this project is
// refused: it is not authority to remove anything.
func loadInstallationRecord(a platform.App) (Receipt, bool, error) {
	exists, e := optionalExists(installationRecordPath(a))
	if e != nil || !exists {
		return Receipt{}, false, e
	}
	b, e := platform.ReadPrivate(installationRecordPath(a))
	if e != nil {
		return Receipt{}, false, e
	}
	var r installationRecord
	if e = StrictJSON(b, &r); e != nil {
		return Receipt{}, false, fail("installation-record-invalid")
	}
	if r.Format != 1 || r.Project != Project {
		return Receipt{}, false, fail("installation-record-invalid")
	}
	if e = removalReceipt(a, r.Receipt); e != nil {
		return Receipt{}, false, e
	}
	return r.Receipt, true, nil
}

func removeInstallationRecord(a platform.App) error {
	if e := os.Remove(installationRecordPath(a)); e != nil && !os.IsNotExist(e) {
		return e
	}
	return syncDir(a.Scope.StateRoot)
}

// orphanedLauncherOurs reports whether the object standing at the recorded
// launcher path is still this installation's launcher. A record that binds
// the launcher object owns it by identity: a replacement carrying identical
// bytes is a different object and never counts as ours. A record written
// before that binding keeps the guarantee it was written with, content
// identity, so a launcher that still hashes to the recorded digest is ours
// and any other object at the path is foreign.
func orphanedLauncherOurs(rec Receipt) (bool, error) {
	device, inode, e := removalObjectIdentity(rec.BinPath)
	if e != nil {
		return false, e
	}
	if rec.LauncherDevice != 0 || rec.LauncherInode != 0 {
		return device == rec.LauncherDevice && inode == rec.LauncherInode, nil
	}
	raw, e := os.ReadFile(rec.BinPath)
	if e != nil {
		return false, e
	}
	return platform.Hash(raw) == rec.LauncherSHA256, nil
}

// installationOrphan reports the launcher of an installation whose program
// root was lost. The launcher is ours only while the object at the path is
// still the object the record names under the guarantee the record was
// written with. A record whose launcher is gone describes an installation
// that left nothing behind.
func installationOrphan(a platform.App) (Receipt, bool, error) {
	rec, exists, e := loadInstallationRecord(a)
	if e != nil || !exists {
		return Receipt{}, false, e
	}
	present, e := optionalExists(rec.BinPath)
	if e != nil {
		return Receipt{}, false, e
	}
	if !present {
		return Receipt{}, false, nil
	}
	ours, e := orphanedLauncherOurs(rec)
	if e != nil {
		return Receipt{}, false, e
	}
	if !ours {
		return Receipt{}, false, nil
	}
	return rec, true, nil
}

// repairOrphanedInstallation removes the launcher of an installation whose
// program root was lost and drops the record that named it. The launcher can
// only fail now: the root it points at is gone. It is removed under the
// guarantee the record was written with — by object identity, or by content
// identity for a record from before object binding — so a foreign object
// that took its place is never deleted as if it were ours. The path of a
// removed launcher is returned; an empty path means that nothing of ours was
// left behind.
func repairOrphanedInstallation(a platform.App) (string, error) {
	rec, exists, e := loadInstallationRecord(a)
	if e != nil || !exists {
		return "", e
	}
	removed := ""
	present, e := optionalExists(rec.BinPath)
	if e != nil {
		return "", e
	}
	if present {
		ours, e := orphanedLauncherOurs(rec)
		if e != nil {
			return "", e
		}
		if ours {
			if e = os.Remove(rec.BinPath); e != nil {
				return "", e
			}
			if e = syncDir(filepath.Dir(rec.BinPath)); e != nil {
				return "", e
			}
			removed = rec.BinPath
		}
	}
	if e = removeInstallationRecord(a); e != nil {
		return "", e
	}
	return removed, nil
}
