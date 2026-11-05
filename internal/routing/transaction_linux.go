//go:build linux

package routing

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

// fileOwnerIDs extracts uid/gid from a stat result.
func fileOwnerIDs(info os.FileInfo) (int, int) {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return int(st.Uid), int(st.Gid)
	}
	return 0, 0
}

// managedFileAcceptable enforces the managed private-file policy: user-scope
// files belong to the acting account with no group/other access; system-scope
// files belong to root and may carry exactly the service-group read bit the
// original mandated (0640), never group write or any other access.
func managedFileAcceptable(info os.FileInfo, system bool) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	if system {
		if int(st.Uid) != 0 {
			return false
		}
		return info.Mode().Perm()&0027 == 0
	}
	if int(st.Uid) != os.Geteuid() {
		return false
	}
	return info.Mode().Perm()&0077 == 0
}

// txAncestorsTrusted requires every existing ancestor directory from the
// destination up to and including its managed root to belong to root or the
// acting account without group/other write access. Ancestors above the
// managed root are outside this package's authority: the roots themselves are
// created and checked private (platform.PrivateDir), exactly like the
// original confined transactions to the managed tree.
func txAncestorsTrusted(path, stop string) bool {
	absolute := filepath.Clean(path)
	stop = filepath.Clean(stop)
	for {
		info, err := os.Lstat(absolute)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return false
			}
			st, ok := info.Sys().(*syscall.Stat_t)
			if !ok || (int(st.Uid) != 0 && int(st.Uid) != os.Geteuid()) || info.Mode().Perm()&0022 != 0 {
				return false
			}
		} else if !os.IsNotExist(err) {
			return false
		}
		if absolute == stop {
			return true
		}
		parent := filepath.Dir(absolute)
		if parent == absolute {
			// The stop point was not an ancestor: treat that as untrusted.
			return stop == ""
		}
		absolute = parent
	}
}

// txRestoreOwnership restores prior ownership after publishing over an
// existing file; best effort at publish time.
func txRestoreOwnership(path string, uid, gid int) {
	if os.Geteuid() != 0 {
		return
	}
	_ = os.Chown(path, uid, gid)
}

// txRestoreOwnershipVerified restores ownership during rollback and proves it
// took, the way the original raised on incomplete restoration.
func txRestoreOwnershipVerified(path string, uid, gid int) error {
	if os.Geteuid() != 0 {
		return nil
	}
	if info, err := os.Stat(path); err == nil {
		if currentUID, currentGID := fileOwnerIDs(info); currentUID != uid || currentGID != gid {
			if err := os.Chown(path, uid, gid); err != nil {
				return err
			}
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if currentUID, currentGID := fileOwnerIDs(info); currentUID != uid || currentGID != gid {
		return errOwnershipIncomplete
	}
	return nil
}

// errOwnershipIncomplete marks a rollback whose ownership restoration did not
// take; it becomes part of a rollback-failed report.
var errOwnershipIncomplete = errors.New("ownership restoration incomplete")

// fsyncDir makes a rename durable.
func fsyncDir(path string) error {
	handle, err := os.Open(path)
	if err != nil {
		return err
	}
	defer handle.Close()
	return handle.Sync()
}

var _ = platform.CheckPath
