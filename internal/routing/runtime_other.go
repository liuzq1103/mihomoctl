//go:build !linux

package routing

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

// execCmd aliases the command type so the tagged identity hook shares it.
type execCmd = exec.Cmd

// runtimeOwner is Linux-only: /proc-based identity proofs have no equivalent
// here, so the ownership proof is reported unavailable rather than guessed.
type runtimeOwner struct{}

// newRuntimeOwner returns nil on non-Linux platforms; verify() then performs
// only the anonymous/authorized controller probes.
func newRuntimeOwner(a platform.App, manager map[string]any) *runtimeOwner { return nil }

// requireOwner is unreachable (owner is always nil off Linux).
func (r *runtimeOwner) requireOwner(ctx context.Context, address string, port int) error {
	return errors.New("unreachable")
}

// trustedCoreExecutable performs the portable checks off Linux.
func trustedCoreExecutable(p string, system bool) error {
	if p == "" || !filepath.IsAbs(p) {
		return control("core-path-invalid", exitUnverify)
	}
	for q := p; ; q = filepath.Dir(q) {
		if st, err := os.Lstat(q); err == nil && st.Mode()&os.ModeSymlink != 0 {
			return control("symlink-refused", exitUnverify)
		}
		if filepath.Dir(q) == q {
			break
		}
	}
	st, err := os.Stat(p)
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0111 == 0 {
		return control("core-unavailable", exitUnverify)
	}
	return nil
}

// serviceAccountUID is unavailable off Linux.
func serviceAccountUID() int { return -1 }

// nobodyUID is unavailable off Linux.
func nobodyUID() int { return -1 }

// chownDashboardAsset is a no-op off Linux.
func chownDashboardAsset(path string) error { return nil }

// chownTree is a no-op off Linux.
func chownTree(root string, uid, gid int) error { return nil }

// validationIdentity applies the credential drop for core validation; there
// is no portable equivalent.
func validationIdentity(cmd *execCmd, uid int) {}

// validationResourceOwned has no portable ownership equivalent off Linux.
func validationResourceOwned(st os.FileInfo, system bool) bool { return true }

// fileOwnedPrivate has no portable ownership equivalent off Linux; the
// regular-file check remains.
func fileOwnedPrivate(info os.FileInfo) bool { return info.Mode().IsRegular() }

// pathOwnedBy has no portable ownership equivalent off Linux.
func pathOwnedBy(info os.FileInfo, uids ...int) bool { return true }

// checkAncestorsOwned performs the portable checks off Linux: no symlinks, no
// group/other writable ancestor directories.
func checkAncestorsOwned(path string, owner int) error {
	absolute := filepath.Clean(path)
	for {
		st, err := os.Lstat(absolute)
		if err == nil {
			if st.Mode()&os.ModeSymlink != 0 {
				return control("subscription-provider-path-unsafe", exitUnverify)
			}
			if st.IsDir() && st.Mode().Perm()&0o022 != 0 {
				return control("subscription-provider-path-unsafe", exitUnverify)
			}
		} else if !os.IsNotExist(err) {
			return control("subscription-provider-path-unsafe", exitUnverify)
		}
		parent := filepath.Dir(absolute)
		if parent == absolute {
			break
		}
		absolute = parent
	}
	return nil
}

// rulesOwnershipExact reports that exact POSIX ownership/mode equality cannot
// be enforced off Linux; type and symlink checks still apply.
func rulesOwnershipExact() bool { return false }

// rulesOwnerCheck is unreachable off Linux (rulesOwnershipExact is false).
func rulesOwnerCheck(info os.FileInfo, kind string) error { return nil }

var _ = context.Background
