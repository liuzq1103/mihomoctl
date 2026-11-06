//go:build linux

package delivery

import (
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

func removalIdentity(p string) (uint64, uint64, error) {
	if e := platform.CheckPath(p); e != nil {
		return 0, 0, e
	}
	st, e := os.Lstat(p)
	if e != nil {
		return 0, 0, e
	}
	s, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !st.IsDir() || int(s.Uid) != os.Geteuid() || st.Mode().Perm()&0077 != 0 {
		return 0, 0, fail("uninstall-root-unowned")
	}
	return uint64(s.Dev), s.Ino, nil
}

func trustedVersionBinary(p string, system bool) error {
	if !filepath.IsAbs(p) || filepath.Clean(p) != p {
		return fail("core-path-untrusted")
	}
	if e := platform.CheckPath(p); e != nil {
		return e
	}
	for q := p; ; q = filepath.Dir(q) {
		st, e := os.Stat(q)
		if e != nil {
			return e
		}
		s, ok := st.Sys().(*syscall.Stat_t)
		if !ok || (s.Uid != 0 && int(s.Uid) != os.Geteuid()) || (system && s.Uid != 0) {
			return fail("core-owner-untrusted")
		}
		// A root-owned sticky ancestor such as /tmp cannot have a private
		// user-owned child replaced by a different user.
		stickyRoot := st.IsDir() && s.Uid == 0 && st.Mode()&os.ModeSticky != 0
		if st.Mode().Perm()&0022 != 0 && !stickyRoot {
			return fail("core-path-writable")
		}
		if q == p && (!st.Mode().IsRegular() || st.Mode().Perm()&0111 == 0 || st.Size() > MaxExpanded) {
			return fail("core-not-executable")
		}
		if filepath.Dir(q) == q {
			break
		}
	}
	return nil
}

func coreValidationIdentity(cmd *exec.Cmd, p string, system bool) error {
	if os.Geteuid() != 0 {
		return nil
	}
	u, e := user.Lookup("nobody")
	if e != nil {
		return fail("core-validator-unavailable")
	}
	uid, e := strconv.ParseUint(u.Uid, 10, 32)
	if e != nil || uid == 0 {
		return fail("core-validator-invalid")
	}
	gid, e := strconv.ParseUint(u.Gid, 10, 32)
	if e != nil {
		return e
	}
	// Private scope ancestors are intentionally inaccessible. Copy only the trusted
	// candidate into an isolated traversable directory before dropping privilege.
	dir, e := os.MkdirTemp("", "mihomoctl-go-core-check-*")
	if e != nil {
		return e
	}
	b, e := readBoundedFile(p, MaxExpanded)
	if e == nil {
		e = os.WriteFile(filepath.Join(dir, "mihomo"), b, 0755)
	}
	if e == nil {
		e = os.Chmod(dir, 0755)
	}
	if e != nil {
		os.RemoveAll(dir)
		return e
	}
	cmd.Path = filepath.Join(dir, "mihomo")
	cmd.Args[0] = cmd.Path
	cmd.Dir = dir
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{}}}
	// Command.WaitDelay does not offer cleanup callbacks; caller owns cleanup via cmd.Dir.
	return nil
}

func syncDir(p string) error {
	d, e := os.Open(p)
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
