//go:build linux

package delivery

import (
	"errors"
	"os"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

// Capture inode identity as well as bytes. Identical bytes from a replacement
// file do not authorize recovery to claim that file as our launcher. It is a
// variable so a test can make one inventoried object unobservable.
var bootstrapIdentity = func(p string) (bootstrapFile, error) {
	var out bootstrapFile
	if e := platform.CheckPath(p); e != nil {
		return out, e
	}
	st, e := os.Lstat(p)
	if e != nil {
		return out, e
	}
	s, ok := st.Sys().(*syscall.Stat_t)
	if !ok || int(s.Uid) != os.Geteuid() || st.Mode().Perm()&0022 != 0 ||
		(!st.IsDir() && !st.Mode().IsRegular()) {
		return out, fail("bootstrap-file-unowned")
	}
	out = bootstrapFile{Directory: st.IsDir(), Mode: uint32(st.Mode().Perm()), Device: uint64(s.Dev), Inode: s.Ino}
	if !out.Directory {
		out.SHA256, _, e = fileDigest(p)
	}
	return out, e
}

// publishRollback reports a publication failure that can never succeed on this
// kernel or filesystem. Such a failure must be rolled back instead of leaving
// a journal behind that refuses every later command.
func publishRollback(e error) (string, bool) {
	switch {
	case errors.Is(e, syscall.ENOSYS), errors.Is(e, syscall.EINVAL), errors.Is(e, syscall.EOPNOTSUPP):
		return "bootstrap-publish-unsupported", true
	}
	return "", false
}

// linkRollback reports a launcher publication failure that can never succeed
// on this filesystem. A launcher is published as a hard link; a filesystem
// that refuses hard links outright (vfat and exfat return EPERM, some network
// filesystems EOPNOTSUPP, a bin directory on another device EXDEV) fails
// AFTER the program root has already been renamed into place, and every later
// recovery would retry the same impossible link forever. Such a failure is
// rolled back — the journal names the published root, so the abandonment can
// remove it — instead of wedging the scope. Errnos an operator can fix
// without redoing the installation (EACCES, ENOSPC, EROFS, EIO) stay
// retryable: recovery finishes once the environment is repaired.
func linkRollback(e error) (string, bool) {
	switch {
	case errors.Is(e, syscall.ENOSYS), errors.Is(e, syscall.EINVAL), errors.Is(e, syscall.EOPNOTSUPP),
		errors.Is(e, syscall.EPERM), errors.Is(e, syscall.EMLINK), errors.Is(e, syscall.EXDEV):
		return "bootstrap-launcher-link-unsupported", true
	}
	return "", false
}

// bootstrapLink is the launcher publication. It is a variable so a test can
// make the filesystem's answer to link(2) observable.
var bootstrapLink = os.Link

// renameat2(RENAME_NOREPLACE) also refuses an existing empty foreign directory.
// No fallback to overwrite-capable rename is safe for installation publication.
func publishBootstrapRoot(from, to string) error {
	var number uintptr
	switch runtime.GOARCH {
	case "amd64":
		number = 316
	case "arm64":
		number = 276
	default:
		return usage("bootstrap-platform-unsupported")
	}
	src, e := syscall.BytePtrFromString(from)
	if e != nil {
		return e
	}
	dst, e := syscall.BytePtrFromString(to)
	if e != nil {
		return e
	}
	atFDCWD := ^uintptr(99) // -100
	_, _, errno := syscall.Syscall6(number, atFDCWD, uintptr(unsafe.Pointer(src)), atFDCWD, uintptr(unsafe.Pointer(dst)), 1, 0)
	runtime.KeepAlive(src)
	runtime.KeepAlive(dst)
	if errno != 0 {
		return errno
	}
	return nil
}
