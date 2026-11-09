//go:build linux

package delivery

import (
	"os"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

// Capture inode identity as well as bytes. Identical bytes from a replacement
// file do not authorize recovery to claim that file as our launcher.
func bootstrapIdentity(p string) (bootstrapFile, error) {
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
