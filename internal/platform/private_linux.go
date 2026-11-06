//go:build linux

package platform

import (
	"context"
	"os"
	"syscall"
	"time"
)

// OpenRegular cannot block on FIFOs and checks the opened inode, closing the
// lstat/open race as well as refusing symlinks at the leaf.
func OpenRegular(path string) (*os.File, error) {
	if e := CheckPath(path); e != nil {
		return nil, e
	}
	fd, e := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return nil, Usage("unsafe-file")
	}
	f := os.NewFile(uintptr(fd), path)
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() {
		f.Close()
		return nil, Usage("unsafe-file")
	}
	return f, nil
}

func checkOwner(st os.FileInfo, private bool) error {
	s, ok := st.Sys().(*syscall.Stat_t)
	if !ok || int(s.Uid) != os.Geteuid() {
		return Usage("owner-mismatch")
	}
	if private && st.Mode().Perm()&0077 != 0 {
		return Usage("private-permissions-required")
	}
	return nil
}
func withLock(ctx context.Context, path string, fn func() error) error {
	if e := CheckPath(path); e != nil {
		return e
	}
	fd, e := syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if e != nil {
		return e
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return e
	}
	if e = checkOwner(st, true); e != nil {
		return e
	}
	for {
		e = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
		if e == nil {
			break
		}
		if e != syscall.EWOULDBLOCK {
			return e
		}
		select {
		case <-ctx.Done():
			return Usage("lock-timeout")
		case <-time.After(25 * time.Millisecond):
		}
	}
	defer syscall.Flock(fd, syscall.LOCK_UN)
	return fn()
}
