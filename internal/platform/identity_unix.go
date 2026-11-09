//go:build unix

package platform

import (
	"fmt"
	"os"
	"syscall"
)

// ObjectIdentity returns the identity of the filesystem object at path. A
// content hash cannot tell the object a transaction published from a foreign
// replacement that carries identical bytes, so the device and inode pair is
// captured as well and re-checked before anything is undone. Lstat only: the
// object must be identified without reading it, so a file whose content cannot
// be read is still identified.
func ObjectIdentity(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", nil
	}
	return fmt.Sprintf("%d:%d", uint64(st.Dev), uint64(st.Ino)), nil
}

// SyncDirectory makes the directory entries of path durable. A rename is only
// durable once the directory itself is flushed, so a publication that cannot
// confirm it has to report the failure instead of claiming success.
func SyncDirectory(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
