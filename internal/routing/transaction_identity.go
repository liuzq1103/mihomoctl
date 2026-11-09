//go:build unix

package routing

import (
	"fmt"
	"os"
	"syscall"
)

// txObjectIdentity returns the identity of the filesystem object at path.
// A content hash cannot tell the object a transaction published from a
// foreign replacement that carries identical bytes, so the device and inode
// pair is captured as well and re-checked before anything is undone. Lstat
// only: the object must be identified without reading it, so a file whose
// content cannot be read is still identified.
func txObjectIdentity(path string) (string, error) {
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
