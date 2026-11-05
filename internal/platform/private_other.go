//go:build !linux

package platform

import (
	"context"
	"os"
)

func OpenRegular(path string) (*os.File, error) {
	if e := CheckPath(path); e != nil {
		return nil, e
	}
	st, e := os.Lstat(path)
	if e != nil || !st.Mode().IsRegular() {
		return nil, Usage("unsafe-file")
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	st, e = f.Stat()
	if e != nil || !st.Mode().IsRegular() {
		f.Close()
		return nil, Usage("unsafe-file")
	}
	return f, nil
}

func checkOwner(st os.FileInfo, private bool) error { return nil }
func withLock(ctx context.Context, path string, fn func() error) error {
	return Usage("linux-required")
}
