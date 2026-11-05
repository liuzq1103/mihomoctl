//go:build !linux

package routing

import (
	"errors"
	"os"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

// Off Linux the platform foundation does not enforce POSIX ownership or
// permission bits (its checkOwner is a no-op), so the transaction mirrors that
// policy instead of inventing a stricter one.

func fileOwnerIDs(info os.FileInfo) (int, int) { return 0, 0 }

func managedFileAcceptable(info os.FileInfo, system bool) bool { return true }

func txAncestorsTrusted(path, stop string) bool { return true }

func txRestoreOwnership(path string, uid, gid int) {}

func txRestoreOwnershipVerified(path string, uid, gid int) error { return nil }

func fsyncDir(path string) error { return nil }

var (
	_ = errors.New
	_ = os.Chmod
	_ = platform.CheckPath
)
