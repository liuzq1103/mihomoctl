//go:build unix

package routing

import "github.com/liuzq1103/mihomoctl/internal/platform"

// txObjectIdentity returns the identity of the filesystem object at path.
// The shared helper keeps one definition of the device and inode pair for
// every journal that binds an object.
func txObjectIdentity(path string) (string, error) { return platform.ObjectIdentity(path) }
