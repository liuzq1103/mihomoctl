//go:build !unix && !windows

package platform

// ObjectIdentity has no portable object identity outside unix and windows.
// The empty token tells a recovery that no identity can be proven for a
// path, so it falls back to the content check it has always applied.
func ObjectIdentity(path string) (string, error) { return "", nil }

// SyncDirectory has no portable meaning outside unix: the publication is
// durable as far as this platform can tell.
func SyncDirectory(string) error { return nil }
