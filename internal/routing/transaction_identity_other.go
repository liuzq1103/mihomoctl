//go:build !unix && !windows

package routing

// txObjectIdentity has no portable object identity outside unix and windows.
// The empty token tells the recovery that no identity can be proven for a
// path, so it falls back to the content check it has always applied.
func txObjectIdentity(path string) (string, error) { return "", nil }
