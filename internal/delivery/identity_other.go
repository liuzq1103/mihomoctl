//go:build !linux

package delivery

import "os/exec"

func removalIdentity(p string) (uint64, uint64, error) { return 0, 0, usage("linux-required") }

func removalObjectIdentity(p string) (uint64, uint64, error) { return 0, 0, usage("linux-required") }

// launcherIdentity has no device and inode pair off Linux, so no launcher
// object identity can be proven there and the receipt binding is not checked.
func launcherIdentity(p string) (uint64, uint64, error) { return 0, 0, nil }

func trustedVersionBinary(p string, system bool) error { return usage("linux-required") }

func coreValidationIdentity(cmd *exec.Cmd, p string, system bool) error {
	return usage("linux-required")
}
func syncDir(p string) error { return nil }
