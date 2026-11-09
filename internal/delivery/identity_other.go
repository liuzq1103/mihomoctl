//go:build !linux

package delivery

import "os/exec"

func removalIdentity(p string) (uint64, uint64, error) { return 0, 0, usage("linux-required") }

func removalObjectIdentity(p string) (uint64, uint64, error) { return 0, 0, usage("linux-required") }

func trustedVersionBinary(p string, system bool) error { return usage("linux-required") }

func coreValidationIdentity(cmd *exec.Cmd, p string, system bool) error {
	return usage("linux-required")
}
func syncDir(p string) error { return nil }
