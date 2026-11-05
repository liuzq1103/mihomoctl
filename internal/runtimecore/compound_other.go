//go:build !linux

package runtimecore

import (
	"github.com/liuzq1103/mihomoctl/internal/platform"
	"os"
)

const launchTokenKey = "MIHOMOCTL_GO_LAUNCH_TOKEN"

func preventLockInheritance(platform.App) error { return nil }
func openPrivateRegular(p string) (*os.File, error) {
	if e := platform.CheckPath(p); e != nil {
		return nil, e
	}
	st, e := os.Lstat(p)
	if e != nil {
		return nil, e
	}
	if !st.Mode().IsRegular() {
		return nil, platform.Usage("unsafe-file")
	}
	return os.Open(p)
}

func syncDirectory(string) error { return nil }
func findCompoundLaunches(platform.App, *compoundRecord) ([]identity, error) {
	return nil, linuxRequired()
}
