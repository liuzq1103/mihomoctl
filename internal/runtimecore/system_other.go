//go:build !linux

package runtimecore

import (
	"context"
	"github.com/liuzq1103/mihomoctl/internal/platform"
	"os"
	"path/filepath"
)

func accountIdentity(bool) (int, int, error)                            { return 0, 0, linuxRequired() }
func prepareServiceFiles(context.Context, platform.App, resolved) error { return linuxRequired() }
func systemBinaryOverlay(a platform.App, binary string) bool {
	return a.Scope.Contains(binary) && within(filepath.Join(a.Scope.DataRoot, "cores"), binary) && filepath.Base(binary) == "mihomo"
}
func ownsTun(identity, string) bool { return false }
func checkArtifactDir(p string) error {
	if e := platform.CheckPath(p); e != nil {
		return e
	}
	return os.MkdirAll(p, 0700)
}
func openCoreResource(a platform.App, p string) (*os.File, error) {
	if e := platform.CheckPath(p); e != nil {
		return nil, e
	}
	f, e := os.Open(p)
	if e != nil {
		return nil, e
	}
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() {
		f.Close()
		return nil, platform.Usage("validation-resource-untrusted")
	}
	return f, nil
}
func checkLogInfo(st os.FileInfo) error {
	if !st.Mode().IsRegular() {
		return platform.Usage("log-file-untrusted")
	}
	return nil
}
func readSystemConfig(p string) ([]byte, error) { return platform.ReadPrivate(p) }
func setSystemConfigMode(string, int) error     { return linuxRequired() }
