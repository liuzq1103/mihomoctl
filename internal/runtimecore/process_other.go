//go:build !linux

package runtimecore

import (
	"context"
	"os"
	"os/exec"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

func linuxRequired() error { return platform.Usage("linux-required") }
func trustedExecutable(p string, system bool) error {
	if e := platform.CheckPath(p); e != nil {
		return e
	}
	st, e := os.Stat(p)
	if e != nil || !st.Mode().IsRegular() {
		return platform.Usage("core-unavailable")
	}
	return nil
}
func inspectIdentity(int) (identity, error)   { return identity{}, linuxRequired() }
func identityAlive(identity) bool             { return false }
func processExists(int) bool                  { return false }
func signalOwned(identity, bool) error        { return linuxRequired() }
func ownsListener(identity, endpoint) bool    { return false }
func detach(*exec.Cmd)                        {}
func reservePort(endpoint) (netCloser, error) { return nil, linuxRequired() }
func validationIdentity(context.Context, *exec.Cmd, platform.App, string) error {
	return linuxRequired()
}
func replaceProcess([]string, []string) error { return linuxRequired() }
func journalLogs(context.Context, []string, platform.Request, logRedactor) ([]byte, error) {
	return nil, linuxRequired()
}
