//go:build linux

package runtimecore

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

const launchTokenKey = "MIHOMOCTL_GO_LAUNCH_TOKEN"

// platform owns the descriptor; prevent its flock surviving manager death in
// an exec'ed core or service utility without changing the shared package.
func preventLockInheritance(a platform.App) error {
	lock := filepath.Join(a.Scope.RuntimeRoot, "manager.lock")
	entries, e := os.ReadDir("/proc/self/fd")
	if e != nil {
		return e
	}
	for _, entry := range entries {
		fd, e := strconv.Atoi(entry.Name())
		if e != nil {
			continue
		}
		path, e := os.Readlink("/proc/self/fd/" + entry.Name())
		if e != nil || path != lock {
			continue
		}
		flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFD, 0)
		if errno != 0 {
			return errno
		}
		_, _, errno = syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_SETFD, flags|syscall.FD_CLOEXEC)
		if errno != 0 {
			return errno
		}
	}
	return nil
}
func openPrivateRegular(p string) (*os.File, error) {
	if e := platform.CheckPath(p); e != nil {
		return nil, e
	}
	fd, e := syscall.Open(p, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), p)
	st, e := f.Stat()
	if e != nil {
		f.Close()
		return nil, e
	}
	if e = checkLogInfo(st); e != nil {
		f.Close()
		return nil, e
	}
	return f, nil
}

func syncDirectory(p string) error {
	d, e := os.Open(p)
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
func findCompoundLaunches(a platform.App, c *compoundRecord) ([]identity, error) {
	out := []identity{}
	if len(c.Launches) == 0 {
		return out, nil
	}
	entries, e := os.ReadDir("/proc")
	if e != nil {
		return nil, platform.Usage("runtime-process-inventory-unavailable")
	}
	if len(entries) > 200000 {
		return nil, platform.Usage("runtime-process-inventory-too-large")
	}
	for _, entry := range entries {
		pid, e := strconv.Atoi(entry.Name())
		if e != nil || pid < 2 {
			continue
		}
		id, e := inspectIdentity(pid)
		if e != nil {
			continue
		}
		intents := []launchIntent{}
		for _, intent := range c.Launches {
			if id.Exe == intent.Binary && id.UID == intent.UID && id.Boot == intent.Boot && equalStrings(id.Args, []string{intent.Binary, "-d", a.Scope.CoreHome(), "-f", intent.Config}) {
				intents = append(intents, intent)
			}
		}
		if len(intents) == 0 {
			continue
		}
		f, e := os.Open(fmt.Sprintf("/proc/%d/environ", pid))
		if e != nil {
			if identityAlive(id) {
				return nil, platform.Usage("runtime-launch-ownership-unverified")
			}
			continue
		}
		raw, e := io.ReadAll(io.LimitReader(f, 1<<20))
		f.Close()
		if e != nil {
			return nil, platform.Usage("runtime-launch-ownership-unverified")
		}
		found := false
		for _, pair := range strings.Split(string(raw), "\x00") {
			key, value, ok := strings.Cut(pair, "=")
			if !ok || key != launchTokenKey {
				continue
			}
			for _, intent := range intents {
				if value == intent.Token {
					found = true
				}
			}
		}
		if found && identityAlive(id) {
			out = append(out, id)
		}
	}
	return out, nil
}
