//go:build linux

package runtimecore

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

func accountIdentity(create bool) (int, int, error) {
	u, e := user.Lookup(serviceAccount)
	if e != nil && create {
		if os.Geteuid() != 0 {
			return 0, 0, platform.Usage("system-requires-root")
		}
		if _, e = utility(context.Background(), "useradd", "--system", "--user-group", "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", serviceAccount); e != nil {
			return 0, 0, e
		}
		u, e = user.Lookup(serviceAccount)
	}
	if e != nil {
		return 0, 0, platform.Usage("service-account-missing")
	}
	uid, e := strconv.Atoi(u.Uid)
	if e != nil || uid == 0 {
		return 0, 0, platform.Usage("service-account-invalid")
	}
	gid, e := strconv.Atoi(u.Gid)
	return uid, gid, e
}
func prepareServiceFiles(ctx context.Context, a platform.App, x resolved) error {
	if !a.Scope.System {
		return platform.PrivateDir(a.Scope.CoreHome())
	}
	uid, gid, e := accountIdentity(true)
	if e != nil {
		return e
	}
	home := a.Scope.CoreHome()
	if e = platform.CheckPath(home); e != nil {
		return e
	}
	if e = platform.PrivateDir(a.Scope.DataRoot); e != nil {
		return e
	}
	if systemBinaryOverlay(a, x.Manager.Core.Binary) {
		if e = prepareSystemBinary(ctx, a, x.Manager.Core.Binary); e != nil {
			return e
		}
	}
	if e = os.Mkdir(home, 0700); e != nil && !os.IsExist(e) {
		return e
	}
	st, e := os.Stat(home)
	if e != nil {
		return e
	}
	s, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !st.IsDir() || st.Mode().Perm()&0077 != 0 || int(s.Uid) != 0 && int(s.Uid) != uid {
		return platform.Usage("core-home-untrusted")
	}
	if e = os.Chown(home, uid, gid); e != nil {
		return e
	}
	if e = setSystemConfigMode(x.Manager.Core.Config, gid); e != nil {
		return e
	}
	// BindPaths in the unit exposes just this service-owned directory below /run.
	// The private manager/state roots retain their 0700 permissions.
	p := filepath.Join(home, "managed-config.yaml")
	if e = platform.CheckPath(p); e != nil {
		return e
	}
	if old, e := os.Stat(p); e == nil {
		s, ok := old.Sys().(*syscall.Stat_t)
		if !ok || !old.Mode().IsRegular() || old.Mode().Perm()&0027 != 0 || int(s.Uid) != uid && s.Uid != 0 {
			return platform.Usage("service-config-untrusted")
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	f, e := os.CreateTemp(home, ".config-*")
	if e != nil {
		return e
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	config, e := platform.DecodeYAML(x.Text)
	if e != nil {
		f.Close()
		return e
	}
	for _, section := range []string{"proxy-providers", "rule-providers"} {
		for _, v := range platform.Map(config[section]) {
			p := platform.Map(v)
			raw := platform.String(p["path"])
			if filepath.IsAbs(raw) && within(home, raw) {
				rel, e := filepath.Rel(home, raw)
				if e != nil {
					f.Close()
					return e
				}
				p["path"] = filepath.Join(serviceHome(a), rel)
			}
		}
	}
	text, e := marshalYAML(config)
	if e != nil {
		f.Close()
		return e
	}
	if e = f.Chmod(0640); e == nil {
		_, e = f.Write(text)
	}
	if e == nil {
		e = f.Chown(0, gid)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	if e = os.Rename(tmp, p); e != nil {
		return e
	}
	return syncDirectory(home)
}
func systemBinaryOverlay(a platform.App, binary string) bool {
	return a.Scope.Contains(binary) && within(filepath.Join(a.Scope.DataRoot, "cores"), binary) && filepath.Base(binary) == "mihomo"
}
func prepareSystemBinary(ctx context.Context, a platform.App, binary string) error {
	target := filepath.Join(a.Scope.DataRoot, "service-binary", "mihomo")
	if e := platform.CheckPath(target); e != nil {
		return e
	}
	if e := platform.PrivateDir(filepath.Dir(target)); e != nil {
		return e
	}
	if st, e := os.Stat(target); e == nil {
		s, ok := st.Sys().(*syscall.Stat_t)
		if !ok || s.Uid != 0 || !st.Mode().IsRegular() || st.Mode().Perm() != 0755 {
			return platform.Usage("service-binary-untrusted")
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	source, _, e := hashResource(ctx, a, binary, "executable")
	if e != nil {
		return e
	}
	// Keep the staged inode when it already carries exactly the reviewed core.
	// Replacing it would unlink the executable of a running service: the
	// kernel then reports /proc/<pid>/exe with a " (deleted)" suffix and the
	// fail-closed identity proof rejects the process it just verified.
	if staged, _, e := hashResource(ctx, a, target, "executable"); e == nil && staged == source {
		return nil
	}
	hash, _, e := transferResource(ctx, a, binary, target, executableLimit)
	if e != nil {
		return e
	}
	current, _, e := hashResource(ctx, a, binary, "executable")
	if e != nil {
		return e
	}
	if current != hash {
		return platform.Usage("validation-inputs-changed")
	}
	if e = os.Chmod(target, 0755); e != nil {
		return e
	}
	f, e := os.Open(target)
	if e != nil {
		return e
	}
	e = f.Sync()
	f.Close()
	if e != nil {
		return e
	}
	return syncDirectory(filepath.Dir(target))
}
func setSystemConfigMode(p string, gid int) error {
	if e := platform.CheckPath(p); e != nil {
		return e
	}
	fd, e := syscall.Open(p, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if e != nil {
		return e
	}
	f := os.NewFile(uintptr(fd), p)
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return e
	}
	s, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !st.Mode().IsRegular() || s.Uid != 0 || st.Mode().Perm()&0137 != 0 {
		return platform.Usage("core-config-untrusted")
	}
	if e = f.Chown(0, gid); e != nil {
		return e
	}
	if e = f.Chmod(0640); e != nil {
		return e
	}
	return f.Sync()
}
func ownsTun(id identity, device string) bool {
	if !identityAlive(id) {
		return false
	}
	root := fmt.Sprintf("/proc/%d", id.PID)
	self, e := os.Stat("/proc/self/ns/net")
	if e != nil {
		return false
	}
	other, e := os.Stat(root + "/ns/net")
	if e != nil || !os.SameFile(self, other) {
		return false
	}
	entries, e := os.ReadDir(root + "/fdinfo")
	if e != nil {
		return false
	}
	for _, entry := range entries {
		target, e := os.Readlink(root + "/fd/" + entry.Name())
		if e != nil || target != "/dev/net/tun" {
			continue
		}
		b, e := os.ReadFile(root + "/fdinfo/" + entry.Name())
		if e != nil || len(b) > 4096 {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			k, v, ok := strings.Cut(line, ":")
			if ok && k == "iff" && strings.TrimSpace(v) == device && identityAlive(id) {
				return true
			}
		}
	}
	return false
}
func checkArtifactDir(p string) error {
	if e := platform.CheckPath(p); e != nil {
		return e
	}
	if e := os.MkdirAll(p, 0700); e != nil {
		return e
	}
	for q := p; ; q = filepath.Dir(q) {
		st, e := os.Stat(q)
		if e != nil {
			return e
		}
		s, ok := st.Sys().(*syscall.Stat_t)
		if !ok || !st.IsDir() || int(s.Uid) != 0 && int(s.Uid) != os.Geteuid() || st.Mode().Perm()&0022 != 0 {
			return platform.Usage("artifact-parent-untrusted")
		}
		if filepath.Dir(q) == q {
			break
		}
	}
	return nil
}
func openCoreResource(a platform.App, p string) (*os.File, error) {
	if e := platform.CheckPath(p); e != nil {
		return nil, e
	}
	allowedUIDs := map[uint32]bool{0: true, uint32(os.Geteuid()): true}
	if a.Scope.System {
		uid, _, e := accountIdentity(false)
		if e == nil {
			allowedUIDs[uint32(uid)] = true
		}
	}
	for q := filepath.Dir(p); ; q = filepath.Dir(q) {
		st, e := os.Stat(q)
		if e != nil {
			return nil, e
		}
		s, ok := st.Sys().(*syscall.Stat_t)
		if !ok || !st.IsDir() || !allowedUIDs[s.Uid] || st.Mode().Perm()&0022 != 0 {
			return nil, platform.Usage("validation-resource-untrusted")
		}
		if filepath.Dir(q) == q {
			break
		}
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
	s, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !st.Mode().IsRegular() || st.Mode().Perm()&0022 != 0 || !allowedUIDs[s.Uid] {
		f.Close()
		return nil, platform.Usage("validation-resource-untrusted")
	}
	return f, nil
}
func checkLogInfo(st os.FileInfo) error {
	s, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !st.Mode().IsRegular() || int(s.Uid) != os.Geteuid() || st.Mode().Perm()&0077 != 0 {
		return platform.Usage("log-file-untrusted")
	}
	return nil
}
func readSystemConfig(p string) ([]byte, error) {
	if e := platform.CheckPath(p); e != nil {
		return nil, e
	}
	fd, e := syscall.Open(p, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), p)
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return nil, e
	}
	s, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !st.Mode().IsRegular() || s.Uid != 0 || st.Mode().Perm()&0027 != 0 {
		return nil, platform.Usage("core-config-untrusted")
	}
	b, e := io.ReadAll(io.LimitReader(f, platform.Limit+1))
	if e != nil {
		return nil, e
	}
	if len(b) > platform.Limit {
		return nil, platform.Usage("config-too-large")
	}
	return b, nil
}
