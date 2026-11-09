//go:build linux

package runtimecore

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

func trustedExecutable(p string, system bool) error {
	if !absolute(p) {
		return platform.Usage("core-path-invalid")
	}
	if e := platform.CheckPath(p); e != nil {
		return e
	}
	st, e := os.Stat(p)
	if e != nil {
		return missingCoreError(p, e)
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0111 == 0 || st.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
		return platform.Usage("core-unavailable")
	}
	for q := p; ; q = filepath.Dir(q) {
		st, e := os.Stat(q)
		if e != nil {
			return platform.Usage("core-untrusted")
		}
		s, ok := st.Sys().(*syscall.Stat_t)
		if !ok || int(s.Uid) != 0 && int(s.Uid) != os.Geteuid() || system && s.Uid != 0 || st.Mode().Perm()&0022 != 0 {
			return platform.Usage("core-untrusted")
		}
		if filepath.Dir(q) == q {
			break
		}
	}
	return nil
}
func inspectIdentity(pid int) (identity, error) {
	var id identity
	root := fmt.Sprintf("/proc/%d", pid)
	stat, e := os.ReadFile(root + "/stat")
	if e != nil {
		return id, e
	}
	tail := strings.LastIndexByte(string(stat), ')')
	if tail < 0 {
		return id, platform.Usage("runtime-identity-invalid")
	}
	fields := strings.Fields(string(stat)[tail+1:])
	if len(fields) < 20 || fields[0] == "Z" || fields[0] == "X" {
		return id, os.ErrNotExist
	}
	st, e := os.Stat(root)
	if e != nil {
		return id, e
	}
	s, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return id, platform.Usage("runtime-identity-invalid")
	}
	exe, e := os.Readlink(root + "/exe")
	if e != nil {
		return id, e
	}
	boot, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if e != nil {
		return id, e
	}
	args, e := os.ReadFile(root + "/cmdline")
	if e != nil {
		return id, e
	}
	id = identity{pid, int(s.Uid), fields[19], strings.TrimSpace(string(boot)), exe, strings.Split(strings.TrimSuffix(string(args), "\x00"), "\x00")}
	return id, nil
}
func identityAlive(id identity) bool {
	now, e := inspectIdentity(id.PID)
	return e == nil && now.UID == id.UID && now.Start == id.Start && now.Boot == id.Boot && now.Exe == id.Exe && equalStrings(now.Args, id.Args)
}
func processExists(pid int) bool { _, e := inspectIdentity(pid); return e == nil || !os.IsNotExist(e) }
func signalOwned(id identity, kill bool) error {
	// pidfd pins the kernel process identity across the signal operation. Refuse
	// signalling on kernels without pidfd support instead of risking PID reuse.
	fd, _, errno := syscall.Syscall(434, uintptr(id.PID), 0, 0)
	if errno != 0 {
		if errno == syscall.ESRCH {
			return nil
		}
		return platform.Usage("pidfd-unavailable")
	}
	defer syscall.Close(int(fd))
	if !identityAlive(id) {
		return platform.Usage("runtime-identity-mismatch")
	}
	sig := syscall.SIGTERM
	if kill {
		sig = syscall.SIGKILL
	}
	_, _, errno = syscall.Syscall6(424, fd, uintptr(sig), 0, 0, 0, 0)
	if errno != 0 && errno != syscall.ESRCH {
		return platform.Fail("runtime-signal-failed")
	}
	return nil
}
func ownsListener(id identity, ep endpoint) bool {
	if !identityAlive(id) {
		return false
	}
	root := fmt.Sprintf("/proc/%d", id.PID)
	entries, e := os.ReadDir(root + "/fd")
	if e != nil {
		return false
	}
	sockets := map[string]bool{}
	for _, f := range entries {
		p, e := os.Readlink(root + "/fd/" + f.Name())
		if e == nil && strings.HasPrefix(p, "socket:[") {
			sockets[strings.TrimSuffix(strings.TrimPrefix(p, "socket:["), "]")] = true
		}
	}
	for _, file := range []string{"tcp", "tcp6"} {
		b, e := os.ReadFile(root + "/net/" + file)
		if e != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			cols := strings.Fields(line)
			if len(cols) < 10 || cols[3] != "0A" || !sockets[cols[9]] {
				continue
			}
			host, port, ok := strings.Cut(cols[1], ":")
			if !ok {
				continue
			}
			n, e := strconv.ParseInt(port, 16, 32)
			if e != nil || int(n) != ep.Port {
				continue
			}
			if procIP(host) == ep.Address && identityAlive(id) {
				return true
			}
		}
	}
	return false
}
func procIP(s string) string {
	var ip net.IP
	if len(s) == 8 {
		ip = make(net.IP, 4)
	} else if len(s) == 32 {
		ip = make(net.IP, 16)
	} else {
		return ""
	}
	for i := 0; i < len(ip); i++ {
		word := i / 4 * 8
		offset := word + (3-i%4)*2
		n, e := strconv.ParseUint(s[offset:offset+2], 16, 8)
		if e != nil {
			return ""
		}
		ip[i] = byte(n)
	}
	return ip.String()
}

func listenerPresent(ep endpoint) bool {
	for _, name := range []string{"tcp", "tcp6"} {
		b, err := os.ReadFile("/proc/net/" + name)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			cols := strings.Fields(line)
			if len(cols) < 4 || cols[3] != "0A" {
				continue
			}
			host, port, ok := strings.Cut(cols[1], ":")
			n, err := strconv.ParseInt(port, 16, 32)
			if ok && err == nil && int(n) == ep.Port && procIP(host) == ep.Address {
				return true
			}
		}
	}
	return false
}
func detach(cmd *exec.Cmd)                       { cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} }
func reservePort(ep endpoint) (netCloser, error) { return net.Listen("tcp", ep.address()) }
func validationIdentity(ctx context.Context, cmd *exec.Cmd, a platform.App, dir string) error {
	if os.Geteuid() != 0 {
		return nil
	}
	name := "nobody"
	if a.Scope.System {
		name = serviceAccount
	}
	u, e := user.Lookup(name)
	if e != nil {
		return platform.Usage("service-account-missing")
	}
	uid, e := strconv.Atoi(u.Uid)
	if e != nil || uid == 0 {
		return platform.Usage("core-root-execution-refused")
	}
	gid, e := strconv.Atoi(u.Gid)
	if e != nil {
		return e
	}
	// The reviewed core may be below root-private delivery directories. Execute
	// only an isolated verified copy after dropping privileges; never weaken the
	// original binary or traverse its private ancestors as the service account.
	if e = trustedExecutable(cmd.Path, a.Scope.System); e != nil {
		return e
	}
	source, e := os.Open(cmd.Path)
	if e != nil {
		return e
	}
	defer source.Close()
	st, e := source.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Size() > executableLimit {
		return platform.Usage("core-untrusted")
	}
	execDir, e := os.MkdirTemp(dir, ".validator-bin-")
	if e != nil {
		return e
	}
	isolated := filepath.Join(execDir, "mihomo")
	out, e := os.OpenFile(isolated, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0700)
	if e != nil {
		return e
	}
	size, e := io.Copy(out, &contextReader{ctx: ctx, reader: io.LimitReader(source, executableLimit+1)})
	if e == nil {
		e = out.Sync()
	}
	ce := out.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	after, e := source.Stat()
	if e != nil || size > executableLimit || st.Size() != size || st.ModTime() != after.ModTime() {
		return platform.Usage("validation-inputs-changed")
	}
	cmd.Path = isolated
	cmd.Args[0] = isolated
	if e = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Chown(p, uid, gid)
	}); e != nil {
		return e
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{uint32(gid)}}}
	cmd.Dir = dir
	return nil
}
func replaceProcess(child, env []string) error {
	p, e := exec.LookPath(child[0])
	if e != nil {
		return platform.Usage("child-unavailable")
	}
	if e = syscall.Exec(p, child, env); e != nil {
		return platform.Usage("child-exec-failed")
	}
	return nil
}
func journalLogs(ctx context.Context, args []string, r platform.Request, redactor logRedactor) ([]byte, error) {
	path, e := exec.LookPath("journalctl")
	if e != nil {
		return nil, platform.Fail("logs-unavailable")
	}
	if e = trustedExecutable(path, os.Geteuid() == 0); e != nil {
		return nil, e
	}
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = cleanEnvironment(true, nil)
	return readJournalCommand(ctx, cmd, r, redactor)
}
func readJournalCommand(ctx context.Context, cmd *exec.Cmd, r platform.Request, redactor logRedactor) ([]byte, error) {
	cmd.Stderr = nil
	if r.Has("follow") {
		if r.Output == nil {
			return nil, platform.Usage("output-required")
		}
		cmd.Stdout = &redactedLogStream{Writer: r.Output, Redactor: redactor}
		stream := cmd.Stdout.(*redactedLogStream)
		if e := cmd.Run(); e != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, platform.Fail("logs-unavailable")
		}
		return nil, stream.Flush()
	}
	pipe, e := cmd.StdoutPipe()
	if e != nil {
		return nil, platform.Fail("logs-unavailable")
	}
	if e = cmd.Start(); e != nil {
		return nil, platform.Fail("logs-unavailable")
	}
	reader := bufio.NewReader(io.LimitReader(pipe, platform.Limit+1))
	var output strings.Builder
	count := 0
	for {
		fragment, e := reader.ReadString('\n')
		count += len(fragment)
		if count > platform.Limit {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			return nil, platform.Fail("logs-too-large")
		}
		output.WriteString(fragment)
		if e != nil {
			if !errors.Is(e, io.EOF) {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
				return nil, platform.Fail("logs-unavailable")
			}
			break
		}
	}
	if e = cmd.Wait(); e != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, platform.Fail("logs-unavailable")
	}
	return []byte(output.String()), nil
}
