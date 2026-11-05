//go:build linux

package routing

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

// runtimeOwner proves that the loopback controller listener belongs to the
// managed core before any credential is sent to it. It mirrors the original
// Client.verify managed path: the running identity must be alive and must own
// the listening socket.
type runtimeOwner struct {
	binary    string
	config    string
	home      string
	backend   string
	system    bool
	statePath string
}

const goUnitName = "mihomoctl-go.service"
const goServiceAccount = "mihomoctl-go"

// newRuntimeOwner resolves the managed runtime identity sources from the
// manager document. A nil result skips the ownership proof (never weakens it:
// the anonymous/authorized probes still run).
func newRuntimeOwner(a platform.App, manager map[string]any) *runtimeOwner {
	core := platform.Map(manager["core"])
	owner := &runtimeOwner{
		binary:    platform.String(core["binary"]),
		config:    platform.String(core["config"]),
		home:      a.Scope.CoreHome(),
		backend:   platform.String(core["backend"]),
		system:    a.Scope.System,
		statePath: a.Scope.RuntimeState(),
	}
	if owner.binary == "" || owner.config == "" {
		return nil
	}
	return owner
}

type goIdentity struct {
	PID   int      `json:"pid"`
	UID   int      `json:"uid"`
	Start string   `json:"start_time"`
	Boot  string   `json:"boot_id"`
	Exe   string   `json:"exe"`
	Args  []string `json:"argv"`
}

type goRuntimeState struct {
	Version   int        `json:"version"`
	Namespace string     `json:"namespace"`
	Scope     string     `json:"scope"`
	Config    string     `json:"config"`
	Home      string     `json:"home"`
	Identity  goIdentity `json:"identity"`
}

// requireOwner verifies the listener at address:port is owned by the managed
// running core.
func (r *runtimeOwner) requireOwner(ctx context.Context, address string, port int) error {
	id, err := r.runningIdentity(ctx)
	if err != nil {
		return control("controller-runtime-ownership-unverified", exitFail)
	}
	if id == nil || !r.identityAlive(id) || !ownsLoopback(id.PID, address, port) {
		return control("controller-runtime-ownership-unverified", exitFail)
	}
	return nil
}

// runningIdentity returns the managed core identity for the configured
// backend: the process state file, or the systemd unit MainPID.
func (r *runtimeOwner) runningIdentity(ctx context.Context) (*goIdentity, error) {
	if r.backend == "systemd" {
		args := []string{"show", goUnitName, "--no-pager", "--property=MainPID,ActiveState"}
		if !r.system {
			args = append([]string{"--user"}, args...)
		}
		cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
		defer cancel()
		cmd := exec.CommandContext(cctx, "systemctl", args...)
		cmd.Env = cleanChildEnvironment()
		out, err := cmd.Output()
		if err != nil {
			return nil, err
		}
		properties := map[string]string{}
		for _, line := range strings.Split(string(out), "\n") {
			if k, v, ok := strings.Cut(line, "="); ok {
				properties[k] = v
			}
		}
		pid, err := strconv.Atoi(properties["MainPID"])
		if err != nil || pid == 0 {
			if properties["ActiveState"] == "inactive" || properties["ActiveState"] == "failed" {
				return nil, nil
			}
			return nil, fmt.Errorf("systemd identity unavailable")
		}
		id, err := inspectGoIdentity(pid)
		if err != nil {
			return nil, err
		}
		home := r.home
		cfg := r.config
		if r.system {
			home = "/run/mihomoctl-go-core"
			cfg = filepath.Join(home, "managed-config.yaml")
		}
		want := []string{r.binary, "-d", home, "-f", cfg}
		if id.Exe != r.binary || !equalStringSlices(id.Args, want) {
			return nil, fmt.Errorf("systemd identity mismatch")
		}
		return &id, nil
	}
	b, err := platform.ReadPrivate(r.statePath)
	if err != nil {
		return nil, err
	}
	var state goRuntimeState
	if json.Unmarshal(b, &state) != nil || state.Version != 1 || state.Namespace != "mihomoctl-go" {
		return nil, fmt.Errorf("runtime state invalid")
	}
	if state.Identity.PID < 2 || state.Identity.Exe != r.binary {
		return nil, fmt.Errorf("runtime state identity mismatch")
	}
	id := state.Identity
	if !r.identityAlive(&id) {
		return nil, fmt.Errorf("runtime identity stale")
	}
	return &id, nil
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// inspectGoIdentity reads the kernel identity of a PID.
func inspectGoIdentity(pid int) (goIdentity, error) {
	var id goIdentity
	root := fmt.Sprintf("/proc/%d", pid)
	stat, err := os.ReadFile(root + "/stat")
	if err != nil {
		return id, err
	}
	tail := strings.LastIndexByte(string(stat), ')')
	if tail < 0 {
		return id, fmt.Errorf("invalid stat")
	}
	fields := strings.Fields(string(stat)[tail+1:])
	if len(fields) < 20 || fields[0] == "Z" || fields[0] == "X" {
		return id, os.ErrNotExist
	}
	st, err := os.Stat(root)
	if err != nil {
		return id, err
	}
	s, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return id, fmt.Errorf("invalid stat_t")
	}
	exe, err := os.Readlink(root + "/exe")
	if err != nil {
		return id, err
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return id, err
	}
	args, err := os.ReadFile(root + "/cmdline")
	if err != nil {
		return id, err
	}
	id = goIdentity{
		PID:   pid,
		UID:   int(s.Uid),
		Start: fields[19],
		Boot:  strings.TrimSpace(string(boot)),
		Exe:   exe,
		Args:  strings.Split(strings.TrimSuffix(string(args), "\x00"), "\x00"),
	}
	return id, nil
}

// identityAlive re-reads the identity and compares the stable fields.
func (r *runtimeOwner) identityAlive(id *goIdentity) bool {
	now, err := inspectGoIdentity(id.PID)
	return err == nil && now.UID == id.UID && now.Start == id.Start && now.Boot == id.Boot && now.Exe == id.Exe && equalStringSlices(now.Args, id.Args)
}

// ownsLoopback proves the PID holds a LISTEN socket at address:port.
func ownsLoopback(pid int, address string, port int) bool {
	root := fmt.Sprintf("/proc/%d", pid)
	entries, err := os.ReadDir(root + "/fd")
	if err != nil {
		return false
	}
	sockets := map[string]bool{}
	for _, f := range entries {
		p, err := os.Readlink(root + "/fd/" + f.Name())
		if err == nil && strings.HasPrefix(p, "socket:[") {
			sockets[strings.TrimSuffix(strings.TrimPrefix(p, "socket:["), "]")] = true
		}
	}
	for _, file := range []string{"tcp", "tcp6"} {
		b, err := os.ReadFile(root + "/net/" + file)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			cols := strings.Fields(line)
			if len(cols) < 10 || cols[3] != "0A" || !sockets[cols[9]] {
				continue
			}
			host, portText, ok := strings.Cut(cols[1], ":")
			if !ok {
				continue
			}
			n, err := strconv.ParseInt(portText, 16, 32)
			if err != nil || int(n) != port {
				continue
			}
			if procHexIP(host) == normalizeLoopback(address) {
				return true
			}
		}
	}
	return false
}

func normalizeLoopback(address string) string {
	ip := net.ParseIP(address)
	if ip == nil {
		return address
	}
	return ip.String()
}

// procHexIP decodes the little-endian hex IPv4/IPv6 form in /proc/net/tcp*.
func procHexIP(s string) string {
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
		n, err := strconv.ParseUint(s[offset:offset+2], 16, 8)
		if err != nil {
			return ""
		}
		ip[i] = byte(n)
	}
	return ip.String()
}

// trustedCoreExecutable validates the managed core binary path and its
// ancestry before it is executed for validation.
func trustedCoreExecutable(p string, system bool) error {
	if p == "" || !filepath.IsAbs(p) {
		return control("core-path-invalid", exitUnverify)
	}
	if err := platform.CheckPath(p); err != nil {
		return control(platform.SafeError(err), exitUnverify)
	}
	st, err := os.Stat(p)
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0111 == 0 {
		return control("core-unavailable", exitUnverify)
	}
	for q := p; ; q = filepath.Dir(q) {
		st, err := os.Stat(q)
		if err != nil {
			return control("core-untrusted", exitUnverify)
		}
		s, ok := st.Sys().(*syscall.Stat_t)
		if !ok || int(s.Uid) != 0 && int(s.Uid) != os.Geteuid() || system && s.Uid != 0 || st.Mode().Perm()&0022 != 0 {
			return control("core-untrusted", exitUnverify)
		}
		if filepath.Dir(q) == q {
			break
		}
	}
	return nil
}

// serviceAccountUID resolves the mihomoctl-go service account for system
// scope validation drops; -1 when absent.
func serviceAccountUID() int {
	u, err := user.Lookup(goServiceAccount)
	if err != nil {
		return -1
	}
	n, err := strconv.Atoi(u.Uid)
	if err != nil {
		return -1
	}
	return n
}

// nobodyUID resolves the unprivileged validation identity for user scope run
// as root.
func nobodyUID() int {
	u, err := user.Lookup("nobody")
	if err != nil {
		return -1
	}
	n, err := strconv.Atoi(u.Uid)
	if err != nil {
		return -1
	}
	return n
}

// chownDashboardAsset applies the system-scope service-group ownership to
// installed dashboard assets.
func chownDashboardAsset(path string) error {
	u, err := user.Lookup(goServiceAccount)
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return err
	}
	return os.Chown(path, 0, gid)
}

// chownTree applies uid/gid ownership to an entire staged tree.
func chownTree(root string, uid, gid int) error {
	return filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Chown(p, uid, gid)
	})
}

// execCmd aliases the command type so the tagged identity hook shares it.
type execCmd = exec.Cmd

// validationIdentity drops the core validation to an unprivileged identity
// when running as root (system scope: the dedicated service account).
func validationIdentity(cmd *execCmd, uid int) {
	if os.Geteuid() != 0 || uid <= 0 {
		return
	}
	gid := uid
	if u, err := user.LookupId(strconv.Itoa(uid)); err == nil {
		if g, err := strconv.Atoi(u.Gid); err == nil {
			gid = g
		}
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{uint32(gid)}},
	}
}

// fileOwnedPrivate reports whether a staged file belongs to the acting account
// with no group/other access bits.
func fileOwnedPrivate(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return int(st.Uid) == os.Geteuid() && info.Mode().Perm()&0o077 == 0
}

// pathOwnedBy reports whether a path belongs to one of the accepted owners.
func pathOwnedBy(info os.FileInfo, uids ...int) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	for _, uid := range uids {
		if int(st.Uid) == uid {
			return true
		}
	}
	return false
}

// checkAncestorsOwned verifies every existing ancestor directory of a provider
// path is root- or service-owned, symlink-free and not group/other writable.
func checkAncestorsOwned(path string, owner int) error {
	absolute := filepath.Clean(path)
	for {
		st, err := os.Lstat(absolute)
		if err == nil {
			if st.Mode()&os.ModeSymlink != 0 {
				return control("subscription-provider-path-unsafe", exitUnverify)
			}
			if st.IsDir() && !pathOwnedBy(st, 0, owner) {
				return control("subscription-provider-path-unsafe", exitUnverify)
			}
			if st.IsDir() && st.Mode().Perm()&0o022 != 0 {
				return control("subscription-provider-path-unsafe", exitUnverify)
			}
		} else if !os.IsNotExist(err) {
			return control("subscription-provider-path-unsafe", exitUnverify)
		}
		parent := filepath.Dir(absolute)
		if parent == absolute {
			break
		}
		absolute = parent
	}
	return nil
}

// rulesOwnershipExact reports that POSIX ownership/mode equality checks apply.
func rulesOwnershipExact() bool { return true }

// rulesOwnerCheck enforces the rules tree belongs to the acting account.
func rulesOwnerCheck(info os.FileInfo, kind string) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Getuid() {
		return ruleFail(kind + "-not-owned-by-current-user")
	}
	return nil
}

var (
	_ = context.Background
	_ = json.Unmarshal
)
