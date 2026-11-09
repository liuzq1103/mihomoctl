//go:build linux

package runtimecore

import (
	"context"
	"encoding/json"
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
	"testing"
	"time"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

// This suite is a required-CI entry point, not an opportunistic host probe.
// Opting in turns missing privileges, tools, systemd and the real core into
// failures. Never run it on an existing installation or a shared machine.
func TestPrivilegedSystemdTunAndSSH(t *testing.T) {
	if os.Getenv("MIHOMOCTL_GO_PRIVILEGED") != "1" {
		t.Skip("disposable systemd VM required; CI must explicitly set MIHOMOCTL_GO_PRIVILEGED=1")
	}
	if os.Geteuid() != 0 {
		t.Fatal("privileged CI opted in without euid 0")
	}
	comm, e := os.ReadFile("/proc/1/comm")
	if e != nil || strings.TrimSpace(string(comm)) != "systemd" {
		t.Fatal("privileged CI requires a real systemd host, not a container/WSL init; no skip is permitted after opt-in")
	}
	source := os.Getenv("MIHOMOCTL_GO_TEST_CORE")
	if source == "" {
		t.Fatal("MIHOMOCTL_GO_TEST_CORE must point to the reviewed real Mihomo binary")
	}
	for _, name := range []string{"systemctl", "ip", "useradd", "userdel", "groupdel", "chpasswd", "runuser", "sshd", "ssh", "ssh-keygen"} {
		if _, e = exec.LookPath(name); e != nil {
			t.Fatalf("required privileged CI tool unavailable: %s", name)
		}
	}
	if st, e := os.Stat("/dev/net/tun"); e != nil || st.Mode()&os.ModeCharDevice == 0 {
		t.Fatal("privileged CI requires /dev/net/tun")
	}
	f := newPrivilegedFixture(t, source)
	a := f.App
	privilegedStep(t, "two-non-root-uids", func(t *testing.T) {
		for i := 0; i < 2; i++ {
			u := f.createUser(t, i)
			doc := f.invokeUser(t, u, false, platform.Request{Command: []string{"init"}, Options: map[string][]string{"core": {f.Core}}}, "PASS")
			_ = doc
			f.invokeUser(t, u, false, platform.Request{Command: []string{"start"}}, "PASS")
			f.invokeUser(t, u, false, platform.Request{Command: []string{"health", "check"}}, "PASS")
		}
		f.assertUserIsolation(t)
	})
	if len(f.Users) != 2 {
		t.Fatal("both non-root accounts must pass before service/TUN testing")
	}
	privilegedStep(t, "service-install-start-status", func(t *testing.T) {
		systemCore := filepath.Join(a.Scope.DataRoot, "cores", "ci-reviewed", "mihomo")
		if e := platform.PrivateDir(filepath.Dir(systemCore)); e != nil {
			t.Fatal(e)
		}
		copyCIExecutable(t, f.Core, systemCore)
		if e := os.Chmod(systemCore, 0700); e != nil {
			t.Fatal(e)
		}
		f.rootRun(t, []string{"init"}, map[string][]string{"core": {systemCore}}, "PASS")
		f.ServiceUID, f.ServiceGID, e = accountIdentity(false)
		if e != nil {
			t.Fatal(e)
		}
		f.saveReceipt(t)
		f.assertSystemConfigMode(t)
		f.rootRun(t, []string{"service", "install"}, nil, "PASS")
		f.rootRun(t, []string{"service", "start"}, nil, "PASS")
		f.rootRun(t, []string{"service", "status"}, nil, "PASS")
		f.rootRun(t, []string{"service", "restart"}, nil, "PASS")
		f.rootRun(t, []string{"health", "check"}, nil, "PASS")
		if st, e := os.Stat(systemCore); e != nil || st.Mode().Perm() != 0700 {
			t.Fatal("system service weakened the original private binary", e)
		}
	})
	if _, e = serviceIdentity(context.Background(), a, mustManager(t, a)); e != nil {
		t.Fatal("service prerequisite failed", e)
	}
	privilegedStep(t, "ssh-sessions-for-both-uids", func(t *testing.T) {
		f.startSSHD(t)
		for _, u := range f.Users {
			f.invokeUser(t, u, true, platform.Request{Command: []string{"restart"}}, "PASS")
			f.invokeUser(t, u, true, platform.Request{Command: []string{"status"}}, "PASS")
			f.invokeUser(t, u, true, platform.Request{Command: []string{"health", "check"}}, "PASS")
			f.assertExecOverSSH(t, u)
			f.invokeUser(t, u, false, platform.Request{Command: []string{"health", "check"}}, "PASS")
		}
	})
	if f.SSH == nil {
		t.Fatal("SSH prerequisite failed")
	}
	privilegedStep(t, "interrupted-tun-enable-restores-running-service", func(t *testing.T) {
		crashAt(t, crashSpec{App: a, Request: platform.Request{Command: []string{"tun", "enable"}}, Phase: "files-published"})
		f.rootRun(t, []string{"start"}, nil, "PASS")
		if mustManager(t, a).Tun.Enabled {
			t.Fatal("interrupted enable was not rolled back")
		}
		if observed, e := deviceState(context.Background(), "mihomo0"); e != nil || observed != nil {
			t.Fatal("interrupted enable left an unverified device", e)
		}
		f.rootRun(t, []string{"health", "check"}, nil, "PASS")
	})
	privilegedStep(t, "real-tun-enable-and-ssh", func(t *testing.T) {
		f.rootRun(t, []string{"tun", "enable"}, nil, "PASS")
		f.rootRun(t, []string{"tun", "status"}, nil, "PASS")
		x, e := resolve(a, "")
		if e != nil {
			t.Fatal(e)
		}
		if _, e = verifyTun(context.Background(), a, x); e != nil {
			t.Fatal(e)
		}
		routes, e := routePresent(context.Background(), tunDevice(x.Manager))
		if e != nil || !routes {
			t.Fatal("real TUN routes not observed", e)
		}
		f.assertSystemConfigMode(t)
		for _, u := range f.Users {
			f.invokeUser(t, u, true, platform.Request{Command: []string{"health", "check"}}, "PASS")
		}
	})
	if !mustManager(t, a).Tun.Enabled {
		t.Fatal("real TUN enable prerequisite failed")
	}
	privilegedStep(t, "interrupted-tun-disable-recreates-owned-device", func(t *testing.T) {
		crashAt(t, crashSpec{App: a, Request: platform.Request{Command: []string{"tun", "disable"}}, Phase: "activated"})
		f.rootRun(t, []string{"start"}, nil, "PASS")
		if !mustManager(t, a).Tun.Enabled {
			t.Fatal("interrupted disable did not restore TUN authorization")
		}
		f.rootRun(t, []string{"tun", "status"}, nil, "PASS")
		f.rootRun(t, []string{"health", "check"}, nil, "PASS")
	})
	privilegedStep(t, "tun-disable-service-stop", func(t *testing.T) {
		f.rootRun(t, []string{"tun", "disable"}, nil, "PASS")
		if observed, e := deviceState(context.Background(), "mihomo0"); e != nil || observed != nil {
			t.Fatal("owned TUN remains after disable", e)
		}
		if routes, e := routePresent(context.Background(), "mihomo0"); e != nil || routes {
			t.Fatal("owned TUN routes remain after disable", e)
		}
		f.rootRun(t, []string{"service", "stop"}, nil, "PASS")
		f.rootRun(t, []string{"service", "status"}, nil, "FAIL")
	})
	privilegedStep(t, "interrupted-stopped-system-reset-and-repair", func(t *testing.T) {
		m := mustManager(t, a)
		bad := []byte("mode: [invalid\n")
		if e := atomicPrivateArtifact(a, m.Core.Config, bad); e != nil {
			t.Fatal(e)
		}
		if e := os.Chown(m.Core.Config, 0, f.ServiceGID); e != nil {
			t.Fatal(e)
		}
		if e := os.Chmod(m.Core.Config, 0640); e != nil {
			t.Fatal(e)
		}
		preview := f.rootRun(t, []string{"reset"}, map[string][]string{"dry-run": {}}, "PASS")
		request := platform.Request{Command: []string{"reset"}, Options: map[string][]string{"apply": {}, "plan-sha256": {preview.Data["plan_sha256"].(string)}}}
		crashAt(t, crashSpec{App: a, Request: request, Phase: "files-published"})
		f.rootRun(t, []string{"migrate"}, map[string][]string{"apply": {}, "no-import": {}}, "PASS")
		restored, e := readManagedFile(a, m.Core.Config)
		if e != nil || !bytesEqual(restored, bad) {
			t.Fatal("stopped original config not restored", e)
		}
		f.assertSystemConfigMode(t)
		preview = f.rootRun(t, []string{"reset"}, map[string][]string{"dry-run": {}}, "PASS")
		f.rootRun(t, []string{"reset"}, map[string][]string{"apply": {}, "plan-sha256": {preview.Data["plan_sha256"].(string)}}, "PASS")
		f.assertSystemConfigMode(t)
		f.rootRun(t, []string{"service", "status"}, nil, "FAIL")
	})
	privilegedStep(t, "service-uninstall", func(t *testing.T) {
		before, err := platform.ReadPrivate(unitPath(a))
		if err != nil {
			t.Fatal(err)
		}
		preview := f.rootRun(t, []string{"service", "uninstall"}, map[string][]string{"dry-run": {}}, "PASS")
		if preview.Command != "service-uninstall-preview" || preview.Data["dry_run"] != true {
			t.Fatal("uninstall preview contract", preview)
		}
		after, err := platform.ReadPrivate(unitPath(a))
		if err != nil || !bytesEqual(before, after) {
			t.Fatal("uninstall preview changed unit", err)
		}
		removed := f.rootRun(t, []string{"service", "uninstall"}, nil, "PASS")
		if removed.Command != "service-uninstall" {
			t.Fatal("uninstall command contract", removed)
		}
		if _, e = os.Lstat(unitPath(a)); !os.IsNotExist(e) {
			t.Fatal("owned unit remains after uninstall", e)
		}
	})
	if t.Failed() {
		return
	}
	t.Log("privileged systemd, real TUN, interrupted recovery, two UIDs and SSH all verified")
}

func TestPrivilegedOptInCannotSilentlySkip(t *testing.T) {
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestPrivilegedSystemdTunAndSSH$", "-test.v")
	env := []string{}
	for _, pair := range os.Environ() {
		key, _, _ := strings.Cut(pair, "=")
		if key != "MIHOMOCTL_GO_PRIVILEGED" && key != "MIHOMOCTL_GO_TEST_CORE" {
			env = append(env, pair)
		}
	}
	cmd.Env = append(env, "MIHOMOCTL_GO_PRIVILEGED=1", "MIHOMOCTL_GO_TEST_CORE=")
	raw, e := cmd.CombinedOutput()
	if e == nil || strings.Contains(string(raw), "--- SKIP:") || !strings.Contains(string(raw), "--- FAIL: TestPrivilegedSystemdTunAndSSH") {
		t.Fatalf("explicit opt-in did not fail hard with missing privileges/prerequisites: %v", e)
	}
}

type privilegedUser struct {
	Name string
	UID  int
	GID  int
	Home string
}
type privilegedReceipt struct {
	Namespace  string
	Token      string
	Scope      platform.Scope
	ServiceUID int
	ServiceGID int
	Users      []privilegedUser
}
type privilegedFixture struct {
	T              *testing.T
	App            platform.App
	Root           string
	Core           string
	Worker         string
	Token          string
	Users          []privilegedUser
	ServiceUID     int
	ServiceGID     int
	SSH            *exec.Cmd
	SSHIdentity    identity
	SSHWait        chan error
	SSHPort        int
	ClientKey      string
	CreatedSSHDRun bool
	Claimed        bool
}

func privilegedStep(t *testing.T, name string, fn func(*testing.T)) {
	t.Helper()
	if !t.Run(name, fn) {
		t.Fatalf("required privileged stage failed: %s", name)
	}
}

func mustManager(t *testing.T, a platform.App) manager {
	t.Helper()
	m, e := loadManager(a)
	if e != nil {
		t.Fatal(e)
	}
	return m
}
func newPrivilegedFixture(t *testing.T, coreSource string) *privilegedFixture {
	t.Helper()
	scope, e := platform.NewScope(true)
	if e != nil {
		t.Fatal(e)
	}
	a := platform.App{Scope: scope}
	seen := map[string]bool{}
	for _, p := range []string{scope.ConfigRoot, scope.DataRoot, scope.CacheRoot, scope.RuntimeRoot, serviceHome(a), unitPath(a), unitPath(a) + ".d", "/sys/class/net/mihomo0"} {
		if seen[p] {
			continue
		}
		seen[p] = true
		if e = platform.CheckPath(p); e != nil {
			t.Fatal(e)
		}
		if _, e = os.Lstat(p); !os.IsNotExist(e) {
			t.Fatalf("refusing non-disposable privileged host: %s already exists or cannot be checked", p)
		}
	}
	if _, e = user.Lookup(serviceAccount); e == nil {
		t.Fatal("refusing an existing service account")
	}
	if _, e = user.LookupGroup(serviceAccount); e == nil {
		t.Fatal("refusing an existing service group")
	}
	token, e := platform.Token()
	if e != nil {
		t.Fatal(e)
	}
	// Hosted images vary: /opt or /usr/local/lib may be group writable. Select
	// a verified existing ancestor tree; never repair permissions on foreign
	// directories just to make the test's executable appear trusted.
	root, e := createTrustedCIFixtureRoot([]string{"/opt", "/usr/local/lib", "/usr/lib", "/etc", "/"}, token)
	if e != nil {
		t.Fatal(e)
	}
	f := &privilegedFixture{T: t, App: a, Root: root, Token: token, Core: filepath.Join(root, "mihomo"), Worker: filepath.Join(root, "runtime-worker")}
	t.Cleanup(f.cleanup)
	// Claim the fixed config root atomically. A second suite on this host must
	// fail instead of sharing the same global unit/account namespace.
	if e = os.Mkdir(scope.ConfigRoot, 0700); e != nil {
		t.Fatal(e)
	}
	f.saveReceipt(t)
	f.Claimed = true
	copyCIExecutable(t, coreSource, f.Core)
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	copyCIExecutable(t, exe, f.Worker)
	if _, e = coreVersion(context.Background(), platform.App{}, f.Core); e != nil {
		t.Fatal("supplied executable is not a runnable Mihomo core", e)
	}
	return f
}
func trustedCIFixtureParent(parent string) error {
	if !absolute(parent) {
		return platform.Usage("ci-fixture-parent-untrusted")
	}
	if e := platform.CheckPath(parent); e != nil {
		return e
	}
	for path := parent; ; path = filepath.Dir(path) {
		st, e := os.Stat(path)
		if e != nil {
			return e
		}
		owner, ok := st.Sys().(*syscall.Stat_t)
		if !ok || !st.IsDir() || owner.Uid != 0 || st.Mode().Perm()&0022 != 0 {
			return platform.Usage("ci-fixture-parent-untrusted")
		}
		if filepath.Dir(path) == path {
			break
		}
	}
	return nil
}
func createTrustedCIFixtureRoot(parents []string, token string) (string, error) {
	if len(token) != 64 || !digestPattern.MatchString(token) {
		return "", platform.Usage("ci-fixture-token-invalid")
	}
	for _, parent := range parents {
		if e := trustedCIFixtureParent(parent); e != nil {
			continue
		}
		root := filepath.Join(parent, "mihomoctl-go-ci-"+token[:12])
		if e := os.Mkdir(root, 0755); e != nil {
			continue
		}
		if e := os.Chmod(root, 0755); e != nil {
			_ = os.Remove(root)
			return "", e
		}
		if e := trustedCIFixtureParent(root); e != nil {
			_ = os.Remove(root)
			continue
		}
		return root, nil
	}
	return "", platform.Usage("ci-fixture-trusted-parent-unavailable")
}
func (f *privilegedFixture) receiptPath() string {
	return filepath.Join(f.App.Scope.ConfigRoot, "privileged-ci.json")
}
func (f *privilegedFixture) saveReceipt(t *testing.T) {
	t.Helper()
	if e := platform.WriteJSON(f.receiptPath(), privilegedReceipt{"mihomoctl-go", f.Token, f.App.Scope, f.ServiceUID, f.ServiceGID, f.Users}); e != nil {
		t.Fatal(e)
	}
}
func copyCIExecutable(t *testing.T, source, target string) {
	t.Helper()
	if e := platform.CheckPath(source); e != nil {
		t.Fatal(e)
	}
	input, e := os.Open(source)
	if e != nil {
		t.Fatal(e)
	}
	defer input.Close()
	st, e := input.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Size() > executableLimit {
		t.Fatal("invalid executable fixture", e)
	}
	out, e := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0755)
	if e != nil {
		t.Fatal(e)
	}
	if e = out.Chmod(0755); e != nil {
		out.Close()
		t.Fatal(e)
	}
	count, e := io.Copy(out, io.LimitReader(input, executableLimit+1))
	if e == nil {
		e = out.Sync()
	}
	closeErr := out.Close()
	if e != nil || closeErr != nil || count > executableLimit {
		t.Fatal("cannot copy executable fixture", e, closeErr)
	}
}
func ciCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	path, e := exec.LookPath(name)
	if e != nil {
		return nil, e
	}
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = cleanEnvironment(true, nil)
	cmd.Dir = "/"
	return cmd.CombinedOutput()
}
func (f *privilegedFixture) createUser(t *testing.T, index int) privilegedUser {
	t.Helper()
	name := fmt.Sprintf("mcg-ci-%s-%d", f.Token[:8], index)
	uid := 31000 + index
	for {
		if _, e := user.LookupId(strconv.Itoa(uid)); e != nil {
			break
		}
		uid += 2
		if uid > 32000 {
			t.Fatal("no disposable test UID available")
		}
	}
	home := "/home/" + name
	// useradd resolves NSS groups and copies /etc/skel before the account
	// exists; a slow NSS backend or cold page cache must not be mistaken for
	// a fixture failure. The combined output names the step that blocked.
	addCtx, addCancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer addCancel()
	out, e := ciCommand(addCtx, "useradd", "--uid", strconv.Itoa(uid), "--create-home", "--home-dir", home, "--shell", "/bin/bash", name)
	if e != nil {
		t.Fatalf("cannot create disposable UID: %v output=%q", e, string(out))
	}
	entry, e := user.Lookup(name)
	if e != nil {
		t.Fatal(e)
	}
	gid, e := strconv.Atoi(entry.Gid)
	if e != nil {
		t.Fatal(e)
	}
	created := privilegedUser{name, uid, gid, home}
	f.Users = append(f.Users, created)
	f.saveReceipt(t)
	if e = os.Chmod(home, 0700); e != nil {
		t.Fatal(e)
	}
	password, e := platform.Token()
	if e != nil {
		t.Fatal(e)
	}
	// chpasswd gets its own deadline: a slow useradd must not consume it.
	pwCtx, pwCancel := context.WithTimeout(context.Background(), time.Minute)
	defer pwCancel()
	cmd := exec.CommandContext(pwCtx, "chpasswd")
	cmd.Env = cleanEnvironment(true, nil)
	cmd.Dir = "/"
	cmd.Stdin = strings.NewReader(name + ":" + password + "\n")
	if e = cmd.Run(); e != nil {
		t.Fatal("cannot unlock disposable account for public-key SSH", e)
	}
	return created
}

type privilegedWorkerSpec struct {
	Request platform.Request
	System  bool
}

func runPrivilegedUserWorker(path string) {
	raw, e := platform.ReadPrivate(path)
	if e != nil {
		os.Exit(121)
	}
	var spec privilegedWorkerSpec
	if json.Unmarshal(raw, &spec) != nil {
		os.Exit(122)
	}
	scope, e := platform.NewScope(spec.System)
	if e != nil {
		os.Exit(123)
	}
	spec.Request.Output = os.Stdout
	spec.Request.Stderr = os.Stderr
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	doc, e := Run(ctx, platform.App{Scope: scope}, spec.Request)
	if e != nil {
		doc = platform.Failure(spec.Request.Name(), scope.Name, e)
	}
	if json.NewEncoder(os.Stdout).Encode(doc) != nil {
		os.Exit(124)
	}
	os.Exit(doc.ExitCode())
}
func (f *privilegedFixture) writeUserSpec(t *testing.T, u privilegedUser, r platform.Request) string {
	t.Helper()
	path := filepath.Join(u.Home, "runtime-request.json")
	raw, e := json.Marshal(privilegedWorkerSpec{Request: r, System: r.Has("_test-system")})
	if e != nil {
		t.Fatal(e)
	}
	file, e := os.CreateTemp(u.Home, ".request-*")
	if e != nil {
		t.Fatal(e)
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if e = file.Chown(u.UID, u.GID); e == nil {
		e = file.Chmod(0600)
	}
	if e == nil {
		_, e = file.Write(raw)
	}
	if e == nil {
		e = file.Sync()
	}
	ce := file.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(temporary, path); e != nil {
		t.Fatal(e)
	}
	return path
}
func (f *privilegedFixture) userArgs(u privilegedUser, spec string) []string {
	return []string{"HOME=" + u.Home, "USER=" + u.Name, "LOGNAME=" + u.Name, "XDG_CONFIG_HOME=" + filepath.Join(u.Home, ".config"), "XDG_DATA_HOME=" + filepath.Join(u.Home, ".local", "share"), "XDG_STATE_HOME=" + filepath.Join(u.Home, ".local", "state"), "XDG_CACHE_HOME=" + filepath.Join(u.Home, ".cache"), "XDG_RUNTIME_DIR=", "MIHOMOCTL_GO_TEST_WORKER=" + spec, f.Worker}
}
func (f *privilegedFixture) userProcess(t *testing.T, u privilegedUser, ssh bool, r platform.Request) ([]byte, error) {
	t.Helper()
	spec := f.writeUserSpec(t, u, r)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	args := f.userArgs(u, spec)
	if member(r.Name(), "exec", "direct") {
		base := append([]string{}, args[:len(args)-1]...)
		for _, key := range proxyKeys {
			base = append(base, key+"=http://inherited.invalid:1")
		}
		args = append(base, f.Worker)
	}
	if !ssh {
		return ciCommand(ctx, "runuser", append([]string{"-u", u.Name, "--", "env"}, args...)...)
	}
	remote := []string{"env"}
	for _, arg := range args {
		remote = append(remote, shellQuote(arg))
	}
	return ciCommand(ctx, "ssh", "-F", "/dev/null", "-i", f.ClientKey, "-p", strconv.Itoa(f.SSHPort), "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR", u.Name+"@127.0.0.1", strings.Join(remote, " "))
}
func (f *privilegedFixture) invokeUser(t *testing.T, u privilegedUser, ssh bool, r platform.Request, overall string) platform.Envelope {
	t.Helper()
	raw, e := f.userProcess(t, u, ssh, r)
	var doc platform.Envelope
	if json.Unmarshal(raw, &doc) != nil {
		t.Fatalf("%s via SSH=%v: worker failed to return an envelope (%v)", u.Name, ssh, e)
	}
	if doc.Overall != overall || e != nil && overall == "PASS" {
		t.Fatalf("%s %s via SSH=%v: overall=%s errors=%v", u.Name, r.Name(), ssh, doc.Overall, doc.Errors)
	}
	return doc
}
func (f *privilegedFixture) rootRun(t *testing.T, command []string, options map[string][]string, overall string) platform.Envelope {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	// The real unit deliberately limits starts to five per minute. CI exercises
	// more explicit transitions than that; reset only this receipt-owned unit's
	// counter so the suite tests activation/recovery rather than rate limiting.
	name := strings.Join(command, "-")
	if member(name, "start", "restart", "service-start", "service-restart", "tun-enable", "tun-disable") {
		if _, exists := os.Lstat(unitPath(f.App)); exists == nil {
			m, e := loadManager(f.App)
			if e != nil {
				t.Fatal(e)
			}
			if e = requireOwnedUnit(f.App, m); e != nil {
				t.Fatal(e)
			}
			if _, e = systemctl(ctx, f.App, "reset-failed", unitName); e != nil {
				t.Fatal("cannot reset owned test unit start counter", e)
			}
		}
	}
	doc, e := Run(ctx, f.App, platform.Request{Command: command, Options: options})
	if len(command) == 1 && command[0] == "init" {
		if uid, gid, lookup := accountIdentity(false); lookup == nil {
			f.ServiceUID = uid
			f.ServiceGID = gid
			f.saveReceipt(t)
		}
	}
	if e != nil || doc.Overall != overall {
		t.Fatalf("system %s: overall=%s errors=%v err=%v", strings.Join(command, " "), doc.Overall, doc.Errors, e)
	}
	return doc
}
func (f *privilegedFixture) assertSystemConfigMode(t *testing.T) {
	t.Helper()
	m := mustManager(t, f.App)
	for _, path := range []string{m.Core.Config, filepath.Join(f.App.Scope.CoreHome(), "managed-config.yaml")} {
		st, e := os.Stat(path)
		if e != nil {
			t.Fatal(e)
		}
		owner, ok := st.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != 0 || int(owner.Gid) != f.ServiceGID || st.Mode().Perm() != 0640 {
			t.Fatalf("core config must be root:service-gid 0640: %s", path)
		}
	}
	if id, e := serviceIdentity(context.Background(), f.App, m); e == nil && id != nil {
		raw, e := os.ReadFile(fmt.Sprintf("/proc/%d/mountinfo", id.PID))
		if e != nil {
			t.Fatal(e)
		}
		readOnly := false
		for _, line := range strings.Split(string(raw), "\n") {
			fields := strings.Fields(line)
			if len(fields) > 5 && fields[4] == serviceConfig(f.App, m) {
				for _, option := range strings.Split(fields[5], ",") {
					if option == "ro" {
						readOnly = true
					}
				}
			}
		}
		if !readOnly {
			t.Fatal("system core config is not mounted read-only in the service namespace")
		}
	}
}
func (f *privilegedFixture) assertUserIsolation(t *testing.T) {
	t.Helper()
	ports := map[int]bool{}
	for i, u := range f.Users {
		doc := f.invokeUser(t, u, false, platform.Request{Command: []string{"status"}}, "PASS")
		rows, ok := doc.Data["listeners"].([]any)
		if !ok || len(rows) == 0 {
			t.Fatal("missing user listeners")
		}
		for _, row := range rows {
			port := platform.Int(platform.Map(row)["port"])
			if ports[port] {
				t.Fatal("independent user listener ports collided")
			}
			ports[port] = true
		}
		denied := f.invokeUser(t, u, false, platform.Request{Command: []string{"start"}, Options: map[string][]string{"_test-system": {}}}, "UNVERIFIED")
		if len(denied.Errors) != 1 || denied.Errors[0].Code != "system-requires-root" {
			t.Fatal("non-root UID crossed into system mutation")
		}
		denied = f.invokeUser(t, u, false, platform.Request{Command: []string{"tun", "enable"}}, "UNVERIFIED")
		if len(denied.Errors) != 1 || denied.Errors[0].Code != "tun-requires-system" {
			t.Fatal("user-scoped UID acquired TUN authorization")
		}
		other := f.Users[1-i]
		secret := filepath.Join(other.Home, ".config", "mihomoctl-go", "credentials", "default.yaml")
		if raw, e := f.userProcess(t, u, false, platform.Request{Command: []string{"direct"}, Child: []string{"/bin/cat", secret}}); e == nil || len(raw) == 0 {
			t.Fatal("cross-UID private credentials were readable or permission denial was not observed")
		}
		own := filepath.Join(u.Home, ".config", "mihomoctl-go", "credentials", "default.yaml")
		st, e := os.Stat(own)
		if e != nil {
			t.Fatal(e)
		}
		s := st.Sys().(*syscall.Stat_t)
		if int(s.Uid) != u.UID || st.Mode().Perm() != 0600 {
			t.Fatal("user credentials not private to that UID")
		}
	}
}
func (f *privilegedFixture) assertExecOverSSH(t *testing.T, u privilegedUser) {
	t.Helper()
	for _, r := range []platform.Request{{Command: []string{"exec"}, Child: []string{"/bin/sh", "-c", `test -n "$HTTP_PROXY" && test -n "$HTTPS_PROXY" && test -n "$ALL_PROXY" && test "$HTTP_PROXY" != http://inherited.invalid:1`}}, {Command: []string{"direct"}, Child: []string{"/bin/sh", "-c", `test -z "$HTTP_PROXY" && test -z "$HTTPS_PROXY" && test -z "$ALL_PROXY"`}}} {
		if _, e := f.userProcess(t, u, true, r); e != nil {
			t.Fatalf("SSH %s did not preserve scoped child environment: %v", r.Name(), e)
		}
	}
}

func (f *privilegedFixture) startSSHD(t *testing.T) {
	t.Helper()
	dir := filepath.Join(f.Root, "sshd")
	if e := os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	hostKey := filepath.Join(dir, "host_ed25519")
	f.ClientKey = filepath.Join(dir, "client_ed25519")
	for _, path := range []string{hostKey, f.ClientKey} {
		if _, e := ciCommand(ctx, "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", path); e != nil {
			t.Fatal("SSH key generation failed", e)
		}
	}
	public, e := os.ReadFile(f.ClientKey + ".pub")
	if e != nil {
		t.Fatal(e)
	}
	for _, u := range f.Users {
		sshDir := filepath.Join(u.Home, ".ssh")
		if e = os.Mkdir(sshDir, 0700); e != nil {
			t.Fatal(e)
		}
		if e = os.Chown(sshDir, u.UID, u.GID); e != nil {
			t.Fatal(e)
		}
		p := filepath.Join(sshDir, "authorized_keys")
		if e = os.WriteFile(p, public, 0600); e != nil {
			t.Fatal(e)
		}
		if e = os.Chown(p, u.UID, u.GID); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = os.Lstat("/run/sshd"); os.IsNotExist(e) {
		if e = os.Mkdir("/run/sshd", 0755); e != nil {
			t.Fatal(e)
		}
		f.CreatedSSHDRun = true
	}
	port, e := freePort()
	if e != nil {
		t.Fatal(e)
	}
	f.SSHPort = port
	config := fmt.Sprintf("Port %d\nListenAddress 127.0.0.1\nHostKey %s\nPidFile %s\nAuthorizedKeysFile .ssh/authorized_keys\nStrictModes yes\nPermitRootLogin no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nPubkeyAuthentication yes\nUsePAM no\nAllowUsers %s %s\nLogLevel ERROR\n", port, hostKey, filepath.Join(dir, "sshd.pid"), f.Users[0].Name, f.Users[1].Name)
	path := filepath.Join(dir, "sshd_config")
	if e = os.WriteFile(path, []byte(config), 0600); e != nil {
		t.Fatal(e)
	}
	sshd, e := exec.LookPath("sshd")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = ciCommand(ctx, "sshd", "-t", "-f", path); e != nil {
		t.Fatal("isolated sshd configuration rejected", e)
	}
	log, e := os.OpenFile(filepath.Join(dir, "sshd.log"), os.O_CREATE|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	defer log.Close()
	f.SSH = exec.Command(sshd, "-D", "-e", "-f", path)
	f.SSH.Stderr = log
	f.SSH.Stdout = log
	f.SSH.Env = cleanEnvironment(true, nil)
	if e = f.SSH.Start(); e != nil {
		t.Fatal(e)
	}
	f.SSHIdentity, _ = inspectIdentity(f.SSH.Process.Pid)
	f.SSHWait = make(chan error, 1)
	go func() { f.SSHWait <- f.SSH.Wait() }()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		conn, e := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 100*time.Millisecond)
		if e == nil {
			conn.Close()
			f.SSHIdentity, e = inspectIdentity(f.SSH.Process.Pid)
			if e == nil {
				return
			}
		}
		select {
		case e := <-f.SSHWait:
			t.Fatal("isolated sshd exited", e)
		case <-time.After(50 * time.Millisecond):
		}
	}
	t.Fatal("isolated SSH listener did not become ready")
}

func (f *privilegedFixture) cleanup() {
	t := f.T
	if !f.Claimed {
		_ = os.RemoveAll(f.Root)
		return
	}
	raw, e := platform.ReadPrivate(f.receiptPath())
	var receipt privilegedReceipt
	if e != nil || json.Unmarshal(raw, &receipt) != nil || receipt.Namespace != "mihomoctl-go" || receipt.Token != f.Token || receipt.Scope != f.App.Scope {
		t.Error("privileged fixture receipt unavailable; refusing global cleanup")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if f.SSH != nil && f.SSH.Process != nil {
		current, e := inspectIdentity(f.SSH.Process.Pid)
		if e == nil && current.Start == f.SSHIdentity.Start && current.Boot == f.SSHIdentity.Boot && current.Exe == f.SSHIdentity.Exe && current.UID == 0 {
			if e = stopExactProcess(ctx, current); e != nil {
				t.Error("cannot stop owned sshd", e)
				return
			}
		}
	}
	// Keep consumers and their helper executable until all owned user cores stop.
	for _, u := range f.Users {
		managerPath := filepath.Join(u.Home, ".config", "mihomoctl-go", "manager.yaml")
		if _, e := os.Lstat(managerPath); e == nil {
			spec := platform.Request{Command: []string{"stop"}}
			raw, e := f.userProcess(t, u, false, spec)
			if e != nil {
				t.Errorf("cannot stop disposable UID %s; refusing account removal", u.Name)
				continue
			}
			_ = raw
		}
		entry, e := user.Lookup(u.Name)
		if e == nil && entry.Uid == strconv.Itoa(u.UID) && entry.HomeDir == u.Home {
			if _, e = ciCommand(ctx, "userdel", "--remove", u.Name); e != nil {
				t.Error("cannot remove owned disposable UID", e)
			} else if group, lookup := user.LookupGroup(u.Name); lookup == nil && group.Gid == strconv.Itoa(u.GID) {
				if _, e = ciCommand(ctx, "groupdel", u.Name); e != nil {
					t.Error("cannot remove owned disposable user group", e)
				}
			}
		}
	}
	if _, e = os.Lstat(unitPath(f.App)); e == nil {
		if c, _ := loadCompound(f.App); c != nil {
			_, _ = Run(ctx, f.App, platform.Request{Command: []string{"start"}})
		}
		if m, e := loadManager(f.App); e == nil && m.Tun.Enabled {
			_, _ = Run(ctx, f.App, platform.Request{Command: []string{"start"}})
			if _, e = Run(ctx, f.App, platform.Request{Command: []string{"tun", "disable"}}); e != nil {
				t.Error("cannot disable owned test TUN; retaining namespace", e)
				return
			}
		}
		if _, e = Run(ctx, f.App, platform.Request{Command: []string{"service", "stop"}}); e != nil {
			t.Error("cannot stop owned test service; retaining namespace", e)
			return
		}
		if _, e = Run(ctx, f.App, platform.Request{Command: []string{"service", "uninstall"}}); e != nil {
			t.Error("cannot uninstall owned test service; retaining namespace", e)
			return
		}
	}
	if observed, e := deviceState(ctx, "mihomo0"); e != nil || observed != nil {
		t.Error("unverified network device remains; refusing namespace deletion")
		return
	}
	if receipt.ServiceUID != 0 {
		entry, e := user.Lookup(serviceAccount)
		if e == nil && entry.Uid == strconv.Itoa(receipt.ServiceUID) {
			if _, e = ciCommand(ctx, "userdel", serviceAccount); e != nil {
				t.Error("cannot remove fixture service account", e)
				return
			}
			if group, lookup := user.LookupGroup(serviceAccount); lookup == nil && group.Gid == strconv.Itoa(receipt.ServiceGID) {
				if _, e = ciCommand(ctx, "groupdel", serviceAccount); e != nil {
					t.Error("cannot remove fixture service group", e)
					return
				}
			}
		}
	}
	// Fixed roots were absent at preflight and are authorized by the private
	// receipt above. Never recursively remove systemd directories or foreign units.
	for _, path := range []string{f.App.Scope.RuntimeRoot, f.App.Scope.CacheRoot, f.App.Scope.DataRoot, f.App.Scope.ConfigRoot} {
		if e = platform.CheckPath(path); e != nil {
			t.Error(e)
			return
		}
		if e = os.RemoveAll(path); e != nil {
			t.Error(e)
			return
		}
	}
	_ = os.Remove(unitPath(f.App) + ".d")
	if f.CreatedSSHDRun {
		_ = os.Remove("/run/sshd")
	}
	if e = os.RemoveAll(f.Root); e != nil {
		t.Error(e)
	}
}
