package runtimecore

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/liuzq1103/mihomoctl/internal/platform"
	"gopkg.in/yaml.v3"
)

const unitName = "mihomoctl-go.service"
const serviceAccount = "mihomoctl-go"
const unitMarker = "# mihomoctl-go managed unit v1"
const tunDropin = "50-mihomoctl-go-tun.conf"
const capText = unitMarker + "\n[Service]\nCapabilityBoundingSet=CAP_NET_ADMIN\nAmbientCapabilities=CAP_NET_ADMIN\n"

func marshalYAML(v any) ([]byte, error) { return yaml.Marshal(v) }
func unitPath(a platform.App) string {
	if a.Scope.System {
		return "/etc/systemd/system/" + unitName
	}
	return filepath.Join(filepath.Dir(a.Scope.ConfigRoot), "systemd", "user", unitName)
}
func quoteUnit(s string) string {
	s = strings.ReplaceAll(s, "%", "%%")
	s = strings.ReplaceAll(s, "$", "$$")
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	return "\"" + s + "\""
}
func serviceConfig(a platform.App, m manager) string {
	if a.Scope.System {
		return filepath.Join(serviceHome(a), "managed-config.yaml")
	}
	return m.Core.Config
}
func unitText(a platform.App, m manager) string {
	text := unitMarker + "\n[Unit]\nDescription=Managed Mihomo runtime (mihomoctl-go)\nAfter=network-online.target\nWants=network-online.target\nStartLimitIntervalSec=60\nStartLimitBurst=5\n\n[Service]\nType=simple\nExecStart=" + quoteUnit(m.Core.Binary) + " -d " + quoteUnit(serviceHome(a)) + " -f " + quoteUnit(serviceConfig(a, m)) + "\nRestart=on-failure\nRestartSec=3\nUMask=0077\nNoNewPrivileges=yes\n"
	text += "UnsetEnvironment=" + strings.Join(proxyKeys, " ") + " LD_PRELOAD LD_LIBRARY_PATH CLASH_HOME_DIR CLASH_CONFIG_FILE CLASH_CONFIG_STRING CLASH_AGE_SECRET_KEY CLASH_OVERRIDE_EXTERNAL_UI_DIR CLASH_OVERRIDE_EXTERNAL_CONTROLLER CLASH_OVERRIDE_EXTERNAL_CONTROLLER_UNIX CLASH_OVERRIDE_EXTERNAL_CONTROLLER_TLS CLASH_OVERRIDE_EXTERNAL_CONTROLLER_PIPE CLASH_OVERRIDE_EXTERNAL_CONTROLLER_ROUTING_MARK CLASH_OVERRIDE_SECRET CLASH_POST_UP CLASH_POST_DOWN\n"
	if a.Scope.System && systemBinaryOverlay(a, m.Core.Binary) {
		text += "TemporaryFileSystem=" + quoteUnit(a.Scope.DataRoot+":ro,mode=0755") + "\nBindReadOnlyPaths=" + quoteUnit(filepath.Join(a.Scope.DataRoot, "service-binary", "mihomo")+":"+m.Core.Binary) + "\n"
	}
	if a.Scope.System {
		text += "User=" + serviceAccount + "\nGroup=" + serviceAccount + "\nCapabilityBoundingSet=\nAmbientCapabilities=\nProtectSystem=strict\nProtectHome=yes\nRuntimeDirectory=mihomoctl-go-core\nRuntimeDirectoryMode=0700\nBindPaths=" + quoteUnit(a.Scope.CoreHome()+":"+serviceHome(a)) + "\nBindReadOnlyPaths=" + quoteUnit(filepath.Join(a.Scope.CoreHome(), "managed-config.yaml")+":"+serviceConfig(a, m)) + "\nReadWritePaths=" + quoteUnit(serviceHome(a)) + "\n"
	}
	target := "default.target"
	if a.Scope.System {
		target = "multi-user.target"
	}
	return text + "\n[Install]\nWantedBy=" + target + "\n"
}
func serviceHome(a platform.App) string {
	if a.Scope.System {
		return "/run/mihomoctl-go-core"
	}
	return a.Scope.CoreHome()
}
func utility(ctx context.Context, name string, args ...string) ([]byte, error) {
	p, e := exec.LookPath(name)
	if e != nil {
		return nil, platform.Usage(name + "-unavailable")
	}
	if e = trustedExecutable(p, os.Geteuid() == 0); e != nil {
		return nil, e
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, p, args...)
	cmd.Env = cleanEnvironment(true, nil)
	b, e := cmd.Output()
	if e != nil {
		return nil, platform.Fail(name + "-operation-failed")
	}
	if len(b) > platform.Limit {
		return nil, platform.Fail(name + "-output-too-large")
	}
	return b, nil
}
func systemctl(ctx context.Context, a platform.App, args ...string) ([]byte, error) {
	if !a.Scope.System {
		args = append([]string{"--user"}, args...)
	}
	return utility(ctx, "systemctl", args...)
}
func serviceProperties(ctx context.Context, a platform.App) (map[string]string, error) {
	b, e := systemctl(ctx, a, "show", unitName, "--no-pager", "--property=MainPID,ActiveState,SubState,FragmentPath,DropInPaths,User,ExecStart,ExecStartPre,ExecStartPost,ExecStop,ExecStopPost,Environment,EnvironmentFiles")
	if e != nil {
		return nil, e
	}
	m := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if ok {
			m[k] = v
		}
	}
	if m["ActiveState"] == "" {
		return nil, platform.Usage("systemd-state-unverified")
	}
	return m, nil
}
func requireOwnedUnit(a platform.App, m manager) error {
	b, e := platform.ReadPrivate(unitPath(a))
	if e != nil {
		return e
	}
	if string(b) != unitText(a, m) {
		return platform.Usage("systemd-unit-unowned")
	}
	entries, e := os.ReadDir(unitPath(a) + ".d")
	if e != nil && !os.IsNotExist(e) {
		return e
	}
	for _, f := range entries {
		if !strings.HasSuffix(f.Name(), ".conf") {
			continue
		}
		if f.Name() != tunDropin || !m.Tun.Enabled {
			return platform.Usage("systemd-dropin-unowned")
		}
		b, e := platform.ReadPrivate(filepath.Join(unitPath(a)+".d", f.Name()))
		if e != nil || string(b) != capText {
			return platform.Usage("systemd-dropin-unowned")
		}
	}
	return nil
}
func requireLoadedUnit(a platform.App, m manager, p map[string]string) error {
	if e := requireOwnedUnit(a, m); e != nil {
		return e
	}
	return requireLoadedDefinition(a, m, p)
}
func requireLoadedDefinition(a platform.App, m manager, p map[string]string) error {
	if p["FragmentPath"] != unitPath(a) {
		return platform.Usage("systemd-unit-unowned")
	}
	drop := p["DropInPaths"]
	want := ""
	if m.Tun.Enabled {
		want = filepath.Join(unitPath(a)+".d", tunDropin)
	}
	if drop != want {
		return platform.Usage("systemd-dropin-unowned")
	}
	for _, k := range []string{"ExecStartPre", "ExecStartPost", "ExecStop", "ExecStopPost", "Environment", "EnvironmentFiles"} {
		if p[k] != "" {
			return platform.Usage("systemd-definition-unverified")
		}
	}
	wantUser := ""
	if a.Scope.System {
		wantUser = serviceAccount
	}
	if p["User"] != wantUser {
		return platform.Usage("systemd-identity-unverified")
	}
	// systemctl serializes ExecStart with argv[]=...; compare the entire argv
	// segment, not a substring containing only the executable name.
	value := p["ExecStart"]
	_, rest, ok := strings.Cut(value, "argv[]=")
	if !ok {
		return platform.Usage("systemd-definition-unverified")
	}
	argv, _, ok := strings.Cut(rest, " ;")
	if !ok {
		return platform.Usage("systemd-definition-unverified")
	}
	expected := strings.Join([]string{m.Core.Binary, "-d", serviceHome(a), "-f", serviceConfig(a, m)}, " ")
	if argv != expected {
		return platform.Usage("systemd-definition-unverified")
	}
	return nil
}
func stopCompoundService(ctx context.Context, a platform.App, c *compoundRecord) error {
	if requireOwnedUnit(a, c.Before) != nil && requireOwnedUnit(a, c.Next) != nil {
		return platform.Usage("systemd-unit-unowned")
	}
	properties, e := serviceProperties(ctx, a)
	if e != nil {
		return e
	}
	var loaded *manager
	for _, m := range []manager{c.Before, c.Next} {
		candidate := m
		if requireLoadedDefinition(a, candidate, properties) == nil {
			loaded = &candidate
			break
		}
	}
	if loaded == nil {
		return platform.Usage("systemd-definition-unverified")
	}
	idText := properties["MainPID"]
	if idText != "0" && idText != "" {
		pid, e := strconv.Atoi(idText)
		if e != nil {
			return platform.Usage("systemd-identity-unverified")
		}
		id, e := inspectIdentity(pid)
		if e != nil || !allowedCompoundProcess(a, c, id) {
			return platform.Usage("systemd-identity-unverified")
		}
		uid := os.Geteuid()
		if a.Scope.System {
			uid, _, e = accountIdentity(false)
			if e != nil {
				return e
			}
		}
		if id.UID != uid {
			return platform.Usage("systemd-identity-unverified")
		}
		for _, m := range []manager{c.Before, c.Next} {
			if !m.Tun.Enabled {
				continue
			}
			observed, e := deviceState(ctx, tunDevice(m))
			if e != nil {
				return e
			}
			if observed != nil && !ownsTun(id, tunDevice(m)) {
				return platform.Usage("tun-ownership-unverified")
			}
		}
	}
	if _, e = systemctl(ctx, a, "stop", unitName); e != nil {
		return e
	}
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	for {
		properties, e = serviceProperties(ctx, a)
		if e != nil {
			return e
		}
		if properties["MainPID"] == "0" && member(properties["ActiveState"], "inactive", "failed") {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return platform.Fail("systemd-transition-unverified")
		case <-time.After(50 * time.Millisecond):
		}
	}
}
func serviceIdentity(ctx context.Context, a platform.App, m manager) (*identity, error) {
	p, e := serviceProperties(ctx, a)
	if e != nil {
		return nil, e
	}
	if e = requireLoadedUnit(a, m, p); e != nil {
		return nil, e
	}
	pid, e := strconv.Atoi(p["MainPID"])
	if e != nil || pid == 0 {
		if p["ActiveState"] == "inactive" || p["ActiveState"] == "failed" {
			return nil, nil
		}
		return nil, platform.Usage("systemd-identity-unverified")
	}
	id, e := inspectIdentity(pid)
	if e != nil {
		return nil, platform.Usage("systemd-identity-unverified")
	}
	uid := os.Geteuid()
	if a.Scope.System {
		uid, _, e = accountIdentity(false)
		if e != nil {
			return nil, e
		}
	}
	want := []string{m.Core.Binary, "-d", serviceHome(a), "-f", serviceConfig(a, m)}
	if id.UID != uid || id.Exe != m.Core.Binary || !equalStrings(id.Args, want) {
		return nil, platform.Usage("systemd-identity-unverified")
	}
	return &id, nil
}
func serviceLifecycle(ctx context.Context, a platform.App, x resolved, action string) error {
	p, e := serviceProperties(ctx, a)
	if e != nil {
		return e
	}
	if e = requireLoadedUnit(a, x.Manager, p); e != nil {
		return e
	}
	if p["MainPID"] != "0" && p["MainPID"] != "" {
		if _, e = serviceIdentity(ctx, a, x.Manager); e != nil {
			return e
		}
	}
	if action != "stop" {
		if e = validateCore(ctx, a, x.Manager.Core.Binary, x.Text); e != nil {
			return e
		}
		if e = prepareServiceFiles(ctx, a, x); e != nil {
			return e
		}
	}
	if _, e = systemctl(ctx, a, action, unitName); e != nil {
		return e
	}
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	for {
		if action == "stop" {
			p, e = serviceProperties(ctx, a)
			if e == nil && p["MainPID"] == "0" && (p["ActiveState"] == "inactive" || p["ActiveState"] == "failed") {
				return nil
			}
		} else {
			h, e := healthResolved(ctx, a, x, nil)
			if e == nil && h.Overall == "PASS" {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			if action != "stop" {
				_, _ = systemctl(ctx, a, "stop", unitName)
			}
			return platform.Fail("systemd-transition-unverified")
		case <-time.After(150 * time.Millisecond):
		}
	}
}
func serviceCommand(ctx context.Context, a platform.App, r platform.Request) (platform.Envelope, error) {
	doc := platform.Document(r.Name(), a.Scope.Name, nil)
	if r.Name() == "service-uninstall" && r.Has("dry-run") {
		doc.Command = "service-uninstall-preview"
	}
	x, e := resolve(a, "")
	if e != nil {
		return doc, e
	}
	path := unitPath(a)
	doc.Data["unit"] = unitName
	doc.Data["path"] = path
	if r.Name() == "service-install" {
		if x.Manager.Core.Backend == "process" {
			id, e := runningIdentity(ctx, a, x.Manager)
			if e != nil {
				return doc, e
			}
			if id != nil {
				return doc, platform.Usage("backend-active")
			}
		}
		if e = trustedExecutable(x.Manager.Core.Binary, a.Scope.System); e != nil {
			return doc, e
		}
		if e = prepareServiceFiles(ctx, a, x); e != nil {
			return doc, e
		}
		oldManager := x.Manager
		x.Manager.Core.Backend = "systemd"
		text := []byte(unitText(a, x.Manager))
		var old []byte
		if _, e = os.Lstat(path); e == nil {
			old, e = platform.ReadPrivate(path)
			if e != nil {
				return doc, e
			}
			if string(old) != unitText(a, oldManager) {
				return doc, platform.Usage("systemd-unit-unowned")
			}
		} else if !os.IsNotExist(e) {
			return doc, e
		}
		mb, e := yaml.Marshal(x.Manager)
		if e != nil {
			return doc, e
		}
		before, e := platform.ReadPrivate(a.Scope.ManagerPath())
		if e != nil {
			return doc, e
		}
		if e = applyFiles(a, map[string][]byte{path: text, a.Scope.ManagerPath(): mb}); e != nil {
			return doc, e
		}
		if _, e = systemctl(ctx, a, "daemon-reload"); e != nil {
			if re := applyFiles(a, map[string][]byte{path: old, a.Scope.ManagerPath(): before}); re != nil {
				return doc, platform.Fail("rollback-failed")
			}
			if _, re := systemctl(ctx, a, "daemon-reload"); re != nil {
				return doc, platform.Fail("rollback-failed")
			}
			return doc, e
		}
		doc.Data["installed"] = true
		doc.Data["changed"] = string(old) != string(text) || oldManager.Core.Backend != "systemd"
		return doc, nil
	}
	if x.Manager.Tun.Enabled {
		return doc, platform.Usage("tun-enabled")
	}
	p, e := serviceProperties(ctx, a)
	if e != nil {
		return doc, e
	}
	if e = requireLoadedUnit(a, x.Manager, p); e != nil {
		return doc, e
	}
	if p["MainPID"] != "0" || !member(p["ActiveState"], "inactive", "failed") {
		return doc, platform.Usage("backend-active")
	}
	if r.Has("dry-run") {
		doc.Data["dry_run"] = true
		return doc, nil
	}
	old, e := platform.ReadPrivate(path)
	if e != nil {
		return doc, e
	}
	before, e := platform.ReadPrivate(a.Scope.ManagerPath())
	if e != nil {
		return doc, e
	}
	if !a.Scope.System {
		x.Manager.Core.Backend = "process"
	}
	mb, e := yaml.Marshal(x.Manager)
	if e != nil {
		return doc, e
	}
	if e = applyFiles(a, map[string][]byte{path: nil, a.Scope.ManagerPath(): mb}); e != nil {
		return doc, e
	}
	if _, e = systemctl(ctx, a, "daemon-reload"); e != nil {
		if re := applyFiles(a, map[string][]byte{path: old, a.Scope.ManagerPath(): before}); re != nil {
			return doc, platform.Fail("rollback-failed")
		}
		_, _ = systemctl(ctx, a, "daemon-reload")
		return doc, e
	}
	doc.Data["installed"] = false
	return doc, nil
}

func tunDevice(m manager) string {
	if m.Tun.Device == "" {
		return "mihomo0"
	}
	return m.Tun.Device
}

type tunReceipt struct {
	Device string `json:"device"`
	Index  int    `json:"ifindex"`
	UID    int    `json:"authorized_by_uid"`
}

func tunReceiptPath(a platform.App) string { return filepath.Join(a.Scope.StateRoot, "tun.json") }
func deviceState(ctx context.Context, name string) (map[string]any, error) {
	b, e := utility(ctx, "ip", "-j", "-d", "link", "show", "dev", name)
	if e != nil {
		if _, e := os.Stat(filepath.Join("/sys/class/net", name)); os.IsNotExist(e) {
			return nil, nil
		}
		return nil, platform.Usage("tun-device-unverified")
	}
	var rows []map[string]any
	if json.Unmarshal(b, &rows) != nil || len(rows) != 1 {
		return nil, platform.Usage("tun-device-unverified")
	}
	return rows[0], nil
}
func routePresent(ctx context.Context, device string) (bool, error) {
	for _, family := range []string{"-4", "-6"} {
		b, e := utility(ctx, "ip", "-j", family, "route", "show", "table", "all")
		if e != nil {
			return false, e
		}
		var rows []map[string]any
		if json.Unmarshal(b, &rows) != nil {
			return false, platform.Usage("tun-route-unverified")
		}
		for _, r := range rows {
			if platform.String(r["dev"]) == device {
				return true, nil
			}
		}
	}
	return false, nil
}
func verifyTun(ctx context.Context, a platform.App, x resolved) (map[string]any, error) {
	device := tunDevice(x.Manager)
	observed, e := deviceState(ctx, device)
	if e != nil {
		return nil, e
	}
	if observed == nil {
		return nil, platform.Usage("tun-device-missing")
	}
	b, e := platform.ReadPrivate(tunReceiptPath(a))
	if e != nil {
		return nil, e
	}
	var rec tunReceipt
	if json.Unmarshal(b, &rec) != nil || rec.Device != device || rec.UID != 0 || rec.Index != platform.Int(observed["ifindex"]) {
		return nil, platform.Usage("tun-ownership-unverified")
	}
	id, e := serviceIdentity(ctx, a, x.Manager)
	if e != nil || id == nil {
		return nil, platform.Usage("tun-ownership-unverified")
	}
	if !ownsTun(*id, device) {
		return nil, platform.Usage("tun-ownership-unverified")
	}
	return observed, nil
}
func tunCommand(ctx context.Context, a platform.App, r platform.Request) (platform.Envelope, error) {
	doc := platform.Document(r.Name(), a.Scope.Name, nil)
	x, e := resolve(a, "")
	if e != nil {
		return doc, e
	}
	device := tunDevice(x.Manager)
	doc.Data = map[string]any{"enabled": x.Manager.Tun.Enabled, "device": device, "system_only": true}
	if r.Name() == "tun-status" {
		if x.Manager.Tun.Enabled {
			_, e = verifyTun(ctx, a, x)
			addCheck(&doc, "tun-ownership", e == nil, safeDetail(e))
		}
		return doc, nil
	}
	if !a.Scope.System {
		return doc, platform.Usage("tun-requires-system")
	}
	if x.Manager.Core.Backend != "systemd" {
		return doc, platform.Usage("tun-requires-systemd")
	}
	id, e := serviceIdentity(ctx, a, x.Manager)
	if e != nil {
		return doc, e
	}
	if id == nil {
		return doc, platform.Usage("tun-runtime-stopped")
	}
	enabled := r.Name() == "tun-enable"
	if enabled == x.Manager.Tun.Enabled {
		if enabled {
			_, e = verifyTun(ctx, a, x)
		}
		doc.Data["changed"] = false
		return doc, e
	}
	observed, e := deviceState(ctx, device)
	if e != nil {
		return doc, e
	}
	if enabled && observed != nil {
		return doc, platform.Usage("tun-device-exists")
	}
	if !enabled {
		if _, e = verifyTun(ctx, a, x); e != nil {
			return doc, e
		}
	}
	drop := filepath.Join(unitPath(a)+".d", tunDropin)
	if enabled {
		if _, e = os.Lstat(drop); e == nil {
			return doc, platform.Usage("tun-dropin-exists")
		} else if !os.IsNotExist(e) {
			return doc, e
		}
	}
	old := x.Manager
	x.Manager.Tun.Enabled = enabled
	x.Manager.Tun.Device = device
	if enabled {
		x.Config["tun"] = map[string]any{"enable": true, "device": device, "stack": "system", "auto-route": true, "auto-detect-interface": true}
	} else {
		delete(x.Config, "tun")
	}
	candidate, e := yaml.Marshal(x.Config)
	if e != nil {
		return doc, e
	}
	if e = validateCore(ctx, a, x.Manager.Core.Binary, candidate); e != nil {
		return doc, e
	}
	mb, e := yaml.Marshal(x.Manager)
	if e != nil {
		return doc, e
	}
	files := map[string][]byte{a.Scope.ManagerPath(): mb, x.Manager.Core.Config: candidate, drop: nil, tunReceiptPath(a): nil}
	if enabled {
		files[drop] = []byte(capText)
		files[tunReceiptPath(a)], _ = json.Marshal(tunReceipt{Device: device, UID: 0})
	}
	if e = applyCompound(ctx, a, r.Name(), old, x.Manager, files, id, func(active context.Context) error {
		if e := lifecycle(active, a, "start"); e != nil {
			return e
		}
		if enabled {
			return sealTunReceipt(active, a, x.Manager)
		}
		observed, e := deviceState(active, device)
		if e != nil {
			return e
		}
		if observed != nil {
			return platform.Fail("tun-disable-unverified")
		}
		return nil
	}); e != nil {
		return doc, e
	}
	doc.Data["enabled"] = enabled
	doc.Data["changed"] = true
	return doc, nil
}
