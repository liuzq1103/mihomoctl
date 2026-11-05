//go:build linux

package runtimecore

import (
	"context"
	"github.com/liuzq1103/mihomoctl/internal/platform"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestResourceSpecialFilesAndSymlinksFailClosed(t *testing.T) {
	a := testApp(t)
	home := a.Scope.CoreHome()
	if e := os.MkdirAll(home, 0700); e != nil {
		t.Fatal(e)
	}
	fifo := filepath.Join(home, "Country.mmdb")
	if e := syscall.Mkfifo(fifo, 0600); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, _, e := hashResource(ctx, a, fifo, "geodata")
	requireCode(t, e, "validation-resource-untrusted")
	if e = os.Remove(fifo); e != nil {
		t.Fatal(e)
	}
	target := filepath.Join(home, "real.dat")
	sparseResource(t, target, 16)
	if e = os.Symlink(target, fifo); e != nil {
		t.Fatal(e)
	}
	_, _, e = hashResource(ctx, a, fifo, "geodata")
	requireCode(t, e, "symlink-refused")
	if e = os.Remove(fifo); e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(home, 0777); e != nil {
		t.Fatal(e)
	}
	defer os.Chmod(home, 0700)
	_, _, e = hashResource(ctx, a, target, "geodata")
	requireCode(t, e, "validation-resource-untrusted")
}

func TestRootValidationExecutesPrivateCoreCopyUnprivileged(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("isolated root-to-nobody validation boundary")
	}
	a := testApp(t)
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	private := filepath.Join(a.Scope.DataRoot, "private", "mihomo")
	raw, e := os.ReadFile(exe)
	if e != nil {
		t.Fatal(e)
	}
	if e = platform.AtomicWrite(private, raw, 0700); e != nil {
		t.Fatal(e)
	}
	dir, e := os.MkdirTemp("", "mihomoctl-go-validator-test-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(dir)
	cmd := exec.Command(private, "-v")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if e = validationIdentity(ctx, cmd, a, dir); e != nil {
		t.Fatal(e)
	}
	if cmd.Path == private || cmd.SysProcAttr.Credential.Uid == 0 {
		t.Fatal("validator did not isolate executable and drop privilege")
	}
	out, e := cmd.Output()
	if e != nil || !strings.HasPrefix(string(out), "Mihomo Meta v") {
		t.Fatal("private core failed under non-root identity", e)
	}
	st, e := os.Stat(private)
	if e != nil || st.Mode().Perm() != 0700 {
		t.Fatal("source executable permissions changed", e)
	}
}
func TestRootSystemConfigReadAndModeWithoutSharedPlatformChanges(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("isolated root-owned config boundary")
	}
	a, m := fixture(t)
	a.Scope.System = true
	a.Scope.Name = "system"
	m.Core.Backend = "systemd"
	if e := platform.WriteYAML(a.Scope.ManagerPath(), m); e != nil {
		t.Fatal(e)
	}
	if e := setSystemConfigMode(m.Core.Config, os.Getegid()); e != nil {
		t.Fatal(e)
	}
	if _, e := platform.ReadPrivate(m.Core.Config); e == nil {
		t.Fatal("test requires platform's strict private-mode refusal")
	}
	x, e := resolve(a, "")
	if e != nil || len(x.Endpoints) != 1 {
		t.Fatal("runtime's local system config reader failed", e)
	}
	if e = applyFiles(a, map[string][]byte{m.Core.Config: x.Text}); e != nil {
		t.Fatal(e)
	}
	if e = setSystemConfigMode(m.Core.Config, os.Getegid()); e != nil {
		t.Fatal(e)
	}
	st, e := os.Stat(m.Core.Config)
	if e != nil || st.Mode().Perm() != 0640 {
		t.Fatal(st, e)
	}
	if e = os.Chmod(m.Core.Config, 0644); e != nil {
		t.Fatal(e)
	}
	_, e = readSystemConfig(m.Core.Config)
	requireCode(t, e, "core-config-untrusted")
}
