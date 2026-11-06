//go:build linux

package runtimecore

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

func TestPrivilegedCoreFixtureNeverWeakensExecutableAncestorTrust(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("isolated root-owned CI fixture trust regression")
	}
	root := tempPrivate(t)
	parent := filepath.Join(root, "hosted-opt-like")
	if e := os.Mkdir(parent, 0755); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(parent, 0777); e != nil {
		t.Fatal(e)
	}
	defer os.Chmod(parent, 0755)
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	candidate := filepath.Join(parent, "mihomo")
	copyCIExecutable(t, exe, candidate)
	_, e = coreVersion(context.Background(), platform.App{}, candidate)
	requireCode(t, e, "core-untrusted")
	secured := filepath.Join(root, "root-owned-lib")
	if e = os.Mkdir(secured, 0755); e != nil {
		t.Fatal(e)
	}
	safe := filepath.Join(secured, "mihomo")
	copyCIExecutable(t, candidate, safe)
	version, e := coreVersion(context.Background(), platform.App{}, safe)
	if e != nil || version != "v1.19.33" {
		t.Fatal("safe root-owned fixture cannot pass validation", version, e)
	}
	st, e := os.Stat(parent)
	if e != nil || st.Mode().Perm() != 0777 {
		t.Fatal("fixture repaired a foreign writable ancestor instead of moving", e)
	}
}

func TestPrivilegedFixtureSelectsTrustedParentWithoutChmodForeignDirectories(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("isolated root-owned fixture parent selection")
	}
	base := tempPrivate(t)
	writable := filepath.Join(base, "group-writable-lib")
	trusted := filepath.Join(base, "trusted-opt")
	for _, p := range []string{writable, trusted} {
		if e := os.Mkdir(p, 0755); e != nil {
			t.Fatal(e)
		}
	}
	if e := os.Chmod(writable, 0775); e != nil {
		t.Fatal(e)
	}
	token := strings.Repeat("a", 64)
	root, e := createTrustedCIFixtureRoot([]string{writable, trusted}, token)
	if e != nil {
		t.Fatal(e)
	}
	if filepath.Dir(root) != trusted {
		t.Fatal("selected writable fixture parent", root)
	}
	if e = trustedCIFixtureParent(root); e != nil {
		t.Fatal(e)
	}
	st, e := os.Stat(writable)
	if e != nil || st.Mode().Perm() != 0775 {
		t.Fatal("changed foreign parent permissions", e)
	}
	children, e := os.ReadDir(writable)
	if e != nil || len(children) != 0 {
		t.Fatal("created fixture below an untrusted parent", e)
	}
	_, e = createTrustedCIFixtureRoot([]string{writable}, strings.Repeat("b", 64))
	requireCode(t, e, "ci-fixture-trusted-parent-unavailable")
	if e = os.Remove(root); e != nil {
		t.Fatal(e)
	}
	ancestor := filepath.Join(base, "writable-ancestor")
	if e = os.Mkdir(ancestor, 0775); e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(ancestor, 0775); e != nil {
		t.Fatal(e)
	}
	leaf := filepath.Join(ancestor, "safe-looking-leaf")
	if e = os.Mkdir(leaf, 0755); e != nil {
		t.Fatal(e)
	}
	_, e = createTrustedCIFixtureRoot([]string{leaf}, strings.Repeat("c", 64))
	requireCode(t, e, "ci-fixture-trusted-parent-unavailable")
}
