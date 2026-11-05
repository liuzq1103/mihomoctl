package platform

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStrictYAMLRejectsAmbiguousDocuments(t *testing.T) {
	for _, s := range []string{"a: 1\na: 2\n", "a: &x [1]\nb: *x\n", "a: 1\n---\nb: 2\n", "- 1\n", "? [a,b]\n: 2\n"} {
		if _, e := StrictYAML([]byte(s)); e == nil {
			t.Errorf("accepted ambiguous YAML %q", s)
		}
	}
}
func TestPatchPreservesUnrelatedNodeAndComments(t *testing.T) {
	b := []byte("# host settings\nsecret: 'do-not-change' # private\nport: 7890\nrules:\n  - MATCH,DIRECT\n")
	patched, e := PatchYAML(b, map[string]any{"rules": []string{"MATCH,PROXY"}})
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(string(patched), "secret: 'do-not-change' # private") || !strings.Contains(string(patched), "# host settings") {
		t.Fatalf("unrelated node changed: %s", patched)
	}
	m, e := DecodeYAML(patched)
	if e != nil || m["port"] != 7890 {
		t.Fatal(m, e)
	}
}
func TestPrivateAtomicWriteRejectsSymlinkAncestor(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if e := os.Mkdir(target, 0700); e != nil {
		t.Fatal(e)
	}
	link := filepath.Join(root, "link")
	if e := os.Symlink(target, link); e != nil {
		t.Skip("symlinks unavailable")
	}
	if e := AtomicWrite(filepath.Join(link, "secret"), []byte("private"), 0600); e == nil {
		t.Fatal("symlink traversal allowed")
	}
	if _, e := os.Stat(filepath.Join(target, "secret")); !os.IsNotExist(e) {
		t.Fatal("wrote through symlink")
	}
}
func TestPrivateWriteAndBounds(t *testing.T) {
	p := filepath.Join(t.TempDir(), "private", "config.yaml")
	if e := AtomicWrite(p, []byte("a: 1\n"), 0600); e != nil {
		t.Fatal(e)
	}
	m, e := ReadYAML(p, true)
	if e != nil || m["a"] != 1 {
		t.Fatal(m, e)
	}
	if _, e = ReadLimited(strings.NewReader(strings.Repeat("a", Limit+1))); e == nil {
		t.Fatal("oversized input accepted")
	}
}
func TestEnvelopeFailureEvidenceAndExit(t *testing.T) {
	for _, tt := range []struct {
		err    error
		exit   int
		status string
	}{{Fail("observed"), 1, "FAIL"}, {Usage("invalid"), 2, "UNVERIFIED"}, {errors.New("secret token"), 2, "UNVERIFIED"}} {
		e := Failure("status", "user", tt.err)
		if e.ExitCode() != tt.exit || e.Overall != tt.status || strings.Contains(e.Errors[0].Detail, "secret") {
			t.Fatal(e)
		}
	}
	_ = context.Background()
}
func TestScopeDoesNotReadOriginalNamespace(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", root)
	s, e := NewScope(false)
	if e != nil {
		t.Fatal(e)
	}
	if s.ConfigRoot != filepath.Join(root, "mihomoctl-go") || s.Contains(filepath.Join(root, "mihomoctl", "manager.yaml")) {
		t.Fatal("shared Python namespace")
	}
	t.Setenv("XDG_CONFIG_HOME", "relative")
	if _, e = NewScope(false); e == nil {
		t.Fatal("relative XDG path accepted")
	}
}
