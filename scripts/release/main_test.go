package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOptionalPayloadsAreExplicitAndInventoried(t *testing.T) {
	source := t.TempDir()
	dest := t.TempDir()
	if e := os.MkdirAll(filepath.Join(source, "geodata"), 0700); e != nil {
		t.Fatal(e)
	}
	content := []byte("local caller-reviewed fixture")
	if e := os.WriteFile(filepath.Join(source, "geodata", "fixture.dat"), content, 0600); e != nil {
		t.Fatal(e)
	}
	if e := copyOptional(source, dest); e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(filepath.Join(dest, "geodata", "fixture.dat"))
	if e != nil || string(b) != string(content) {
		t.Fatal(e)
	}
	if e = os.Mkdir(filepath.Join(source, "unknown-input"), 0700); e != nil {
		t.Fatal(e)
	}
	if e = copyOptional(source, dest); e == nil {
		t.Fatal("unknown optional input silently accepted")
	}
}
func TestCrossBuildEnvironmentIsUnambiguous(t *testing.T) {
	t.Setenv("GOOS", "windows")
	t.Setenv("GOARCH", "386")
	t.Setenv("CGO_ENABLED", "1")
	seen := map[string]string{}
	for _, kv := range buildEnv("arm64") {
		k, v, _ := strings.Cut(kv, "=")
		if k == "GOOS" || k == "GOARCH" || k == "CGO_ENABLED" {
			if _, ok := seen[k]; ok {
				t.Fatal("duplicate cross environment", k)
			}
			seen[k] = v
		}
	}
	if seen["GOOS"] != "linux" || seen["GOARCH"] != "arm64" || seen["CGO_ENABLED"] != "0" {
		t.Fatal(seen)
	}
}

func TestSourceTreeKeepsEmbeddedAssetsAndExcludesTestExecutables(t *testing.T) {
	source := t.TempDir()
	dest := filepath.Join(t.TempDir(), "package")
	for name, body := range map[string]string{"dashboard.go": "package routing\n", "dashboard.html": "<html>embedded asset</html>", "runtime-arm64.test": "generated ELF fixture"} {
		if e := os.WriteFile(filepath.Join(source, name), []byte(body), 0600); e != nil {
			t.Fatal(e)
		}
	}
	if e := copyTree(source, dest); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"dashboard.go", "dashboard.html"} {
		if _, e := os.Stat(filepath.Join(dest, name)); e != nil {
			t.Fatal("source/embedded asset lost", name, e)
		}
	}
	if _, e := os.Stat(filepath.Join(dest, "runtime-arm64.test")); !os.IsNotExist(e) {
		t.Fatal("generated test executable entered source archive")
	}
}
