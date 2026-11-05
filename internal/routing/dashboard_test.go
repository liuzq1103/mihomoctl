package routing

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

func TestChoosePortProbesLoopback(t *testing.T) {
	port, err := choosePort(0, false)
	if err != nil {
		t.Fatal(err)
	}
	if port < 1024 || port > 65535 {
		t.Fatalf("port = %d", port)
	}
	if _, err := choosePort(80, true); err == nil {
		t.Fatal("privileged port accepted")
	} else {
		mustCode(t, err, "controller-port-out-of-range")
	}
	if _, err := choosePort(70000, true); err == nil {
		t.Fatal("out-of-range port accepted")
	} else {
		mustCode(t, err, "controller-port-out-of-range")
	}

	// An occupied port must be refused before it reaches configuration.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	occupied := listener.Addr().(*net.TCPAddr).Port
	_, err = choosePort(occupied, true)
	mustCode(t, err, "controller-port-in-use")
	listener.Close()

	// A requested free port must come back unchanged; retry in case another
	// process races for the port between release and probe.
	for attempt := 0; attempt < 8; attempt++ {
		probe, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		want := probe.Addr().(*net.TCPAddr).Port
		probe.Close()
		got, err := choosePort(want, true)
		if err == nil {
			if got != want {
				t.Fatalf("choosePort(%d) = %d", want, got)
			}
			return
		}
	}
	t.Fatal("could not confirm a requested free port")
}

func TestControllerTokenShape(t *testing.T) {
	pattern := regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	first, err := controllerTokenURLSafe()
	if err != nil {
		t.Fatal(err)
	}
	second, _ := controllerTokenURLSafe()
	if !pattern.MatchString(first) {
		t.Fatalf("token = %q", first)
	}
	if first == second {
		t.Fatal("tokens are not random")
	}
}

func TestBase64URLSafeNoPadVectors(t *testing.T) {
	for _, raw := range [][]byte{[]byte(""), []byte("f"), []byte("fo"), []byte("foo"), []byte("foob"), []byte("fooba"), []byte("foobar")} {
		want := base64.RawURLEncoding.EncodeToString(raw)
		if got := base64URLSafeNoPad(raw); got != want {
			t.Errorf("base64URLSafeNoPad(%q) = %q want %q", raw, got, want)
		}
	}
}

// buildZip assembles an in-memory archive the way the original fixtures did.
func buildZip(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for name, content := range entries {
		file, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func stageArchive(t *testing.T, raw []byte) (string, string) {
	t.Helper()
	path := filepath.Join(privateTempDir(t), "dashboard.zip")
	if err := platform.AtomicWrite(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return path, hashSHA256(raw)
}

func TestArchiveUIUnpacksReviewedArchive(t *testing.T) {
	// The single index.html sits in "app/", so only that root installs.
	raw := buildZip(t, map[string]string{
		"app/index.html":     "<html>ok</html>",
		"app/assets/app.js":  "console.log(1)",
		"app/assets/app.css": "body{}",
		"OUTSIDE.md":         "not part of the dashboard",
	})
	archive, checksum := stageArchive(t, raw)
	destination := privateTempDir(t)
	if err := archiveUI(archive, checksum, destination); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		"index.html":     "<html>ok</html>",
		"assets/app.js":  "console.log(1)",
		"assets/app.css": "body{}",
	} {
		data, err := os.ReadFile(filepath.Join(destination, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if string(data) != want {
			t.Fatalf("%s = %q", name, data)
		}
	}
	if _, err := os.Lstat(filepath.Join(destination, "OUTSIDE.md")); !os.IsNotExist(err) {
		t.Fatal("file outside the index.html root was extracted")
	}
}

func TestArchiveUIRejectsUnsafeArchives(t *testing.T) {
	destination := privateTempDir(t)

	// Digest mismatch.
	raw := buildZip(t, map[string]string{"index.html": "x"})
	archive, checksum := stageArchive(t, raw)
	err := archiveUI(archive, hashSHA256([]byte("other")), destination)
	mustCode(t, err, "dashboard-sha256-mismatch")

	// Non-hex checksum.
	err = archiveUI(archive, "ZZ"+strings.Repeat("a", 62), destination)
	mustCode(t, err, "dashboard-requires-pinned-sha256")

	// Two competing index.html roots.
	raw = buildZip(t, map[string]string{"a/index.html": "x", "b/index.html": "y"})
	archive, checksum = stageArchive(t, raw)
	err = archiveUI(archive, checksum, destination)
	mustCode(t, err, "dashboard-archive-needs-one-index-html")

	// No index.html at all.
	raw = buildZip(t, map[string]string{"assets/app.js": "x"})
	archive, checksum = stageArchive(t, raw)
	err = archiveUI(archive, checksum, destination)
	mustCode(t, err, "dashboard-archive-needs-one-index-html")

	// Parent traversal beside the single index.html root.
	raw = buildZip(t, map[string]string{"index.html": "x", "../evil.txt": "y"})
	archive, checksum = stageArchive(t, raw)
	err = archiveUI(archive, checksum, destination)
	mustCode(t, err, "dashboard-archive-unsafe-path")

	// Not a zip at all.
	archive, checksum = stageArchive(t, []byte("definitely not a zip"))
	err = archiveUI(archive, checksum, destination)
	mustCode(t, err, "dashboard-archive-invalid")
}

func TestBundledDashboardIsPresent(t *testing.T) {
	if !strings.Contains(bundledDashboard, "<!doctype html") {
		t.Fatal("embedded dashboard.html is missing its doctype")
	}
}
