package delivery

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

func privateTemp(t *testing.T) string {
	t.Helper()
	p := t.TempDir()
	if e := os.Chmod(p, 0700); e != nil {
		t.Fatal(e)
	}
	return p
}

func makeArchive(t *testing.T, headers []*tar.Header, contents [][]byte) []byte {
	t.Helper()
	var b bytes.Buffer
	g := gzip.NewWriter(&b)
	tw := tar.NewWriter(g)
	for i, h := range headers {
		if e := tw.WriteHeader(h); e != nil {
			t.Fatal(e)
		}
		if len(contents) > i {
			if _, e := tw.Write(contents[i]); e != nil {
				t.Fatal(e)
			}
		}
	}
	if e := tw.Close(); e != nil {
		t.Fatal(e)
	}
	if e := g.Close(); e != nil {
		t.Fatal(e)
	}
	return b.Bytes()
}
func TestExtractionRefusesDangerousMembers(t *testing.T) {
	for _, tc := range []struct {
		name string
		h    *tar.Header
	}{
		{"parent", &tar.Header{Name: "../outside", Typeflag: tar.TypeReg}},
		{"absolute", &tar.Header{Name: "/outside", Typeflag: tar.TypeReg}},
		{"windows", &tar.Header{Name: `C:\outside`, Typeflag: tar.TypeReg}},
		{"backslash", &tar.Header{Name: `a\..\outside`, Typeflag: tar.TypeReg}},
		{"symlink", &tar.Header{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "../outside"}},
		{"hardlink", &tar.Header{Name: "link", Typeflag: tar.TypeLink, Linkname: "outside"}},
		{"fifo", &tar.Header{Name: "fifo", Typeflag: tar.TypeFifo}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := privateTemp(t)
			if e := ExtractTarGzip(bytes.NewReader(makeArchive(t, []*tar.Header{tc.h}, nil)), dir); e == nil {
				t.Fatal("unsafe archive accepted")
			}
		})
	}
	dup := makeArchive(t, []*tar.Header{{Name: "same", Typeflag: tar.TypeReg}, {Name: "same", Typeflag: tar.TypeReg}}, nil)
	if e := ExtractTarGzip(bytes.NewReader(dup), privateTemp(t)); e == nil {
		t.Fatal("duplicate member accepted")
	}
}
func TestExtractionBoundsAndCRC(t *testing.T) {
	b := makeArchive(t, []*tar.Header{{Name: "bin/mihomoctl", Mode: 0777, Typeflag: tar.TypeReg, Size: 4}}, [][]byte{[]byte("test")})
	dir := privateTemp(t)
	if e := ExtractTarGzip(bytes.NewReader(b), dir); e != nil {
		t.Fatal(e)
	}
	got, e := os.ReadFile(filepath.Join(dir, "bin", "mihomoctl"))
	if e != nil || string(got) != "test" {
		t.Fatal(e, string(got))
	}
	b[len(b)-8] ^= 1
	if e := ExtractTarGzip(bytes.NewReader(b), privateTemp(t)); e == nil {
		t.Fatal("corrupt CRC accepted")
	}
	var raw bytes.Buffer
	g := gzip.NewWriter(&raw)
	tw := tar.NewWriter(g)
	if e := tw.WriteHeader(&tar.Header{Name: "huge", Size: MaxExpanded + 1, Typeflag: tar.TypeReg}); e != nil {
		t.Fatal(e)
	}
	g.Close()
	if e := ExtractTarGzip(bytes.NewReader(raw.Bytes()), privateTemp(t)); e == nil {
		t.Fatal("unbounded member accepted")
	}
}
func TestStrictJSON(t *testing.T) {
	for _, b := range []string{`{"a":1,"a":2}`, `{"nested":{"x":1,"x":2}}`, `{} {}`, strings.Repeat("[", 70) + strings.Repeat("]", 70)} {
		var v any
		if e := StrictJSON([]byte(b), &v); e == nil {
			t.Fatalf("accepted %s", b)
		}
	}
	var dst struct {
		A int `json:"a"`
	}
	if e := StrictJSON([]byte(`{"a":1,"extra":2}`), &dst); e == nil {
		t.Fatal("unknown key accepted")
	}
}
func fixture(t *testing.T, version, content string) string {
	t.Helper()
	root := privateTemp(t)
	if e := platform.AtomicWrite(filepath.Join(root, "bin", "mihomoctl"), []byte(content), 0700); e != nil {
		t.Fatal(e)
	}
	if e := WriteManifest(root, Manifest{Version: version, Kind: "basic", Arch: runtime.GOARCH}); e != nil {
		t.Fatal(e)
	}
	return root
}
func TestManifestInventory(t *testing.T) {
	root := fixture(t, "0.2.0", "binary")
	m, e := LoadManifest(root)
	if e != nil {
		t.Fatal(e)
	}
	if e = VerifyTree(root, m); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(root, "unexpected"), []byte("secret"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = VerifyTree(root, m); e == nil {
		t.Fatal("unlisted file accepted")
	}
	os.Remove(filepath.Join(root, "unexpected"))
	os.WriteFile(filepath.Join(root, "bin", "mihomoctl"), []byte("tamper"), 0700)
	if e = VerifyTree(root, m); e == nil {
		t.Fatal("tampering accepted")
	}
}
func TestPinsAndCoreValidation(t *testing.T) {
	pins, e := Pins()
	if e != nil || len(pins) != 3 {
		t.Fatalf("pins: %v %v", pins, e)
	}
	p, e := PlanCore("v1.19.33", "amd64", "")
	if e != nil || p.SHA256 != "386508bfb1c72c43b6a0eda73708ecdce82546581b0ebcb16366c53757c622b6" {
		t.Fatal(p, e)
	}
	if _, e = PlanCore("v1.19.33", "amd64", strings.Repeat("0", 64)); e == nil {
		t.Fatal("conflicting pin accepted")
	}
	if p, e = PlanCore("v1.19.33", "arm64", ""); e != nil || p.SHA256 != "ba408b317080ee265c46cb923a50018c1b82cbd708551cdd46a1e3e307396187" {
		t.Fatal(p, e)
	}
	if _, e = PlanCore("v1.19.32", "arm64", ""); e == nil {
		t.Fatal("unreviewed arm64 version accepted")
	}
	if _, e = PlanCore("latest", "amd64", ""); e == nil {
		t.Fatal("implicit latest accepted")
	}
	elf := make([]byte, 64)
	copy(elf, []byte{127, 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint16(elf[18:20], 62)
	var b bytes.Buffer
	g := gzip.NewWriter(&b)
	g.Write(elf)
	g.Close()
	if _, e = VerifyCore(b.Bytes(), "amd64"); e != nil {
		t.Fatal(e)
	}
	if _, e = VerifyCore(b.Bytes(), "arm64"); e == nil {
		t.Fatal("wrong ELF architecture accepted")
	}
}

func TestCachedCoreValidationPreservesDestination(t *testing.T) {
	elf := make([]byte, 64)
	copy(elf, []byte{127, 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint16(elf[18:20], 62)
	var raw bytes.Buffer
	g := gzip.NewWriter(&raw)
	g.Write(elf)
	g.Close()
	input := filepath.Join(privateTemp(t), "asset.gz")
	if e := os.WriteFile(input, raw.Bytes(), 0600); e != nil {
		t.Fatal(e)
	}
	destination := filepath.Join(privateTemp(t), "mihomo")
	plan := CorePlan{Version: "v1.2.3", Asset: "asset.gz", SHA256: platform.Hash(raw.Bytes()), Provenance: "user-provided-sha256"}
	if e := PrepareCoreFromFile(context.Background(), plan, "amd64", destination, input); e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(destination)
	if e != nil || !bytes.Equal(b, elf) {
		t.Fatal(e)
	}
	plan.SHA256 = strings.Repeat("0", 64)
	if e = PrepareCoreFromFile(context.Background(), plan, "amd64", destination, input); e == nil {
		t.Fatal("corrupt cache accepted")
	}
	b, e = os.ReadFile(destination)
	if e != nil || !bytes.Equal(b, elf) {
		t.Fatal("failed cache transfer replaced destination")
	}
	plan.SHA256 = platform.Hash(raw.Bytes())
	if e = PrepareCoreFromFile(context.Background(), plan, "arm64", destination, input); e == nil {
		t.Fatal("wrong cached architecture accepted")
	}
}
func TestVersionOrdering(t *testing.T) {
	if n, e := CompareVersions("0.10.0", "0.2.0"); e != nil || n <= 0 {
		t.Fatal(n, e)
	}
	for _, v := range []string{"v0.2.0", "0.2", "0.02.0", "0.2.0-rc1", "99999999999999.2.0"} {
		if _, e := CompareVersions(v, "0.2.0"); e == nil {
			t.Fatal(v)
		}
	}
}
func TestArchiveRoundTrip(t *testing.T) {
	source := fixture(t, "0.2.0", "binary")
	dst := filepath.Join(privateTemp(t), "bundle.tar.gz")
	if e := Archive(source, dst); e != nil {
		t.Fatal(e)
	}
	f, e := os.Open(dst)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	out := privateTemp(t)
	if e = ExtractTarGzip(f, out); e != nil {
		t.Fatal(e)
	}
	m, e := LoadManifest(out)
	if e != nil {
		t.Fatal(e)
	}
	if e = VerifyTree(out, m); e != nil {
		t.Fatal(e)
	}
}
