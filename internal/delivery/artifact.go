// Package delivery owns release acquisition and independently scoped installation.
package delivery

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

const Project = "mihomoctl-go"
const Repository = "liuzq1103/mihomoctl"
const Version = "0.2.0"
const MaxDownload int64 = 128 << 20
const MaxExpanded int64 = 512 << 20
const MaxMembers = 20000

var shaPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var versionPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

func fail(code string) error  { return platform.Fail(code) }
func usage(code string) error { return platform.Usage(code) }

// CompareVersions accepts stable numeric triples only; no lexicographic ordering.
func CompareVersions(a, b string) (int, error) {
	if !versionPattern.MatchString(a) || !versionPattern.MatchString(b) {
		return 0, usage("release-version-invalid")
	}
	aa, bb := strings.Split(a, "."), strings.Split(b, ".")
	for i := range aa {
		x, e := strconv.ParseUint(aa[i], 10, 32)
		if e != nil {
			return 0, usage("release-version-invalid")
		}
		y, e := strconv.ParseUint(bb[i], 10, 32)
		if e != nil {
			return 0, usage("release-version-invalid")
		}
		if x < y {
			return -1, nil
		}
		if x > y {
			return 1, nil
		}
	}
	return 0, nil
}

// StrictJSON rejects duplicate keys, trailing documents, unknown fields and excessive depth.
func StrictJSON(b []byte, dst any) error {
	if len(b) > 2<<20 {
		return fail("metadata-too-large")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 64 {
			return fail("metadata-too-deep")
		}
		t, e := d.Token()
		if e != nil {
			return e
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return e
				}
				s, ok := k.(string)
				if !ok || seen[s] {
					return fail("metadata-duplicate-key")
				}
				seen[s] = true
				if e = walk(depth + 1); e != nil {
					return e
				}
			}
		case '[':
			for d.More() {
				if e = walk(depth + 1); e != nil {
					return e
				}
			}
		default:
			return fail("metadata-invalid")
		}
		_, e = d.Token()
		return e
	}
	if e := walk(0); e != nil {
		return e
	}
	if _, e := d.Token(); e != io.EOF {
		return fail("metadata-trailing-data")
	}
	d = json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e := d.Decode(dst); e != nil {
		return fail("metadata-invalid")
	}
	return nil
}

type File struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	Mode   uint32 `json:"mode"`
}
type Manifest struct {
	Format  int             `json:"format"`
	Project string          `json:"project"`
	Version string          `json:"version"`
	Kind    string          `json:"kind"`
	OS      string          `json:"os"`
	Arch    string          `json:"arch"`
	Files   map[string]File `json:"files"`
	Core    *CorePlan       `json:"core,omitempty"`
}

func safeName(n string) bool {
	if n == "" || n == "." || strings.ContainsAny(n, "\\:\x00\r\n") || strings.HasPrefix(n, "/") || path.Clean(n) != n {
		return false
	}
	for _, p := range strings.Split(n, "/") {
		if p == ".." || p == "." || p == "" {
			return false
		}
	}
	return true
}
func fileDigest(p string) (string, int64, error) {
	if e := platform.CheckPath(p); e != nil {
		return "", 0, e
	}
	f, e := platform.OpenRegular(p)
	if e != nil {
		return "", 0, e
	}
	defer f.Close()
	s, e := f.Stat()
	if e != nil || !s.Mode().IsRegular() {
		return "", 0, fail("artifact-not-regular")
	}
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(f, MaxExpanded+1))
	if e != nil {
		return "", 0, e
	}
	if n > MaxExpanded {
		return "", 0, fail("artifact-too-large")
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func readBoundedFile(p string, limit int64) ([]byte, error) {
	if e := platform.CheckPath(p); e != nil {
		return nil, e
	}
	f, e := platform.OpenRegular(p)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return nil, e
	}
	if !st.Mode().IsRegular() || st.Size() > limit {
		return nil, fail("artifact-size-or-type-invalid")
	}
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil {
		return nil, e
	}
	if int64(len(b)) > limit {
		return nil, fail("artifact-too-large")
	}
	return b, nil
}

// ExtractTarGzip accepts regular files/directories only, with strict global limits.
// The destination must be empty. No archive permissions, links or special files survive.
func ExtractTarGzip(r io.Reader, destination string) error {
	if e := platform.CheckPath(destination); e != nil {
		return e
	}
	es, e := os.ReadDir(destination)
	if e != nil {
		return e
	}
	if len(es) != 0 {
		return fail("extract-destination-not-empty")
	}
	g, e := gzip.NewReader(r)
	if e != nil {
		return fail("archive-corrupt")
	}
	defer g.Close()
	limited := &io.LimitedReader{R: g, N: MaxExpanded + 1}
	t := tar.NewReader(limited)
	seen := map[string]bool{}
	var total int64
	for count := 0; ; count++ {
		h, e := t.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return fail("archive-corrupt")
		}
		if count >= MaxMembers {
			return fail("archive-too-many-members")
		}
		n := strings.TrimSuffix(h.Name, "/")
		if !safeName(n) || seen[n] {
			return fail("archive-unsafe-path")
		}
		seen[n] = true
		if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeDir {
			return fail("archive-link-or-special-refused")
		}
		if h.Size < 0 || h.Size > MaxExpanded-total {
			return fail("archive-too-large")
		}
		total += h.Size
		p := filepath.Join(destination, filepath.FromSlash(n))
		if e = platform.CheckPath(p); e != nil {
			return e
		}
		if h.Typeflag == tar.TypeDir {
			if h.Size != 0 {
				return fail("archive-invalid-directory")
			}
			if e = os.MkdirAll(p, 0700); e != nil {
				return e
			}
			continue
		}
		if e = os.MkdirAll(filepath.Dir(p), 0700); e != nil {
			return e
		}
		f, e := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return e
		}
		_, e = io.CopyN(f, t, h.Size)
		ce := f.Close()
		if e != nil {
			return fail("archive-truncated")
		}
		if ce != nil {
			return ce
		}
	}
	// Consume padding and gzip trailer so CRC errors and decompression bombs cannot hide after tar EOF.
	if _, e = io.Copy(io.Discard, limited); e != nil {
		return fail("archive-corrupt")
	}
	if limited.N <= 0 {
		return fail("archive-too-large")
	}
	return nil
}

func LoadManifest(root string) (Manifest, error) {
	var m Manifest
	b, e := platform.ReadPrivate(filepath.Join(root, "release-manifest.json"))
	if e != nil {
		return m, e
	}
	if e = StrictJSON(b, &m); e != nil {
		return m, e
	}
	if m.Format != 1 || m.Project != Project || m.OS != "linux" || (m.Arch != "amd64" && m.Arch != "arm64") || (m.Kind != "basic" && m.Kind != "offline") || len(m.Files) == 0 || len(m.Files) >= MaxMembers {
		return m, fail("manifest-identity-invalid")
	}
	if _, e = CompareVersions(m.Version, m.Version); e != nil {
		return m, e
	}
	if _, ok := m.Files["bin/mihomoctl"]; !ok {
		return m, fail("manifest-entrypoint-missing")
	}
	if m.Files["bin/mihomoctl"].Mode != 0700 {
		return m, fail("manifest-entrypoint-not-executable")
	}
	if m.Kind == "offline" {
		if m.Core == nil {
			return m, fail("offline-core-missing")
		}
		pin, e := PlanCore(m.Core.Version, m.Arch, "")
		if e != nil || pin != *m.Core {
			return m, fail("offline-core-not-reviewed")
		}
		if _, ok := m.Files["core/mihomo"]; !ok {
			return m, fail("offline-core-missing")
		}
		if compressed, ok := m.Files["core/"+m.Core.Asset]; !ok || compressed.SHA256 != m.Core.SHA256 {
			return m, fail("offline-core-reviewed-archive-missing")
		}
	}
	if m.Kind == "basic" && m.Core != nil {
		return m, fail("manifest-core-unexpected")
	}
	for n, f := range m.Files {
		if !safeName(n) || n == "release-manifest.json" || !shaPattern.MatchString(f.SHA256) || f.Size < 0 || f.Size > MaxExpanded || (f.Mode != 0600 && f.Mode != 0700) {
			return m, fail("manifest-inventory-invalid")
		}
	}
	return m, nil
}

// VerifyTree verifies every byte and rejects undeclared files, links and special files.
// Hashes in a manifest establish consistency; the caller must establish its provenance.
func VerifyTree(root string, m Manifest) error {
	seen := map[string]bool{}
	var total int64
	e := filepath.WalkDir(root, func(p string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if e = platform.CheckPath(p); e != nil {
			return e
		}
		if d.IsDir() {
			return nil
		}
		rel, e := filepath.Rel(root, p)
		if e != nil {
			return e
		}
		n := filepath.ToSlash(rel)
		if n == "release-manifest.json" {
			return nil
		}
		f, ok := m.Files[n]
		if !ok {
			return fail("manifest-unlisted-file")
		}
		hash, size, e := fileDigest(p)
		if e != nil {
			return e
		}
		if hash != f.SHA256 || size != f.Size {
			return fail("manifest-digest-mismatch")
		}
		total += size
		if total > MaxExpanded {
			return fail("manifest-too-large")
		}
		seen[n] = true
		return nil
	})
	if e != nil {
		return e
	}
	if len(seen) != len(m.Files) {
		return fail("manifest-file-missing")
	}
	if m.Core != nil {
		b, e := readBoundedFile(filepath.Join(root, "core", m.Core.Asset), MaxDownload)
		if e != nil {
			return e
		}
		if platform.Hash(b) != m.Core.SHA256 {
			return fail("offline-core-pin-mismatch")
		}
		core, e := VerifyCore(b, m.Arch)
		if e != nil {
			return e
		}
		if platform.Hash(core) != m.Files["core/mihomo"].SHA256 {
			return fail("offline-core-payload-mismatch")
		}
	}
	return nil
}

// WriteManifest is used by the Go release builder after all inputs are finalized.
func WriteManifest(root string, m Manifest) error {
	m.Format = 1
	m.Project = Project
	m.OS = "linux"
	m.Files = map[string]File{}
	e := filepath.WalkDir(root, func(p string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.IsDir() {
			return nil
		}
		n, e := filepath.Rel(root, p)
		if e != nil {
			return e
		}
		n = filepath.ToSlash(n)
		if n == "release-manifest.json" {
			return fail("manifest-already-exists")
		}
		h, s, e := fileDigest(p)
		if e != nil {
			return e
		}
		mode := uint32(0600)
		if n == "bin/mihomoctl" || n == "core/mihomo" {
			mode = 0700
		}
		m.Files[n] = File{h, s, mode}
		return nil
	})
	if e != nil {
		return e
	}
	if e = platform.WriteJSON(filepath.Join(root, "release-manifest.json"), m); e != nil {
		return e
	}
	validated, e := LoadManifest(root)
	if e != nil {
		return e
	}
	return VerifyTree(root, validated)
}

// Archive creates a deterministic archive of regular files under root.
func Archive(root, destination string) error {
	var names []string
	e := filepath.WalkDir(root, func(p string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if !d.IsDir() {
			names = append(names, p)
		}
		return nil
	})
	if e != nil {
		return e
	}
	sort.Strings(names)
	f, e := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			os.Remove(destination)
		}
	}()
	g := gzip.NewWriter(f)
	t := tar.NewWriter(g)
	for _, p := range names {
		if e = platform.CheckPath(p); e != nil {
			return e
		}
		st, e := os.Stat(p)
		if e != nil || !st.Mode().IsRegular() {
			return fail("archive-not-regular")
		}
		n, e := filepath.Rel(root, p)
		if e != nil {
			return e
		}
		mode := int64(0600)
		if st.Mode().Perm()&0100 != 0 {
			mode = 0700
		}
		if e = t.WriteHeader(&tar.Header{Name: filepath.ToSlash(n), Mode: mode, Size: st.Size(), Typeflag: tar.TypeReg}); e != nil {
			return e
		}
		in, e := platform.OpenRegular(p)
		if e != nil {
			return e
		}
		_, e = io.Copy(t, in)
		in.Close()
		if e != nil {
			return e
		}
	}
	if e = t.Close(); e != nil {
		return e
	}
	if e = g.Close(); e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	ok = true
	return nil
}

func native(m Manifest) error {
	if m.OS != runtime.GOOS || m.Arch != runtime.GOARCH {
		return fail("artifact-platform-mismatch")
	}
	return nil
}
func AssetName(v, arch, kind string) string {
	return fmt.Sprintf("%s-%s-%s-linux-%s.tar.gz", Project, v, kind, arch)
}
