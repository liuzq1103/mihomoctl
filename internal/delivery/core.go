package delivery

import (
	"bytes"
	"compress/gzip"
	"context"
	_ "embed"
	"encoding/binary"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

//go:embed mihomo-digests.json
var coreDigests []byte

type Pin struct {
	Version    string `json:"version"`
	Asset      string `json:"asset"`
	SHA256     string `json:"sha256"`
	URL        string `json:"url"`
	Source     string `json:"source"`
	ReviewedBy string `json:"reviewed_by"`
	ReviewedAt string `json:"reviewed_at"`
}
type CorePlan struct {
	Version    string `json:"version"`
	Asset      string `json:"asset"`
	SHA256     string `json:"sha256"`
	URL        string `json:"url"`
	Provenance string `json:"provenance"`
}

func Pins() ([]Pin, error) {
	var table struct {
		Format     int    `json:"format"`
		Provenance string `json:"provenance"`
		Pins       []Pin  `json:"pins"`
	}
	if e := StrictJSON(coreDigests, &table); e != nil {
		return nil, e
	}
	if table.Format != 1 || table.Provenance == "" {
		return nil, fail("core-pins-invalid")
	}
	seen := map[string]bool{}
	for _, p := range table.Pins {
		if !strings.HasPrefix(p.Version, "v") {
			return nil, fail("core-pins-invalid")
		}
		if _, e := CompareVersions(p.Version[1:], p.Version[1:]); e != nil {
			return nil, e
		}
		if !shaPattern.MatchString(p.SHA256) || p.Source == "" || p.ReviewedBy == "" || p.ReviewedAt == "" || !safeName(p.Asset) || p.URL != "https://github.com/MetaCubeX/mihomo/releases/download/"+p.Version+"/"+p.Asset || seen[p.Asset] {
			return nil, fail("core-pins-invalid")
		}
		seen[p.Asset] = true
	}
	return table.Pins, nil
}
func PlanCore(version, arch, sha string) (CorePlan, error) {
	var plan CorePlan
	if !strings.HasPrefix(version, "v") {
		return plan, usage("core-version-invalid")
	}
	if _, e := CompareVersions(strings.TrimPrefix(version, "v"), strings.TrimPrefix(version, "v")); e != nil {
		return plan, e
	}
	variant := arch
	if arch == "amd64" {
		variant = "amd64-compatible"
	} else if arch != "arm64" {
		return plan, usage("core-arch-unsupported")
	}
	asset := "mihomo-linux-" + variant + "-" + version + ".gz"
	plan = CorePlan{version, asset, sha, "https://github.com/MetaCubeX/mihomo/releases/download/" + version + "/" + asset, "user-provided-sha256"}
	pins, e := Pins()
	if e != nil {
		return plan, e
	}
	for _, p := range pins {
		if p.Version == version && p.Asset == asset {
			if sha != "" && sha != p.SHA256 {
				return plan, fail("core-pin-disagrees")
			}
			plan.SHA256 = p.SHA256
			plan.Provenance = "maintainer-pin"
			return plan, nil
		}
	}
	if !shaPattern.MatchString(sha) {
		return plan, fail("core-reviewed-digest-required")
	}
	return plan, nil
}

// VerifyCore checks bounded gzip, ELF64 little endian, and the requested architecture.
func VerifyCore(compressed []byte, arch string) ([]byte, error) {
	if int64(len(compressed)) > MaxDownload {
		return nil, fail("core-asset-too-large")
	}
	g, e := gzip.NewReader(bytes.NewReader(compressed))
	if e != nil {
		return nil, fail("core-gzip-invalid")
	}
	defer g.Close()
	b, e := io.ReadAll(io.LimitReader(g, MaxExpanded+1))
	if e != nil {
		return nil, fail("core-gzip-invalid")
	}
	if int64(len(b)) > MaxExpanded {
		return nil, fail("core-too-large")
	}
	machine := uint16(62)
	if arch == "arm64" {
		machine = 183
	} else if arch != "amd64" {
		return nil, usage("core-arch-unsupported")
	}
	if len(b) < 64 || !bytes.Equal(b[:4], []byte{127, 'E', 'L', 'F'}) || b[4] != 2 || b[5] != 1 || b[6] != 1 || binary.LittleEndian.Uint16(b[18:20]) != machine {
		return nil, fail("core-elf-architecture-invalid")
	}
	return b, nil
}

// PrepareCore downloads only pinned or explicitly reviewed bytes; it never executes foreign code.
func PrepareCore(ctx context.Context, plan CorePlan, arch, destination string, d Downloader) error {
	return prepareCore(ctx, plan, arch, destination, "", d)
}

// PrepareCoreFromFile supports strict offline acquisition. Local cached bytes
// must match the same independently reviewed archive digest as network bytes.
func PrepareCoreFromFile(ctx context.Context, plan CorePlan, arch, destination, input string) error {
	if input == "" {
		return usage("core-asset-path-required")
	}
	return prepareCore(ctx, plan, arch, destination, input, Downloader{})
}
func prepareCore(ctx context.Context, plan CorePlan, arch, destination, input string, d Downloader) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if !shaPattern.MatchString(plan.SHA256) {
		return fail("core-reviewed-digest-required")
	}
	if e := platform.PrivateDir(filepath.Dir(destination)); e != nil {
		return e
	}
	stage, e := os.MkdirTemp(filepath.Dir(destination), ".core-download-*")
	if e != nil {
		return e
	}
	defer os.RemoveAll(stage)
	archive := filepath.Join(stage, plan.Asset)
	if input != "" {
		h, size, e := fileDigest(input)
		if e != nil {
			return e
		}
		if size > MaxDownload {
			return fail("core-asset-too-large")
		}
		if h != plan.SHA256 {
			return fail("core-asset-digest-mismatch")
		}
		archive = input
	} else if e = d.Download(ctx, plan.URL, archive, plan.SHA256); e != nil {
		return e
	}
	b, e := readBoundedFile(archive, MaxDownload)
	if e != nil {
		return e
	}
	if platform.Hash(b) != plan.SHA256 {
		return fail("core-asset-digest-mismatch")
	}
	b, e = VerifyCore(b, arch)
	if e != nil {
		return e
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	return platform.AtomicWrite(destination, b, 0700)
}

type cappedOutput struct {
	b        bytes.Buffer
	overflow bool
}

func (w *cappedOutput) Write(b []byte) (int, error) {
	n := len(b)
	remain := 8192 - w.b.Len()
	if len(b) > remain {
		w.overflow = true
		b = b[:remain]
	}
	_, _ = w.b.Write(b)
	return n, nil
}
func verifyCoreVersion(ctx context.Context, p, version string, system bool) error {
	line, e := probeCoreVersion(ctx, p, system)
	if e != nil {
		return e
	}
	match := coreVersionPattern.FindStringSubmatch(line)
	if match == nil || match[1] != strings.TrimPrefix(version, "v") {
		return fail("core-version-mismatch")
	}
	return nil
}

var coreVersionPattern = regexp.MustCompile(`^Mihomo Meta v?([0-9]+\.[0-9]+\.[0-9]+)(?:\s|$)`)

func probeCoreVersion(ctx context.Context, p string, system bool) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	dir, e := os.MkdirTemp("", "mihomoctl-go-version-*")
	if e != nil {
		return "", e
	}
	defer os.RemoveAll(dir)
	cmd := exec.CommandContext(ctx, p, "-v")
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "HOME=/nonexistent"}
	cmd.Dir = dir
	cmd.WaitDelay = time.Second
	var out, diagnostics cappedOutput
	cmd.Stdout = &out
	cmd.Stderr = &diagnostics
	if e := coreValidationIdentity(cmd, p, system); e != nil {
		return "", e
	}
	if cmd.Dir != dir && cmd.Dir != "" {
		defer os.RemoveAll(cmd.Dir)
	}
	if e := cmd.Run(); e != nil || out.overflow || diagnostics.overflow {
		return "", fail("core-version-failed")
	}
	line, _, _ := strings.Cut(strings.TrimSpace(out.b.String()), "\n")
	line = strings.TrimSpace(line)
	if !coreVersionPattern.MatchString(line) {
		return "", fail("core-version-unrecognized")
	}
	return line, nil
}

func configuredCoreVersion(ctx context.Context, a platform.App) any {
	m, e := a.LoadManager()
	if e != nil {
		return nil
	}
	p := platform.String(platform.Map(m["core"])["binary"])
	if e = trustedVersionBinary(p, a.Scope.System); e != nil {
		return nil
	}
	line, e := probeCoreVersion(ctx, p, a.Scope.System)
	if e != nil {
		return nil
	}
	return line
}

func coreInstall(ctx context.Context, a platform.App, r platform.Request) (map[string]any, error) {
	v := r.Get("version")
	if v == "" {
		v = r.Arg(0)
	}
	plan, e := PlanCore(v, runtime.GOARCH, r.Get("sha256"))
	if e != nil {
		return nil, e
	}
	data := map[string]any{"plan": plan, "version": plan.Version, "sha256": plan.SHA256, "provenance": plan.Provenance, "url": plan.URL, "asset": plan.Asset, "activated": false, "activation": "use core adopt --path after installation", "signature_verified": false, "dry_run": r.Has("dry-run")}
	if r.Has("dry-run") {
		return data, nil
	}
	e = platform.WithLock(ctx, a.Scope, func() error {
		root := filepath.Join(a.Scope.DataRoot, "cores")
		if e := platform.PrivateDir(root); e != nil {
			return e
		}
		// Immutable digest-addressed generations preserve all existing and active core paths.
		dest := filepath.Join(root, v+"-"+plan.SHA256[:16])
		data["binary"] = filepath.Join(dest, "mihomo")
		if e := platform.CheckPath(dest); e != nil {
			return e
		}
		if _, e := os.Lstat(dest); !os.IsNotExist(e) {
			return fail("core-already-installed")
		}
		stage, e := os.MkdirTemp(root, ".core-stage-*")
		if e != nil {
			return e
		}
		defer os.RemoveAll(stage)
		binary := filepath.Join(stage, "mihomo")
		if r.Get("asset") != "" {
			e = PrepareCoreFromFile(ctx, plan, runtime.GOARCH, binary, r.Get("asset"))
		} else {
			e = PrepareCore(ctx, plan, runtime.GOARCH, binary, Downloader{})
		}
		if e != nil {
			return e
		}
		if e = verifyCoreVersion(ctx, binary, v, a.Scope.System); e != nil {
			return e
		}
		h, _, e := fileDigest(binary)
		if e != nil {
			return e
		}
		receipt := map[string]any{"format": 1, "project": Project, "plan": plan, "binary_sha256": h, "installed_at": time.Now().UTC(), "note": "digest comparison, not an upstream signature"}
		if e = platform.WriteJSON(filepath.Join(stage, "receipt.json"), receipt); e != nil {
			return e
		}
		if e = os.Rename(stage, dest); e != nil {
			return e
		}
		return syncDir(root)
	})
	return data, e
}
