package delivery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

func ValidateURL(raw string) error {
	u, e := url.Parse(raw)
	if e != nil {
		return fail("download-url-refused")
	}
	if u.Scheme != "https" || u.User != nil || u.Fragment != "" || (u.Port() != "" && u.Port() != "443") {
		return fail("download-url-refused")
	}
	switch u.Hostname() {
	case "github.com", "api.github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com":
	default:
		return fail("download-host-refused")
	}
	for _, c := range raw {
		if c < 33 || c == 127 {
			return fail("download-url-refused")
		}
	}
	return nil
}

type Downloader struct{ Client *http.Client }

func (d Downloader) stream(ctx context.Context, raw string, w io.Writer, limit int64) (int64, error) {
	if e := ValidateURL(raw); e != nil {
		return 0, e
	}
	c := http.Client{Timeout: 90 * time.Second}
	if d.Client != nil {
		c = *d.Client
	}
	c.CheckRedirect = func(r *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return fail("download-redirect-limit")
		}
		return ValidateURL(r.URL.String())
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if e != nil {
		return 0, e
	}
	req.Header.Set("User-Agent", Project+"/"+Version)
	req.Header.Set("Accept-Encoding", "identity")
	r, e := c.Do(req)
	if e != nil {
		return 0, fail("download-unavailable")
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		return 0, fail("download-http-status")
	}
	if r.ContentLength > limit {
		return 0, fail("download-too-large")
	}
	if r.Header.Get("Content-Encoding") != "" && r.Header.Get("Content-Encoding") != "identity" {
		return 0, fail("download-content-encoding-refused")
	}
	n, e := io.Copy(w, io.LimitReader(r.Body, limit+1))
	if e != nil {
		return n, fail("download-incomplete")
	}
	if n == 0 || n > limit {
		return n, fail("download-size-invalid")
	}
	if r.ContentLength >= 0 && n != r.ContentLength {
		return n, fail("download-size-mismatch")
	}
	return n, nil
}

// Download requires an independently obtained digest, never a checksum fetched alongside the asset.
// It publishes the destination only after a complete bounded transfer and hash match.
func (d Downloader) Download(ctx context.Context, raw, destination, expected string) error {
	if !shaPattern.MatchString(expected) {
		return fail("reviewed-digest-required")
	}
	if e := platform.CheckPath(destination); e != nil {
		return e
	}
	if _, e := os.Lstat(destination); !os.IsNotExist(e) {
		return fail("download-destination-exists")
	}
	if e := platform.PrivateDir(filepath.Dir(destination)); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(destination), ".download-*")
	if e != nil {
		return e
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	defer f.Close()
	h := sha256.New()
	if _, e = d.stream(ctx, raw, io.MultiWriter(f, h), MaxDownload); e != nil {
		return e
	}
	if hex.EncodeToString(h.Sum(nil)) != expected {
		return fail("download-digest-mismatch")
	}
	if e = f.Sync(); e != nil {
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	// Link publication is atomic and cannot overwrite a concurrently created
	// destination (Rename would overwrite it on Unix).
	if e = os.Link(tmp, destination); e != nil {
		return e
	}
	return syncDir(filepath.Dir(destination))
}

type ReleaseAsset struct {
	Name   string `json:"name"`
	URL    string `json:"browser_download_url"`
	Size   int64  `json:"size"`
	Digest string `json:"digest"`
	State  string `json:"state"`
}
type Release struct {
	Tag        string         `json:"tag_name"`
	Draft      bool           `json:"draft"`
	Prerelease bool           `json:"prerelease"`
	Assets     []ReleaseAsset `json:"assets"`
}

func (d Downloader) Metadata(ctx context.Context, version string) (Release, error) {
	var r Release
	endpoint := "latest"
	if version != "" && version != "latest" {
		v := strings.TrimPrefix(version, "v")
		if _, e := CompareVersions(v, v); e != nil {
			return r, e
		}
		endpoint = "tags/v" + v
	}
	var b strings.Builder
	if _, e := d.stream(ctx, "https://api.github.com/repos/"+Repository+"/releases/"+endpoint, &b, 2<<20); e != nil {
		return r, e
	}
	// GitHub adds fields over time. Validate duplicates using the generic representation first.
	var generic any
	if e := StrictJSON([]byte(b.String()), &generic); e != nil {
		return r, e
	}
	if e := json.Unmarshal([]byte(b.String()), &r); e != nil {
		return r, fail("release-metadata-invalid")
	}
	v := strings.TrimPrefix(r.Tag, "v")
	if !strings.HasPrefix(r.Tag, "v") {
		return r, fail("release-tag-invalid")
	}
	if _, e := CompareVersions(v, v); e != nil {
		return r, e
	}
	if r.Draft || r.Prerelease || (endpoint != "latest" && r.Tag != "v"+strings.TrimPrefix(version, "v")) {
		return r, fail("release-not-stable")
	}
	// Missing boolean fields must not silently decode to a stable release.
	obj, ok := generic.(map[string]any)
	if !ok || obj["draft"] != false || obj["prerelease"] != false {
		return r, fail("release-metadata-invalid")
	}
	seen := map[string]bool{}
	for _, a := range r.Assets {
		if !safeName(a.Name) || strings.Contains(a.Name, "/") || seen[a.Name] {
			return r, fail("release-assets-invalid")
		}
		seen[a.Name] = true
	}
	return r, nil
}
func (d Downloader) Fetch(ctx context.Context, r Release, destination, expected, kind string) (string, error) {
	return d.FetchTarget(ctx, r, destination, expected, kind, "")
}
func targetArch(target string) (string, error) {
	switch target {
	case "":
		return runtime.GOARCH, nil
	case "linux-amd64", "linux-x86_64":
		return "amd64", nil
	case "linux-arm64", "linux-aarch64":
		return "arm64", nil
	default:
		return "", usage("release-target-unsupported")
	}
}
func (d Downloader) FetchTarget(ctx context.Context, r Release, destination, expected, kind, target string) (string, error) {
	arch, e := targetArch(target)
	if e != nil {
		return "", e
	}
	if !filepath.IsAbs(destination) {
		return "", usage("release-output-dir-must-be-absolute")
	}
	if kind == "" {
		kind = "basic"
	}
	if kind != "basic" && kind != "offline" {
		return "", usage("release-kind-invalid")
	}
	name := AssetName(strings.TrimPrefix(r.Tag, "v"), arch, kind)
	for _, a := range r.Assets {
		if a.Name != name {
			continue
		}
		want := "https://github.com/" + Repository + "/releases/download/" + r.Tag + "/" + name
		if a.URL != want || a.State != "uploaded" || a.Size <= 0 || a.Size > MaxDownload {
			return "", fail("release-asset-invalid")
		}
		if !shaPattern.MatchString(expected) {
			return "", fail("reviewed-digest-required")
		}
		if a.Digest != "" && a.Digest != "sha256:"+expected {
			return "", fail("release-api-digest-disagrees")
		}
		p := filepath.Join(destination, name)
		if e := platform.PrivateDir(destination); e != nil {
			return "", e
		}
		if _, e := os.Lstat(p); !os.IsNotExist(e) {
			return "", fail("release-output-exists")
		}
		stage, e := os.MkdirTemp(destination, ".fetch-*")
		if e != nil {
			return "", e
		}
		defer os.RemoveAll(stage)
		candidate := filepath.Join(stage, name)
		if e := d.Download(ctx, want, candidate, expected); e != nil {
			return "", e
		}
		st, e := os.Stat(candidate)
		if e != nil {
			return "", e
		}
		if st.Size() != a.Size {
			return "", fail("release-asset-size-mismatch")
		}
		payload := filepath.Join(stage, "payload")
		if e = os.Mkdir(payload, 0700); e != nil {
			return "", e
		}
		f, e := platform.OpenRegular(candidate)
		if e != nil {
			return "", e
		}
		e = ExtractTarGzip(f, payload)
		f.Close()
		if e != nil {
			return "", e
		}
		m, e := LoadManifest(payload)
		if e != nil {
			return "", e
		}
		if m.Version != strings.TrimPrefix(r.Tag, "v") || m.Kind != kind || m.Arch != arch {
			return "", fail("release-manifest-identity-mismatch")
		}
		if e = VerifyTree(payload, m); e != nil {
			return "", e
		}
		if e = os.Link(candidate, p); e != nil {
			return "", e
		}
		if e = syncDir(destination); e != nil {
			return "", e
		}
		return p, nil
	}
	return "", fail("release-asset-unavailable")
}
