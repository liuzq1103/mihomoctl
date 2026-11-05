package delivery

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

func TestFetchVerifiesManifestBeforePublication(t *testing.T) {
	for _, tc := range []struct {
		name, version string
		valid         bool
	}{{"valid", "0.2.0", true}, {"wrong-version", "0.1.0", false}} {
		t.Run(tc.name, func(t *testing.T) {
			source := fixture(t, tc.version, "binary")
			archive := filepath.Join(privateTemp(t), "bundle.tar.gz")
			if e := Archive(source, archive); e != nil {
				t.Fatal(e)
			}
			b, e := os.ReadFile(archive)
			if e != nil {
				t.Fatal(e)
			}
			name := AssetName("0.2.0", runtime.GOARCH, "basic")
			url := "https://github.com/" + Repository + "/releases/download/v0.2.0/" + name
			meta := Release{Tag: "v0.2.0", Assets: []ReleaseAsset{{Name: name, URL: url, Size: int64(len(b)), State: "uploaded", Digest: "sha256:" + platform.Hash(b)}}}
			d := Downloader{Client: &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) { return response(r, 200, string(b), int64(len(b))), nil })}}
			dest := privateTemp(t)
			p, e := d.Fetch(context.Background(), meta, dest, platform.Hash(b), "basic")
			if (e == nil) != tc.valid {
				t.Fatal(e)
			}
			if !tc.valid {
				if _, e = os.Stat(filepath.Join(dest, name)); !os.IsNotExist(e) {
					t.Fatal("invalid candidate published")
				}
			} else if p != filepath.Join(dest, name) {
				t.Fatal(p)
			}
		})
	}
}
func TestDownloadCancellationAndStreamingBound(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	d := Downloader{Client: &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		select {
		case <-r.Context().Done():
			return nil, r.Context().Err()
		case <-time.After(time.Second):
			t.Error("request failed to carry cancellation")
			return nil, context.DeadlineExceeded
		}
	})}}
	if e := d.Download(ctx, "https://github.com/asset", filepath.Join(privateTemp(t), "asset"), strings.Repeat("0", 64)); e == nil {
		t.Fatal("cancelled transfer accepted")
	}
	d.Client.Transport = transportFunc(func(r *http.Request) (*http.Response, error) { return response(r, 200, "123456", -1), nil })
	if _, e := d.stream(context.Background(), "https://github.com/asset", io.Discard, 4); e == nil {
		t.Fatal("unknown-length transfer escaped bound")
	}
}

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func response(r *http.Request, status int, b string, size int64) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(b)), ContentLength: size, Request: r}
}
func TestDownloaderAtomicAndBounded(t *testing.T) {
	for _, tc := range []struct {
		name   string
		body   string
		size   int64
		sha    string
		status int
		ok     bool
	}{
		{"valid", "asset", 5, platform.Hash([]byte("asset")), 200, true},
		{"digest", "asset", 5, strings.Repeat("0", 64), 200, false},
		{"truncated", "abc", 6, platform.Hash([]byte("abc")), 200, false},
		{"oversized", "abc", MaxDownload + 1, platform.Hash([]byte("abc")), 200, false},
		{"status", "abc", 3, platform.Hash([]byte("abc")), 404, false},
		{"empty", "", 0, platform.Hash(nil), 200, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := Downloader{Client: &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) { return response(r, tc.status, tc.body, tc.size), nil })}}
			p := filepath.Join(privateTemp(t), "asset")
			e := d.Download(context.Background(), "https://github.com/official/asset", p, tc.sha)
			if (e == nil) != tc.ok {
				t.Fatal(e)
			}
			_, se := os.Stat(p)
			if !tc.ok && !os.IsNotExist(se) {
				t.Fatal("failed transfer published destination")
			}
			files, _ := filepath.Glob(filepath.Join(filepath.Dir(p), ".download-*"))
			if len(files) != 0 {
				t.Fatal("temporary download leaked")
			}
		})
	}
}
func TestRedirectRefusesUntrustedHost(t *testing.T) {
	calls := 0
	d := Downloader{Client: &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		res := response(r, 302, "redirect", 8)
		res.Header.Set("Location", "https://evil.example/payload")
		return res, nil
	})}}
	e := d.Download(context.Background(), "https://github.com/release", filepath.Join(privateTemp(t), "asset"), strings.Repeat("0", 64))
	if e == nil || calls != 1 {
		t.Fatal(e, calls)
	}
}
func TestURLPolicy(t *testing.T) {
	for _, u := range []string{"http://github.com/a", "https://github.com.evil/a", "https://user@github.com/a", "https://github.com:8443/a", "https://github.com/a#frag", "https://127.0.0.1/a"} {
		if e := ValidateURL(u); e == nil {
			t.Fatal(u)
		}
	}
}

func TestDownloadNeverClobbersConcurrentDestination(t *testing.T) {
	dest := filepath.Join(privateTemp(t), "asset")
	d := Downloader{Client: &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		if e := os.WriteFile(dest, []byte("concurrent-owner"), 0600); e != nil {
			t.Fatal(e)
		}
		return response(r, 200, "asset", 5), nil
	})}}
	if e := d.Download(context.Background(), "https://github.com/asset", dest, platform.Hash([]byte("asset"))); e == nil {
		t.Fatal("concurrent destination overwritten")
	}
	b, e := os.ReadFile(dest)
	if e != nil || string(b) != "concurrent-owner" {
		t.Fatal(string(b), e)
	}
}
func TestMetadataStableAndTrust(t *testing.T) {
	for _, body := range []string{`{"tag_name":"v0.2.0","draft":true,"prerelease":false,"assets":[]}`, `{"tag_name":"v0.2.0","assets":[]}`, `{"tag_name":"v0.2.0","draft":false,"draft":false,"prerelease":false}`, `{"tag_name":"v0.2.0-rc1","draft":false,"prerelease":false}`} {
		d := Downloader{Client: &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) { return response(r, 200, body, int64(len(body))), nil })}}
		if _, e := d.Metadata(context.Background(), ""); e == nil {
			t.Fatal(body)
		}
	}
	d := Downloader{Client: &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		body := `{"tag_name":"v0.3.0","draft":false,"prerelease":false,"assets":[],"new_github_field":1}`
		return response(r, 200, body, int64(len(body))), nil
	})}}
	if _, e := d.Metadata(context.Background(), ""); e != nil {
		t.Fatal(e)
	}
}
