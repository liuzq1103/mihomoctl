// release builds reviewed candidates locally; it never publishes anything.
package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/liuzq1103/mihomoctl/internal/delivery"
	"github.com/liuzq1103/mihomoctl/internal/platform"
)

func run() error {
	out := flag.String("out", "dist/release", "output directory")
	arches := flag.String("arch", "amd64,arm64", "Linux architectures")
	offline := flag.Bool("offline", false, "include complete offline bundles; requires embedded reviewed pin for every requested architecture")
	core := flag.String("core-version", "v1.19.33", "reviewed Mihomo version")
	cache := flag.String("core-cache", "", "strict offline directory containing reviewed core .gz files; no network fallback")
	inputs := flag.String("optional-inputs", "", "optional local directory: dashboard/, geodata/ (caller reviewed; no network lookup)")
	entry := flag.String("entry", ".", "Go CLI package; production candidates must use repository root")
	flag.Parse()
	if delivery.Version != platform.Version {
		return fmt.Errorf("platform version disagrees with delivery version")
	}
	provenance, e := readSourceProvenance(".")
	if e != nil {
		return e
	}
	if e := os.MkdirAll(*out, 0700); e != nil {
		return e
	}
	output, e := filepath.Abs(*out)
	if e != nil {
		return e
	}
	if e = platform.CheckPath(output); e != nil {
		return e
	}
	var outputs []string
	success := false
	defer func() {
		if !success {
			for _, p := range outputs {
				os.Remove(p)
			}
		}
	}()
	archList := strings.Split(*arches, ",")
	seen := map[string]bool{}
	// Preflight all trust requirements before producing partial offline candidates.
	for _, arch := range archList {
		if seen[arch] || (arch != "amd64" && arch != "arm64") {
			return fmt.Errorf("invalid/duplicate architecture: %s", arch)
		}
		seen[arch] = true
		if *offline {
			if _, e = delivery.PlanCore(*core, arch, ""); e != nil {
				return fmt.Errorf("offline %s unavailable: %w; add an independently reviewed pin, never copy an unreviewed remote checksum", arch, e)
			}
		}
	}
	for _, arch := range archList {
		stage, e := os.MkdirTemp(output, ".build-*")
		if e != nil {
			return e
		}
		e = func() error {
			defer os.RemoveAll(stage)
			root := filepath.Join(stage, "bundle")
			if e := os.MkdirAll(filepath.Join(root, "bin"), 0700); e != nil {
				return e
			}
			binary := filepath.Join(root, "bin", "mihomoctl")
			cmd := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-ldflags=-s -w", "-o", binary, *entry)
			cmd.Env = buildEnv(arch)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			if e := cmd.Run(); e != nil {
				return e
			}
			// Installer helper uses only the delivery API; no Python or build tools are needed at install time.
			cmd = exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-ldflags=-s -w", "-o", filepath.Join(root, "bin", "deliveryctl"), "./scripts/deliveryctl")
			cmd.Env = buildEnv(arch)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			if e := cmd.Run(); e != nil {
				return e
			}
			for _, name := range []string{"install.sh", "uninstall.sh", "LICENSE", "CHANGELOG.md", "README.md", "README.en.md"} {
				b, e := os.ReadFile(name)
				if e != nil {
					return e
				}
				if e = platform.AtomicWrite(filepath.Join(root, name), b, 0600); e != nil {
					return e
				}
			}
			// The delivery contract keeps its own name. It is not an installation
			// guide, and the bundle's README already documents how to install.
			for source, destination := range map[string]string{"scripts/DELIVERY.md": "DELIVERY.md", "scripts/ACCEPTANCE.md": "ACCEPTANCE.md"} {
				b, e := os.ReadFile(source)
				if e != nil {
					return e
				}
				if e = platform.AtomicWrite(filepath.Join(root, destination), b, 0600); e != nil {
					return e
				}
			}
			if e := platform.WriteJSON(filepath.Join(root, "BUILD.json"), provenance); e != nil {
				return e
			}
			if e := delivery.WriteManifest(root, delivery.Manifest{Version: delivery.Version, Kind: "basic", Arch: arch}); e != nil {
				return e
			}
			name := delivery.AssetName(delivery.Version, arch, "basic")
			p := filepath.Join(output, name)
			if e := delivery.Archive(root, p); e != nil {
				return e
			}
			outputs = append(outputs, p)
			if !*offline {
				return nil
			}
			if e := os.Remove(filepath.Join(root, "release-manifest.json")); e != nil {
				return e
			}
			plan, e := delivery.PlanCore(*core, arch, "")
			if e != nil {
				return e
			}
			input := filepath.Join(stage, plan.Asset)
			if *cache != "" {
				input = filepath.Join(*cache, plan.Asset)
				if _, se := os.Lstat(input); os.IsNotExist(se) {
					input = filepath.Join(*cache, "mihomo-linux-"+arch+".gz")
				}
			} else {
				// GitHub's release CDN intermittently answers a runner's GET
				// with a transient non-200 or an aborted transfer even though
				// the asset is healthy, which would fail a whole CI matrix
				// attempt. Retry only those transient conditions; every
				// attempt is a complete fresh transfer that must still match
				// the reviewed digest, so retrying cannot weaken the pin.
				transient := map[string]bool{"download-http-status": true, "download-unavailable": true, "download-incomplete": true}
				for attempt := 1; ; attempt++ {
					dctx, dcancel := context.WithTimeout(context.Background(), 3*time.Minute)
					e = (delivery.Downloader{}).Download(dctx, plan.URL, input, plan.SHA256)
					dcancel()
					if e == nil || !transient[e.Error()] {
						break
					}
					if attempt >= 5 {
						return e
					}
					fmt.Fprintf(os.Stderr, "release: core download attempt %d failed (%v); retrying\n", attempt, e)
					time.Sleep(time.Duration(attempt) * 15 * time.Second)
				}
				if e != nil {
					return e
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()
			if e = delivery.PrepareCoreFromFile(ctx, plan, arch, filepath.Join(root, "core", "mihomo"), input); e != nil {
				return e
			}
			compressed, e := os.ReadFile(input)
			if e != nil {
				return e
			}
			if platform.Hash(compressed) != plan.SHA256 {
				return fmt.Errorf("cached core changed during build")
			}
			if e = platform.AtomicWrite(filepath.Join(root, "core", plan.Asset), compressed, 0600); e != nil {
				return e
			}
			license, e := os.ReadFile("internal/delivery/mihomo-LICENSE.txt")
			if e != nil {
				return e
			}
			if e = platform.AtomicWrite(filepath.Join(root, "core", "LICENSE.txt"), license, 0600); e != nil {
				return e
			}
			if e = platform.WriteJSON(filepath.Join(root, "core", "provenance.json"), map[string]any{"plan": plan, "source": "https://github.com/MetaCubeX/mihomo", "note": "GPL-3.0 core redistributed separately from the MIT controller; review upstream corresponding source for the pinned tag; not an upstream signature"}); e != nil {
				return e
			}
			if *inputs != "" {
				if e = copyOptional(*inputs, root); e != nil {
					return e
				}
			}
			if e = delivery.WriteManifest(root, delivery.Manifest{Version: delivery.Version, Kind: "offline", Arch: arch, Core: &plan}); e != nil {
				return e
			}
			p = filepath.Join(output, delivery.AssetName(delivery.Version, arch, "offline"))
			if e = delivery.Archive(root, p); e != nil {
				return e
			}
			outputs = append(outputs, p)
			return nil
		}()
		if e != nil {
			return e
		}
	}
	// Git's tracked-file inventory excludes ignored worktree secrets and build outputs.
	source, e := os.MkdirTemp(output, ".source-*")
	if e != nil {
		return e
	}
	defer os.RemoveAll(source)
	cmd := exec.Command("git", "ls-files", "-z")
	listed, e := cmd.Output()
	if e != nil {
		return e
	}
	for _, n := range strings.Split(string(listed), "\x00") {
		if n == "" {
			continue
		}
		if strings.HasPrefix(n, "dist/") || strings.HasSuffix(n, ".exe") {
			continue
		}
		if e = platform.CheckPath(filepath.FromSlash(n)); e != nil {
			return e
		}
		b, e := os.ReadFile(filepath.FromSlash(n))
		if e != nil {
			return e
		}
		if e = platform.AtomicWrite(filepath.Join(source, filepath.FromSlash(n)), b, 0600); e != nil {
			return e
		}
	}
	// Delivery files may be untracked in a local candidate, so include their explicit owned inventory.
	for _, p := range []string{"internal", "scripts", ".github", "install.sh", "uninstall.sh", "CHANGELOG.md"} {
		if e = copyTree(p, filepath.Join(source, p)); e != nil {
			return e
		}
	}
	// The shared workspace may contain new Go packages awaiting its owner's
	// commit. Include Go sources explicitly so a local source candidate is complete.
	e = filepath.WalkDir(".", func(p string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.IsDir() {
			if p != "." && (strings.HasPrefix(d.Name(), ".") || (!strings.HasPrefix(p, "internal"+string(os.PathSeparator)) && !strings.HasPrefix(p, "scripts"+string(os.PathSeparator)) && p != "internal" && p != "scripts")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") && p != "go.mod" && p != "go.sum" && p != filepath.Join("internal", "command", "spec.json") {
			return nil
		}
		if e = platform.CheckPath(p); e != nil {
			return e
		}
		b, e := os.ReadFile(p)
		if e != nil {
			return e
		}
		return platform.AtomicWrite(filepath.Join(source, p), b, 0600)
	})
	if e != nil {
		return e
	}
	if e = platform.WriteJSON(filepath.Join(source, "BUILD.json"), provenance); e != nil {
		return e
	}
	p := filepath.Join(output, delivery.Project+"-"+delivery.Version+"-source.tar.gz")
	if e = delivery.Archive(source, p); e != nil {
		return e
	}
	outputs = append(outputs, p)
	sort.Strings(outputs)
	var sums strings.Builder
	for _, p := range outputs {
		b, e := os.ReadFile(p)
		if e != nil {
			return e
		}
		fmt.Fprintf(&sums, "%s  %s\n", platform.Hash(b), filepath.Base(p))
	}
	if e = platform.AtomicWrite(filepath.Join(output, "SHA256SUMS"), []byte(sums.String()), 0600); e != nil {
		return e
	}
	receipt := map[string]any{"format": 1, "project": delivery.Project, "version": delivery.Version, "entry": *entry, "builder_go": runtime.Version(), "offline": *offline, "architectures": archList, "publication": "candidate only; independent review required", "trust": "SHA256SUMS verifies consistency, not independent trust", "optional_inputs": *inputs}
	receipt["source_commit"] = provenance.Commit
	receipt["source_dirty"] = provenance.Dirty
	if e = platform.WriteJSON(filepath.Join(output, "build-receipt.json"), receipt); e != nil {
		return e
	}
	success = true
	return nil
}

type sourceProvenance struct {
	Commit string `json:"source_commit"`
	Dirty  bool   `json:"source_dirty"`
}

func readSourceProvenance(directory string) (sourceProvenance, error) {
	gitOutput := func(args ...string) ([]byte, error) {
		cmd := exec.Command("git", args...)
		cmd.Dir = directory
		return cmd.Output()
	}
	head, e := gitOutput("rev-parse", "--verify", "HEAD")
	if e != nil {
		return sourceProvenance{}, e
	}
	commit := strings.TrimSpace(string(head))
	if _, e = hex.DecodeString(commit); e != nil || len(commit) != 40 {
		return sourceProvenance{}, fmt.Errorf("full source commit unavailable")
	}
	status, e := gitOutput("status", "--porcelain", "--untracked-files=normal")
	if e != nil {
		return sourceProvenance{}, e
	}
	return sourceProvenance{Commit: commit, Dirty: len(status) != 0}, nil
}
func buildEnv(arch string) []string {
	var env []string
	for _, e := range os.Environ() {
		if strings.HasPrefix(e, "GOOS=") || strings.HasPrefix(e, "GOARCH=") || strings.HasPrefix(e, "CGO_ENABLED=") {
			continue
		}
		env = append(env, e)
	}
	return append(env, "GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0")
}
func copyTree(source, dest string) error {
	return filepath.WalkDir(source, func(p string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if e = platform.CheckPath(p); e != nil {
			return e
		}
		rel, e := filepath.Rel(source, p)
		if e != nil {
			return e
		}
		target := dest
		if rel != "." {
			target = filepath.Join(dest, rel)
		}
		if d.IsDir() {
			if d.Name() == ".validation" || d.Name() == "__pycache__" {
				return filepath.SkipDir
			}
			return os.MkdirAll(target, 0700)
		}
		if strings.HasSuffix(d.Name(), ".test") || strings.HasSuffix(d.Name(), ".exe") || strings.HasSuffix(d.Name(), ".pyc") {
			return nil
		}
		st, e := d.Info()
		if e != nil || !st.Mode().IsRegular() {
			return fmt.Errorf("nonregular input: %s", p)
		}
		if st.Size() > delivery.MaxDownload {
			return fmt.Errorf("input too large")
		}
		b, e := os.ReadFile(p)
		if e != nil {
			return e
		}
		return platform.AtomicWrite(target, b, 0600)
	})
}
func copyOptional(source, dest string) error {
	entries, e := os.ReadDir(source)
	if e != nil {
		return e
	}
	for _, d := range entries {
		if d.Name() != "dashboard" && d.Name() != "geodata" {
			return fmt.Errorf("unknown optional input %s", d.Name())
		}
		if !d.IsDir() {
			return fmt.Errorf("optional input must be directory")
		}
		if e = copyTree(filepath.Join(source, d.Name()), filepath.Join(dest, d.Name())); e != nil {
			return e
		}
	}
	return nil
}
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
