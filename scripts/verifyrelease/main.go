// verifyrelease validates a caller-reviewed release bundle and can explicitly
// execute its native CLI and core. Never use --execute on unreviewed inputs.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/liuzq1103/mihomoctl/internal/delivery"
	"github.com/liuzq1103/mihomoctl/internal/platform"
)

func run() error {
	archive := flag.String("archive", "", "reviewed basic/offline tar.gz")
	expected := flag.String("sha256", "", "independently reviewed outer archive SHA-256 (required)")
	execute := flag.Bool("execute", false, "execute the explicitly reviewed native CLI/core")
	flag.Parse()
	if len(*expected) != 64 {
		return fmt.Errorf("independently reviewed --sha256 required")
	}
	if e := platform.CheckPath(*archive); e != nil {
		return e
	}
	b, e := os.ReadFile(*archive)
	if e != nil {
		return e
	}
	if platform.Hash(b) != *expected {
		return fmt.Errorf("outer digest mismatch")
	}
	dir, e := os.MkdirTemp("", "mihomoctl-go-verify-*")
	if e != nil {
		return e
	}
	defer os.RemoveAll(dir)
	f, e := os.Open(*archive)
	if e != nil {
		return e
	}
	e = delivery.ExtractTarGzip(f, dir)
	f.Close()
	if e != nil {
		return e
	}
	m, e := delivery.LoadManifest(dir)
	if e != nil {
		return e
	}
	if e = delivery.VerifyTree(dir, m); e != nil {
		return e
	}
	if *execute {
		if runtime.GOOS != m.OS || runtime.GOARCH != m.Arch {
			return fmt.Errorf("native execution unavailable for %s/%s", m.OS, m.Arch)
		}
		for _, p := range []string{"bin/mihomoctl", "core/mihomo"} {
			if _, ok := m.Files[p]; !ok {
				continue
			}
			if e = os.Chmod(filepath.Join(dir, p), 0700); e != nil {
				return e
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, filepath.Join(dir, "bin", "mihomoctl"), "version", "--json")
		out, e := cmd.Output()
		if e != nil {
			return fmt.Errorf("product CLI version smoke failed: %w", e)
		}
		var env platform.Envelope
		if e = json.Unmarshal(out, &env); e != nil {
			return e
		}
		if env.Schema != platform.Schema || env.Overall != "PASS" || env.Data["version"] != m.Version || env.Data["mihomoctl"] != m.Version {
			return fmt.Errorf("CLI identity mismatch")
		}
		if m.Core != nil {
			cmd = exec.CommandContext(ctx, filepath.Join(dir, "core", "mihomo"), "-v")
			out, e = cmd.Output()
			if e != nil {
				return fmt.Errorf("core version smoke failed: %w", e)
			}
			if !strings.HasPrefix(string(out), "Mihomo Meta "+m.Core.Version+" ") && !strings.HasPrefix(string(out), "Mihomo Meta "+strings.TrimPrefix(m.Core.Version, "v")+" ") {
				return fmt.Errorf("core version mismatch")
			}
		}
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"archive": *archive, "version": m.Version, "arch": m.Arch, "kind": m.Kind, "inventory_verified": true, "native_execution": *execute, "signature_verified": false, "trust": "caller-reviewed outer SHA-256"})
}
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
