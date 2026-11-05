package delivery

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

func Handles(command []string) bool {
	if len(command) == 1 {
		return command[0] == "version" || command[0] == "update"
	}
	if len(command) != 2 {
		return false
	}
	n := strings.Join(command, "-")
	switch n {
	case "release-check", "release-fetch", "core-install", "core-update", "installation-install", "installation-status", "installation-uninstall", "installation-recover":
		return true
	}
	return false
}

func Run(ctx context.Context, a platform.App, r platform.Request) (platform.Envelope, error) {
	// Compatibility with the stable public grammar inherited by the CLI agent.
	if r.Has("allow-same-version") && !r.Has("reinstall") {
		opts := map[string][]string{}
		for k, v := range r.Options {
			opts[k] = v
		}
		opts["reinstall"] = []string{"true"}
		r.Options = opts
	}
	doc := platform.Document(r.Name(), a.Scope.Name, nil)
	var data map[string]any
	var e error
	if !Handles(r.Command) {
		e = usage("unknown-command")
	} else {
		switch r.Name() {
		case "version":
			data = map[string]any{"version": Version, "mihomoctl": Version, "schema": platform.Schema, "core": nil, "project": Project, "repository": Repository, "command": "mihomoctl"}
			data["core"] = configuredCoreVersion(ctx, a)
		case "core-install", "core-update":
			data, e = coreInstall(ctx, a, r)
		case "update":
			data, e = update(ctx, a, r)
		case "installation-install":
			bin := r.Get("bin-dir")
			if bin == "" {
				if a.Scope.System {
					bin = "/usr/local/bin"
				} else {
					var h string
					h, e = os.UserHomeDir()
					if e == nil {
						bin = filepath.Join(h, ".local", "bin")
					}
				}
			}
			if e == nil {
				data, e = Bootstrap(ctx, a, r.Get("source"), bin, r.Has("dry-run"))
			}
		case "installation-status":
			data, e = installationStatus(a)
		case "installation-recover":
			e = platform.WithLock(ctx, a.Scope, func() error { return recoverInstall(a) })
			if e == nil {
				data, e = installationStatus(a)
			}
		case "installation-uninstall":
			data, e = Uninstall(ctx, a, r.Has("dry-run"))
		case "release-check", "release-fetch":
			var meta Release
			meta, e = (Downloader{}).Metadata(ctx, r.Get("version"))
			if e == nil {
				v := strings.TrimPrefix(meta.Tag, "v")
				var cmp int
				cmp, e = CompareVersions(v, Version)
				data = map[string]any{"current_version": Version, "observed_version": v, "newer_available": cmp > 0, "checked_at": time.Now().Unix(), "release_url": "https://github.com/" + Repository + "/releases/tag/" + meta.Tag, "trust": "metadata observation, not a signature or independent asset review"}
				if e == nil && r.Name() == "release-fetch" {
					dest := r.Get("output-dir")
					if dest == "" {
						e = usage("release-output-dir-required")
					} else {
						var p string
						p, e = (Downloader{}).FetchTarget(ctx, meta, dest, r.Get("sha256"), r.Get("kind"), r.Get("target"))
						if e == nil {
							data["path"] = p
							data["source"] = p
							data["output_dir"] = dest
							data["version"] = v
							data["target"] = r.Get("target")
							data["wheelhouse"] = nil
							data["sha256"] = r.Get("sha256")
							data["trust"] = "caller-provided SHA-256; no upstream signature"
						}
					}
				}
			}
		}
	}
	if e != nil {
		return platform.Failure(r.Name(), a.Scope.Name, e), e
	}
	doc.Data = data
	return doc, nil
}
