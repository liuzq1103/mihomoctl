package delivery

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

type bootstrapFile struct {
	Directory bool   `json:"directory"`
	Mode      uint32 `json:"mode"`
	Device    uint64 `json:"device"`
	Inode     uint64 `json:"inode"`
	SHA256    string `json:"sha256,omitempty"`
}

// Both publication sources are fully written and synced before this journal is
// synced. The launcher is published by exclusive hard link, preserving the
// journaled inode even across the link/journal crash window.
type bootstrapJournal struct {
	Format          int                      `json:"format"`
	Project         string                   `json:"project"`
	Token           string                   `json:"token"`
	Root            string                   `json:"root"`
	Stage           string                   `json:"stage"`
	LauncherDir     string                   `json:"launcher_dir"`
	Receipt         Receipt                  `json:"receipt"`
	Generation      string                   `json:"generation"`
	RootFile        bootstrapFile            `json:"root_identity"`
	Launcher        bootstrapFile            `json:"launcher_identity"`
	LauncherDirFile bootstrapFile            `json:"launcher_dir_identity"`
	Entries         map[string]bootstrapFile `json:"entries"`
}

type bootstrapHooks struct{ checkpoint func(string) error }

func bootstrapJournalPath(a platform.App) string {
	return filepath.Join(a.Scope.StateRoot, "delivery-bootstrap.json")
}

func bootstrapCheckpoint(h bootstrapHooks, phase string) error {
	if h.checkpoint != nil {
		return h.checkpoint(phase)
	}
	return nil
}

func captureBootstrapTree(root string) (map[string]bootstrapFile, error) {
	entries := map[string]bootstrapFile{}
	e := filepath.WalkDir(root, func(p string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if p == root {
			return nil
		}
		rel, e := filepath.Rel(root, p)
		if e != nil {
			return e
		}
		n := filepath.ToSlash(rel)
		if !safeName(n) || len(entries) >= MaxMembers {
			return fail("bootstrap-inventory-invalid")
		}
		entry, e := bootstrapIdentity(p)
		if e != nil {
			return e
		}
		entries[n] = entry
		return nil
	})
	return entries, e
}

func bootstrapManifestID(m Manifest) string {
	b, _ := json.MarshalIndent(m, "", "  ")
	return platform.Hash(append(b, '\n'))
}

func loadBootstrap(a platform.App) (bootstrapJournal, error) {
	var j bootstrapJournal
	b, e := platform.ReadPrivate(bootstrapJournalPath(a))
	if e != nil {
		return j, e
	}
	if e = StrictJSON(b, &j); e != nil {
		return j, e
	}
	if j.Format != 1 || j.Project != Project || j.Root != installRoot(a) ||
		!shaPattern.MatchString(j.Token) || j.Receipt.InstallationID != j.Token ||
		j.Stage != filepath.Join(a.Scope.DataRoot, ".install-bootstrap-"+j.Token) ||
		j.LauncherDir != filepath.Join(filepath.Dir(j.Receipt.BinPath), ".mihomoctl-bootstrap-"+j.Token) ||
		!generationPattern.MatchString(j.Generation) || len(j.Entries) == 0 || len(j.Entries) > MaxMembers {
		return j, fail("bootstrap-journal-invalid")
	}
	if e = removalReceipt(a, j.Receipt); e != nil {
		return j, e
	}
	valid := func(f bootstrapFile) bool {
		return f.Inode != 0 && f.Mode&0022 == 0 && f.Mode&^uint32(0777) == 0 &&
			((f.Directory && f.SHA256 == "") || (!f.Directory && shaPattern.MatchString(f.SHA256)))
	}
	if !valid(j.RootFile) || !j.RootFile.Directory || j.RootFile.Mode != 0700 ||
		!valid(j.LauncherDirFile) || !j.LauncherDirFile.Directory || j.LauncherDirFile.Mode != 0700 ||
		!valid(j.Launcher) || j.Launcher.Directory || j.Launcher.Mode != 0700 ||
		j.Launcher.SHA256 != j.Receipt.LauncherSHA256 {
		return j, fail("bootstrap-journal-identity-invalid")
	}
	for n, f := range j.Entries {
		if !safeName(n) || !valid(f) ||
			(n != "receipt.json" && n != "current" && n != "generations" && !strings.HasPrefix(n, "generations/")) {
			return j, fail("bootstrap-journal-inventory-invalid")
		}
	}
	rec, _ := json.MarshalIndent(j.Receipt, "", "  ")
	if j.Entries["receipt.json"].SHA256 != platform.Hash(append(rec, '\n')) ||
		j.Entries["current"].SHA256 != platform.Hash([]byte(j.Generation+"\n")) ||
		j.Entries["generations/"+j.Generation+"/release-manifest.json"].SHA256 != j.Generation {
		return j, fail("bootstrap-journal-inventory-invalid")
	}
	return j, nil
}

func verifyBootstrapFile(p string, want bootstrapFile) error {
	got, e := bootstrapIdentity(p)
	if e != nil {
		return e
	}
	if got != want {
		return fail("bootstrap-owned-identity-changed")
	}
	return nil
}

func verifyBootstrapTree(root string, j bootstrapJournal) error {
	if e := verifyBootstrapFile(root, j.RootFile); e != nil {
		return e
	}
	got, e := captureBootstrapTree(root)
	if e != nil {
		return e
	}
	if len(got) != len(j.Entries) {
		return fail("bootstrap-inventory-drift")
	}
	for n, want := range j.Entries {
		if got[n] != want {
			return fail("bootstrap-inventory-drift")
		}
	}
	_, _, e = generation(root, j.Generation)
	return e
}

// Recovery rolls forward only the exact staged installation. It never deletes
// or overwrites a public launcher, even one with identical expected bytes.
func recoverBootstrap(a platform.App) error {
	return recoverBootstrapWithHooks(a, bootstrapHooks{})
}

func recoverBootstrapWithHooks(a platform.App, h bootstrapHooks) error {
	exists, e := optionalExists(bootstrapJournalPath(a))
	if e != nil || !exists {
		return e
	}
	j, e := loadBootstrap(a)
	if e != nil {
		return e
	}
	stage, e := optionalExists(j.Stage)
	if e != nil {
		return e
	}
	root, e := optionalExists(j.Root)
	if e != nil {
		return e
	}
	if !stage && !root {
		// The recorded publication is gone: no staged tree remains and the
		// install root was removed. Nothing can be rolled forward, so undo the
		// remnants this journal owns instead of refusing every later command.
		return abandonBootstrap(a, j)
	}
	if stage && root {
		// The staged tree was never renamed away and an install root exists:
		// the recorded publication cannot be identified.
		return fail("bootstrap-root-identity-conflict")
	}
	tree := j.Stage
	if root {
		tree = j.Root
	}
	if e = verifyBootstrapTree(tree, j); e != nil {
		return e
	}

	bin, e := optionalExists(j.Receipt.BinPath)
	if e != nil {
		return e
	}
	if bin {
		if e = verifyBootstrapFile(j.Receipt.BinPath, j.Launcher); e != nil {
			return e
		}
	}
	ld, e := optionalExists(j.LauncherDir)
	if e != nil {
		return e
	}
	lf := filepath.Join(j.LauncherDir, "launcher")
	stagedLauncher := false
	if ld {
		if e = verifyBootstrapFile(j.LauncherDir, j.LauncherDirFile); e != nil {
			return e
		}
		children, e := os.ReadDir(j.LauncherDir)
		if e != nil {
			return e
		}
		for _, child := range children {
			if child.Name() != "launcher" {
				return fail("bootstrap-launcher-stage-drift")
			}
			if e = verifyBootstrapFile(lf, j.Launcher); e != nil {
				return e
			}
			stagedLauncher = true
		}
	}
	if !bin && !stagedLauncher {
		// The staged launcher is gone and the public launcher was never
		// published. The receipt binds the exact launcher object, and that
		// object was released together with the staging directory: a
		// replacement carrying identical bytes is a different object, so
		// publishing it would break the binding the receipt records. This
		// publication can therefore never be rolled forward. The remnants this
		// journal owns are undone instead, so the scope stays usable instead of
		// retaining a half-installed program that no command can roll back or
		// clear.
		if e = abandonBootstrap(a, j); e != nil {
			return e
		}
		return platform.FailDetail("bootstrap-launcher-source-missing",
			"the staged launcher was removed before it could be published; the incomplete installation was rolled back and the installation has to be run again")
	}
	if !root {
		if e = publishBootstrapRoot(j.Stage, j.Root); e != nil {
			if code, ok := publishRollback(e); ok {
				// This kernel or filesystem cannot publish the root atomically.
				// Nothing was published, so the staged tree and the journal are
				// rolled back rather than wedging every later command.
				if re := abandonBootstrap(a, j); re != nil {
					return re
				}
				return fail(code)
			}
			return e
		}
		if e = syncDir(a.Scope.DataRoot); e != nil {
			return e
		}
	}
	if e = bootstrapCheckpoint(h, "root-published"); e != nil {
		return e
	}
	if !bin {
		if e = verifyBootstrapTree(j.Root, j); e != nil {
			return e
		}
		if e = verifyBootstrapFile(j.LauncherDir, j.LauncherDirFile); e != nil {
			return e
		}
		if e = verifyBootstrapFile(lf, j.Launcher); e != nil {
			return e
		}
		// Link is atomic and never replaces an existing destination.
		if e = os.Link(lf, j.Receipt.BinPath); e != nil {
			return e
		}
		if e = syncDir(filepath.Dir(j.Receipt.BinPath)); e != nil {
			return e
		}
	}
	if e = bootstrapCheckpoint(h, "launcher-published"); e != nil {
		return e
	}
	// Validate again before cleanup. No mutation of public paths occurs here.
	if e = verifyBootstrapTree(j.Root, j); e != nil {
		return e
	}
	if e = verifyBootstrapFile(j.Receipt.BinPath, j.Launcher); e != nil {
		return e
	}
	if stagedLauncher {
		if e = verifyBootstrapFile(lf, j.Launcher); e != nil {
			return e
		}
		if e = os.Remove(lf); e != nil {
			return e
		}
		if e = syncDir(j.LauncherDir); e != nil {
			return e
		}
	}
	if e = bootstrapCheckpoint(h, "launcher-stage-unlinked"); e != nil {
		return e
	}
	if ld {
		if e = verifyBootstrapFile(j.LauncherDir, j.LauncherDirFile); e != nil {
			return e
		}
		if e = os.Remove(j.LauncherDir); e != nil {
			return e
		}
		if e = syncDir(filepath.Dir(j.LauncherDir)); e != nil {
			return e
		}
	}
	if e = bootstrapCheckpoint(h, "staging-cleaned"); e != nil {
		return e
	}
	if e = os.Remove(bootstrapJournalPath(a)); e != nil {
		return e
	}
	if e = syncDir(a.Scope.StateRoot); e != nil {
		return e
	}
	return bootstrapCheckpoint(h, "journal-removed")
}

// abandonBootstrap rolls back a publication that can no longer complete. It
// removes only objects the journal proves are ours, never a foreign file, and
// it discards our own journal so the scope stays usable instead of refusing
// every later command.
func abandonBootstrap(a platform.App, j bootstrapJournal) error {
	var e error
	if exists, e := optionalExists(j.Root); e != nil {
		return e
	} else if exists {
		// A published root is ours while its identity still matches the
		// journal. It is removed only when it matches, so a foreign directory
		// standing at the path is never touched.
		if e = verifyBootstrapFile(j.Root, j.RootFile); e != nil {
			return e
		}
		if e = os.RemoveAll(j.Root); e != nil {
			return e
		}
		if e = syncDir(a.Scope.DataRoot); e != nil {
			return e
		}
	}
	if exists, e := optionalExists(j.Stage); e != nil {
		return e
	} else if exists {
		if e = verifyBootstrapFile(j.Stage, j.RootFile); e != nil {
			return e
		}
		if e = os.RemoveAll(j.Stage); e != nil {
			return e
		}
		if e = syncDir(filepath.Dir(j.Stage)); e != nil {
			return e
		}
	}
	if exists, e := optionalExists(j.LauncherDir); e != nil {
		return e
	} else if exists {
		if e = verifyBootstrapFile(j.LauncherDir, j.LauncherDirFile); e != nil {
			return e
		}
		children, e := os.ReadDir(j.LauncherDir)
		if e != nil {
			return e
		}
		for _, child := range children {
			if child.Name() != "launcher" {
				return fail("bootstrap-launcher-stage-drift")
			}
			if e = verifyBootstrapFile(filepath.Join(j.LauncherDir, "launcher"), j.Launcher); e != nil {
				return e
			}
		}
		if e = os.RemoveAll(j.LauncherDir); e != nil {
			return e
		}
		if e = syncDir(filepath.Dir(j.LauncherDir)); e != nil {
			return e
		}
	}
	if exists, e := optionalExists(j.Receipt.BinPath); e != nil {
		return e
	} else if exists {
		// A published launcher points at an install root that no longer exists.
		// It stays ours only while its identity still matches the journal.
		if e = verifyBootstrapFile(j.Receipt.BinPath, j.Launcher); e != nil {
			return e
		}
		if e = os.Remove(j.Receipt.BinPath); e != nil {
			return e
		}
		if e = syncDir(filepath.Dir(j.Receipt.BinPath)); e != nil {
			return e
		}
	}
	if e = os.Remove(bootstrapJournalPath(a)); e != nil {
		return e
	}
	return syncDir(a.Scope.StateRoot)
}

func bootstrap(ctx context.Context, a platform.App, source, binDir string, dry bool, h bootstrapHooks) (map[string]any, error) {
	m, e := LoadManifest(source)
	if e != nil {
		return nil, e
	}
	if e = VerifyTree(source, m); e != nil {
		return nil, e
	}
	if e = native(m); e != nil {
		return nil, e
	}
	if !filepath.IsAbs(binDir) || filepath.Clean(binDir) != binDir || strings.ContainsAny(binDir, "\n\r\x00") {
		return nil, usage("installation-bin-dir-invalid")
	}
	root, bin := installRoot(a), filepath.Join(binDir, "mihomoctl")
	if within(root, bin) || within(bin, root) {
		return nil, usage("installation-bin-dir-invalid")
	}
	data := map[string]any{"version": m.Version, "bin_path": bin, "dry_run": dry, "active_core_preserved": true}
	preflight := func() (bool, error) {
		rootExists, e := optionalExists(root)
		if e != nil {
			return false, e
		}
		if rootExists {
			rec, e := readReceipt(a)
			if e != nil {
				return false, e
			}
			id, e := readCurrent(root)
			if e != nil {
				return false, e
			}
			if rec.BinPath != bin || rec.InstallationID == "" || id != bootstrapManifestID(m) {
				return false, fail("installation-root-exists")
			}
			if _, e = collectRemoval(a); e != nil {
				return false, e
			}
			return true, nil
		}
		if exists, e := optionalExists(bin); e != nil {
			return false, e
		} else if exists {
			return false, fail("installation-command-exists")
		}
		return false, nil
	}
	if dry {
		if e = platform.CheckPending(a.Scope); e != nil {
			return nil, e
		}
		installed, e := preflight()
		if e == nil {
			data["already_installed"], data["changed"] = installed, false
		}
		return data, e
	}
	e = platform.WithLock(ctx, a.Scope, func() error {
		installed, e := preflight()
		if e != nil {
			return e
		}
		if installed {
			data["already_installed"], data["changed"] = true, false
			return nil
		}
		j, e := prepareBootstrap(a, source, bin, m)
		if e != nil {
			return e
		}
		if e = bootstrapCheckpoint(h, "staged"); e != nil {
			return e
		}
		// Durable write-ahead authority precedes BOTH root rename and launcher link.
		if e = platform.WriteJSON(bootstrapJournalPath(a), j); e != nil {
			return e
		}
		if e = syncDir(a.Scope.StateRoot); e != nil {
			return e
		}
		if e = bootstrapCheckpoint(h, "journal-published"); e != nil {
			return e
		}
		if e = recoverBootstrapWithHooks(a, h); e != nil {
			return e
		}
		data["changed"] = true
		if m.Core != nil {
			data["core"] = map[string]any{"binary": filepath.Join(root, "generations", j.Generation, "core", "mihomo"), "version": m.Core.Version, "activated": false, "provenance": m.Core.Provenance,
				"program_owned": true, "uninstall_policy": "Install and adopt an independent core with core install --asset before uninstalling this program."}
		}
		return nil
	})
	return data, e
}

func prepareBootstrap(a platform.App, source, bin string, m Manifest) (bootstrapJournal, error) {
	j := bootstrapJournal{Format: 1, Project: Project, Root: installRoot(a)}
	var e error
	j.Token, e = platform.Token()
	if e != nil {
		return j, e
	}
	j.Stage = filepath.Join(a.Scope.DataRoot, ".install-bootstrap-"+j.Token)
	j.LauncherDir = filepath.Join(filepath.Dir(bin), ".mihomoctl-bootstrap-"+j.Token)
	if e = platform.PrivateDir(a.Scope.DataRoot); e != nil {
		return j, e
	}
	if e = os.Mkdir(j.Stage, 0700); e != nil {
		return j, e
	}
	// Before journal publication, interruption may leave private random staging
	// directories. They cannot block a retry and are never guessed or deleted.
	j.Generation, e = stageGeneration(j.Stage, source, m)
	if e != nil {
		return j, e
	}
	j.Receipt = Receipt{Format: 1, Project: Project, BinPath: bin, LauncherSHA256: platform.Hash(launcher(j.Root)), InstallationID: j.Token}
	if e = platform.AtomicWrite(filepath.Join(j.Stage, "current"), []byte(j.Generation+"\n"), 0600); e != nil {
		return j, e
	}
	if e = platform.CheckPath(filepath.Dir(bin)); e != nil {
		return j, e
	}
	if e = os.MkdirAll(filepath.Dir(bin), 0755); e != nil {
		return j, e
	}
	if e = os.Mkdir(j.LauncherDir, 0700); e != nil {
		return j, e
	}
	if e = platform.AtomicWrite(filepath.Join(j.LauncherDir, "launcher"), launcher(j.Root), 0700); e != nil {
		return j, e
	}
	if j.RootFile, e = bootstrapIdentity(j.Stage); e != nil {
		return j, e
	}
	if j.LauncherDirFile, e = bootstrapIdentity(j.LauncherDir); e != nil {
		return j, e
	}
	if j.Launcher, e = bootstrapIdentity(filepath.Join(j.LauncherDir, "launcher")); e != nil {
		return j, e
	}
	// The launcher is staged before the receipt so the receipt can bind its
	// object: the published launcher is a hard link of this file, so the
	// recorded device and inode identify exactly the object a later
	// uninstall may delete. A replacement carrying identical bytes is a
	// different object and is never adopted.
	j.Receipt.LauncherDevice = j.Launcher.Device
	j.Receipt.LauncherInode = j.Launcher.Inode
	if e = platform.WriteJSON(filepath.Join(j.Stage, "receipt.json"), j.Receipt); e != nil {
		return j, e
	}
	if j.Entries, e = captureBootstrapTree(j.Stage); e != nil {
		return j, e
	}
	b, e := json.MarshalIndent(j, "", "  ")
	if e != nil {
		return j, e
	}
	if len(b) > 2<<20 {
		return j, fail("bootstrap-inventory-too-large")
	}
	// Persist all directory entries, from children to parents, before the WAL.
	dirs := []string{}
	for n, f := range j.Entries {
		if f.Directory {
			dirs = append(dirs, filepath.Join(j.Stage, filepath.FromSlash(n)))
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(dirs)))
	dirs = append(dirs, j.Stage, a.Scope.DataRoot, j.LauncherDir, filepath.Dir(bin))
	for _, p := range dirs {
		if e = syncDir(p); e != nil {
			return j, e
		}
	}
	return j, nil
}
