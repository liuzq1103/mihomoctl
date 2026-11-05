package runtimecore

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

// Compound records live in persistent state, never /run. The original files,
// runtime intent, executable digests, and every child launch intent are durable
// before stopping, publishing, reloading, or launching anything.
type compoundFile struct {
	Path     string
	Before   []byte
	Existed  bool
	Versions [][]byte
}
type launchIntent struct {
	Token  string
	Binary string
	Config string
	UID    int
	Boot   string
}
type compoundRecord struct {
	Version    int
	Namespace  string
	Scope      platform.Scope
	Operation  string
	Phase      string
	Before     manager
	Next       manager
	Original   *identity
	Reload     bool
	BinaryHash map[string]string
	Files      []compoundFile
	Launches   []launchIntent
}

func compoundPath(a platform.App) string { return filepath.Join(a.Scope.StateRoot, "compound.json") }
func samePersistentScope(a, b platform.Scope) bool {
	a.RuntimeRoot = ""
	b.RuntimeRoot = ""
	return a == b
}

// Tests install a crash checkpoint in a separate helper process. No environment
// variable or public command can enable fault injection in the application.
var compoundCheckpoint = func(string) {}

func durableRemove(p string) error {
	if e := platform.CheckPath(p); e != nil {
		return e
	}
	if e := os.Remove(p); e != nil && !os.IsNotExist(e) {
		return e
	}
	return syncDirectory(filepath.Dir(p))
}
func writeCompound(a platform.App, c *compoundRecord) error {
	if len(c.Files) > 1024 || len(c.Launches) > 32 {
		return platform.Usage("compound-record-limit")
	}
	for _, f := range c.Files {
		if len(f.Versions) > 32 {
			return platform.Usage("compound-record-limit")
		}
	}
	b, e := json.Marshal(c)
	if e != nil {
		return e
	}
	if int64(len(b)) > compoundJournalLimit {
		return platform.Usage("compound-journal-too-large")
	}
	if e = platform.AtomicWrite(compoundPath(a), append(b, '\n'), 0600); e != nil {
		return e
	}
	return syncDirectory(a.Scope.StateRoot)
}
func loadCompound(a platform.App) (*compoundRecord, error) {
	p := compoundPath(a)
	if e := platform.CheckPath(p); e != nil {
		return nil, e
	}
	if _, e := os.Lstat(p); os.IsNotExist(e) {
		return nil, nil
	}
	raw, e := readPrivateBounded(p, compoundJournalLimit)
	if e != nil {
		return nil, e
	}
	var c compoundRecord
	if json.Unmarshal(raw, &c) != nil || c.Version != 1 || c.Namespace != "mihomoctl-go" || !samePersistentScope(c.Scope, a.Scope) || !member(c.Operation, "core-adopt", "reset", "tun-enable", "tun-disable", "configuration-start") || !member(c.Phase, "prepared", "stopped", "files-published", "activated", "restoring", "restoring-runtime", "committed") || len(c.Files) == 0 || len(c.Files) > 1024 || len(c.Launches) > 32 {
		return nil, platform.Usage("compound-journal-invalid")
	}
	if validateManager(a, c.Before) != nil || validateManager(a, c.Next) != nil {
		return nil, platform.Usage("compound-journal-invalid")
	}
	if member(c.Operation, "tun-enable", "tun-disable") && (!a.Scope.System || c.Before.Core.Backend != "systemd" || c.Next.Core.Backend != "systemd" || c.Original == nil || c.Before.Tun.Enabled == c.Next.Tun.Enabled || (c.Operation == "tun-enable") != c.Next.Tun.Enabled) {
		return nil, platform.Usage("compound-journal-invalid")
	}
	seen := map[string]bool{}
	for _, f := range c.Files {
		if !transactionPath(a, f.Path) || f.Path == a.Scope.RuntimeState() || seen[f.Path] || len(f.Versions) > 32 {
			return nil, platform.Usage("compound-journal-invalid")
		}
		seen[f.Path] = true
	}
	if !seen[a.Scope.ManagerPath()] {
		return nil, platform.Usage("compound-journal-invalid")
	}
	for _, m := range []manager{c.Before, c.Next} {
		if !digestPattern.MatchString(c.BinaryHash[m.Core.Binary]) {
			return nil, platform.Usage("compound-journal-invalid")
		}
	}
	for _, l := range c.Launches {
		if len(l.Token) != 64 || !secretPattern.MatchString(l.Token) || l.Boot == "" || !allowedCompoundProcess(a, &c, identity{UID: l.UID, Exe: l.Binary, Args: []string{l.Binary, "-d", a.Scope.CoreHome(), "-f", l.Config}}) {
			return nil, platform.Usage("compound-journal-invalid")
		}
	}
	if c.Original != nil && (c.Original.PID < 2 || c.Original.Start == "" || c.Original.Boot == "" || !allowedCompoundProcess(a, &c, *c.Original)) {
		return nil, platform.Usage("compound-journal-invalid")
	}
	return &c, nil
}
func allowedCompoundProcess(a platform.App, c *compoundRecord, id identity) bool {
	for _, m := range []manager{c.Before, c.Next} {
		home, config := a.Scope.CoreHome(), m.Core.Config
		uid := os.Geteuid()
		if m.Core.Backend == "systemd" && a.Scope.System {
			home, config = serviceHome(a), serviceConfig(a, m)
			// Decoding a durable record must work even if the service account is
			// temporarily unavailable after boot. Kernel effects verify its exact
			// current UID in stopCompoundService/serviceIdentity before acting.
			if id.UID <= 0 {
				return false
			}
			uid = id.UID
		}
		if id.UID == uid && id.Exe == m.Core.Binary && equalStrings(id.Args, []string{m.Core.Binary, "-d", home, "-f", config}) {
			return true
		}
	}
	return false
}
func snapshotCompoundFile(a platform.App, p string, after []byte) (compoundFile, error) {
	f := compoundFile{Path: p, Versions: [][]byte{after}}
	if !transactionPath(a, p) || p == a.Scope.RuntimeState() {
		return f, platform.Usage("compound-path-unsafe")
	}
	if e := platform.CheckPath(p); e != nil {
		return f, e
	}
	if _, e := os.Lstat(p); e == nil {
		var e error
		f.Before, e = readManagedFile(a, p)
		if e != nil {
			return f, e
		}
		f.Existed = true
	} else if !os.IsNotExist(e) {
		return f, e
	}
	return f, nil
}
func currentCompoundFile(a platform.App, f compoundFile) error {
	if e := platform.CheckPath(f.Path); e != nil {
		return e
	}
	if _, e := os.Lstat(f.Path); os.IsNotExist(e) {
		if !f.Existed {
			return nil
		}
		for _, v := range f.Versions {
			if v == nil {
				return nil
			}
		}
		return platform.Usage("compound-file-conflict")
	} else if e != nil {
		return e
	}
	raw, e := readManagedFile(a, f.Path)
	if e != nil {
		return e
	}
	if f.Existed && bytesEqual(raw, f.Before) {
		return nil
	}
	for _, v := range f.Versions {
		if v != nil && bytesEqual(raw, v) {
			return nil
		}
	}
	return platform.Usage("compound-file-conflict")
}
func trackCompoundWrites(a platform.App, files map[string][]byte) error {
	c, e := loadCompound(a)
	if e != nil || c == nil {
		return e
	}
	if c.Phase == "committed" {
		return platform.Usage("compound-already-committed")
	}
	for _, path := range sortedKeys(files) {
		found := false
		for i := range c.Files {
			f := &c.Files[i]
			if f.Path != path {
				continue
			}
			found = true
			if e = currentCompoundFile(a, *f); e != nil {
				return e
			}
			known := false
			for _, v := range f.Versions {
				if (v == nil) == (files[path] == nil) && bytesEqual(v, files[path]) {
					known = true
				}
			}
			if !known {
				// applyFiles refuses a pending file journal. Older publications
				// are therefore durably complete; keep only the current and next
				// variants so repeated recovery cannot exhaust the history bound.
				var current []byte
				if _, e := os.Lstat(path); e == nil {
					current, e = readManagedFile(a, path)
					if e != nil {
						return e
					}
				} else if !os.IsNotExist(e) {
					return e
				}
				f.Versions = [][]byte{current, files[path]}
			}
			break
		}
		if !found {
			f, e := snapshotCompoundFile(a, path, files[path])
			if e != nil {
				return e
			}
			c.Files = append(c.Files, f)
		}
	}
	return writeCompound(a, c)
}
func compoundPhase(a platform.App, phase string) error {
	c, e := loadCompound(a)
	if e != nil {
		return e
	}
	if c == nil {
		return platform.Usage("compound-journal-missing")
	}
	c.Phase = phase
	if e = writeCompound(a, c); e != nil {
		return e
	}
	compoundCheckpoint(phase)
	return nil
}
func recordLaunch(a platform.App, m manager) (string, error) {
	c, e := loadCompound(a)
	if e != nil || c == nil {
		return "", e
	}
	self, e := inspectIdentity(os.Getpid())
	if e != nil {
		return "", e
	}
	if len(c.Launches) >= 32 {
		live, e := findCompoundLaunches(a, c)
		if e != nil {
			return "", e
		}
		if len(live) != 0 {
			return "", platform.Usage("compound-launch-limit")
		}
		c.Launches = nil
	}
	token, e := platform.Token()
	if e != nil {
		return "", e
	}
	intent := launchIntent{token, m.Core.Binary, m.Core.Config, os.Geteuid(), self.Boot}
	c.Launches = append(c.Launches, intent)
	if e = writeCompound(a, c); e != nil {
		return "", e
	}
	compoundCheckpoint("launch-recorded")
	return token, nil
}
func pendingRecovery(a platform.App) error {
	for _, p := range []string{journalPath(a), compoundPath(a)} {
		if e := platform.CheckPath(p); e != nil {
			return e
		}
		if _, e := os.Lstat(p); e == nil {
			return platform.Usage("transaction-recovery-required")
		} else if !os.IsNotExist(e) {
			return e
		}
	}
	return nil
}

func applyCompound(ctx context.Context, a platform.App, operation string, before, next manager, files map[string][]byte, original *identity, activate func(context.Context) error) error {
	if c, e := loadCompound(a); e != nil {
		return e
	} else if c != nil {
		return platform.Usage("compound-operation-pending")
	}
	c := &compoundRecord{Version: 1, Namespace: "mihomoctl-go", Scope: a.Scope, Operation: operation, Phase: "prepared", Before: before, Next: next, Original: original, BinaryHash: map[string]string{}}
	for _, m := range []manager{before, next} {
		if _, exists := c.BinaryHash[m.Core.Binary]; exists {
			continue
		}
		if e := trustedExecutable(m.Core.Binary, a.Scope.System); e != nil {
			return e
		}
		hash, _, e := hashResource(ctx, a, m.Core.Binary, "executable")
		if e != nil {
			return e
		}
		c.BinaryHash[m.Core.Binary] = hash
	}
	for _, path := range sortedKeys(files) {
		f, e := snapshotCompoundFile(a, path, files[path])
		if e != nil {
			return e
		}
		c.Files = append(c.Files, f)
		if !a.Scope.Contains(path) {
			c.Reload = true
		}
	}
	// Preserve the runtime's inputs even when this operation only repoints the
	// executable. Later retries can extend these snapshots before writing.
	extra := []string{before.Core.Config, generatedPath(a)}
	for _, p := range before.Profiles {
		if p.Credentials != "" {
			extra = append(extra, p.Credentials)
		}
	}
	for _, path := range extra {
		found := false
		for _, f := range c.Files {
			if f.Path == path {
				found = true
			}
		}
		if found {
			continue
		}
		var current []byte
		if _, e := os.Lstat(path); e == nil {
			var e error
			current, e = readManagedFile(a, path)
			if e != nil {
				return e
			}
		} else if !os.IsNotExist(e) {
			return e
		}
		f, e := snapshotCompoundFile(a, path, current)
		if e != nil {
			return e
		}
		c.Files = append(c.Files, f)
	}
	c.Reload = c.Reload || before.Core.Backend == "systemd" || next.Core.Backend == "systemd"
	if e := writeCompound(a, c); e != nil {
		return e
	}
	compoundCheckpoint("prepared")
	work := func() error {
		if original != nil {
			if e := lifecycle(ctx, a, "stop"); e != nil {
				return e
			}
		}
		if e := ensureCompoundTunAbsent(ctx, a, c); e != nil {
			return e
		}
		if e := compoundPhase(a, "stopped"); e != nil {
			return e
		}
		if e := applyFiles(a, files); e != nil {
			return e
		}
		if e := compoundPhase(a, "files-published"); e != nil {
			return e
		}
		if c.Reload {
			if _, e := systemctl(ctx, a, "daemon-reload"); e != nil {
				return e
			}
		}
		if activate != nil {
			if e := activate(ctx); e != nil {
				return e
			}
		}
		if e := compoundPhase(a, "activated"); e != nil {
			return e
		}
		if e := compoundPhase(a, "committed"); e != nil {
			return e
		}
		return durableRemove(compoundPath(a))
	}
	if e := work(); e != nil {
		recoveryCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 120*time.Second)
		defer cancel()
		if re := recoverCompound(recoveryCtx, a); re != nil {
			return platform.Fail("rollback-failed")
		}
		return e
	}
	return nil
}
func ensureCompoundTunAbsent(ctx context.Context, a platform.App, c *compoundRecord) error {
	seen := map[string]bool{}
	for _, m := range []manager{c.Before, c.Next} {
		if !m.Tun.Enabled || seen[tunDevice(m)] {
			continue
		}
		seen[tunDevice(m)] = true
		observed, e := deviceState(ctx, tunDevice(m))
		if e != nil {
			return e
		}
		if observed != nil {
			return platform.Fail("tun-disable-unverified")
		}
	}
	return nil
}

type compoundRecoveryEffects struct {
	Stop      func(context.Context, platform.App, *compoundRecord) error
	TunAbsent func(context.Context, platform.App, *compoundRecord) error
	Prepare   func(context.Context, platform.App, manager) error
	Reload    func(context.Context, platform.App) error
	Start     func(context.Context, platform.App) error
	SealTun   func(context.Context, platform.App, manager) error
}

func recoverCompound(ctx context.Context, a platform.App) error {
	return recoverCompoundWith(ctx, a, compoundRecoveryEffects{
		Stop: stopCompoundRuntime, TunAbsent: ensureCompoundTunAbsent, Reload: func(ctx context.Context, a platform.App) error { _, e := systemctl(ctx, a, "daemon-reload"); return e }, Start: func(ctx context.Context, a platform.App) error { return lifecycle(ctx, a, "start") }, SealTun: sealTunReceipt,
		Prepare: prepareRestoredSystemFiles,
	})
}
func prepareRestoredSystemFiles(ctx context.Context, a platform.App, m manager) error {
	if !a.Scope.System || m.Core.Backend != "systemd" {
		return nil
	}
	c, e := loadCompound(a)
	if e != nil {
		return e
	}
	if c == nil {
		return platform.Usage("compound-journal-missing")
	}
	if _, e = os.Lstat(m.Core.Config); os.IsNotExist(e) && c.Original == nil {
		return nil
	} else if e != nil {
		return e
	}
	text, e := readManagedFile(a, m.Core.Config)
	if e != nil {
		return e
	}
	if _, parseErr := platform.DecodeYAML(text); parseErr != nil && c.Original == nil {
		_, gid, e := accountIdentity(false)
		if e != nil {
			return e
		}
		return setSystemConfigMode(m.Core.Config, gid)
	}
	return prepareServiceFiles(ctx, a, resolved{Manager: m, Text: text})
}
func recoverCompoundWith(ctx context.Context, a platform.App, effects compoundRecoveryEffects) error {
	if e := preventLockInheritance(a); e != nil {
		return e
	}
	c, e := loadCompound(a)
	if e != nil || c == nil {
		return e
	}
	if c.Phase == "committed" {
		return durableRemove(compoundPath(a))
	}
	// Verify every publication before stopping a process or changing files. A
	// foreign edit, device, unit or PID leaves the recovery record intact.
	for _, f := range c.Files {
		if e = currentCompoundFile(a, f); e != nil {
			return e
		}
	}
	if e = effects.Stop(ctx, a, c); e != nil {
		return e
	}
	if e = effects.TunAbsent(ctx, a, c); e != nil {
		return e
	}
	if e = compoundPhase(a, "restoring"); e != nil {
		return e
	}
	if e = recoverTransaction(a); e != nil {
		return e
	}
	for i := len(c.Files) - 1; i >= 0; i-- {
		f := c.Files[i]
		if e = publishFile(a, f.Path, f.Before, !f.Existed); e != nil {
			return e
		}
	}
	if effects.Prepare != nil {
		if e = effects.Prepare(ctx, a, c.Before); e != nil {
			return e
		}
	}
	if c.Reload {
		if e = effects.Reload(ctx, a); e != nil {
			return e
		}
	}
	compoundCheckpoint("restored-files")
	if c.Original != nil {
		hash, _, e := hashResource(ctx, a, c.Before.Core.Binary, "executable")
		if e != nil {
			return e
		}
		if hash != c.BinaryHash[c.Before.Core.Binary] {
			return platform.Usage("compound-binary-changed")
		}
		if e = compoundPhase(a, "restoring-runtime"); e != nil {
			return e
		}
		if e = effects.Start(ctx, a); e != nil {
			return e
		}
		if c.Before.Tun.Enabled {
			if e = effects.SealTun(ctx, a, c.Before); e != nil {
				return e
			}
		}
	}
	compoundCheckpoint("restored-runtime")
	if e = compoundPhase(a, "committed"); e != nil {
		return e
	}
	return durableRemove(compoundPath(a))
}
func stopCompoundRuntime(ctx context.Context, a platform.App, c *compoundRecord) error {
	if c.Before.Core.Backend == "systemd" || c.Next.Core.Backend == "systemd" {
		return stopCompoundService(ctx, a, c)
	}
	identities, e := findCompoundLaunches(a, c)
	if e != nil {
		return e
	}
	if c.Original != nil && identityAlive(*c.Original) {
		identities = append(identities, *c.Original)
	}
	for _, id := range identities {
		if e = stopExactProcess(ctx, id); e != nil {
			return e
		}
	}
	if _, e = os.Lstat(a.Scope.RuntimeState()); e == nil {
		raw, e := platform.ReadPrivate(a.Scope.RuntimeState())
		if e != nil {
			return e
		}
		var state runtimeState
		if json.Unmarshal(raw, &state) != nil || state.Version != 1 || state.Namespace != "mihomoctl-go" || state.Scope != a.Scope.Name || state.Home != a.Scope.CoreHome() || !allowedCompoundProcess(a, c, state.Identity) {
			return platform.Usage("runtime-state-invalid")
		}
		if identityAlive(state.Identity) {
			return platform.Usage("compound-runtime-unverified")
		}
		if e = durableRemove(a.Scope.RuntimeState()); e != nil {
			return e
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	return nil
}
func stopExactProcess(ctx context.Context, id identity) error {
	if !identityAlive(id) {
		return nil
	}
	if e := signalOwned(id, false); e != nil {
		return e
	}
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	killed := false
	for identityAlive(id) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		case <-deadline.C:
			if killed {
				return platform.Fail("runtime-stop-timeout")
			}
			if e := signalOwned(id, true); e != nil {
				return e
			}
			killed = true
			deadline.Reset(time.Second)
		}
	}
	return nil
}
func sealTunReceipt(ctx context.Context, a platform.App, m manager) error {
	device := tunDevice(m)
	observed, e := deviceState(ctx, device)
	if e != nil {
		return e
	}
	if observed == nil || platform.String(platform.Map(observed["linkinfo"])["info_kind"]) != "tun" {
		return platform.Fail("tun-activation-unverified")
	}
	id, e := serviceIdentity(ctx, a, m)
	if e != nil || id == nil || !ownsTun(*id, device) {
		return platform.Fail("tun-ownership-unverified")
	}
	routes, e := routePresent(ctx, device)
	if e != nil {
		return e
	}
	if !routes {
		return platform.Fail("tun-activation-unverified")
	}
	raw, e := json.Marshal(tunReceipt{device, platform.Int(observed["ifindex"]), 0})
	if e != nil {
		return e
	}
	return applyFiles(a, map[string][]byte{tunReceiptPath(a): raw})
}
