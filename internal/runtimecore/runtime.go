package runtimecore

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/liuzq1103/mihomoctl/internal/platform"
	"gopkg.in/yaml.v3"
)

// Handles recognizes only the native runtime grammar. Core downloads and releases
// are deliberately left to their respective handlers.
func Handles(command []string) bool {
	if len(command) == 1 {
		switch command[0] {
		case "init", "start", "stop", "restart", "status", "logs", "profiles", "exec", "direct", "integration", "health", "doctor", "reset", "migrate", "rollback":
			return true
		}
	}
	if len(command) != 2 {
		return false
	}
	switch command[0] {
	case "config":
		return member(command[1], "validate", "check")
	case "profile":
		return member(command[1], "list", "show", "validate", "set-default")
	case "env":
		return member(command[1], "show", "export")
	case "integration":
		return member(command[1], "list", "show", "check", "export", "install", "remove")
	case "service":
		return member(command[1], "install", "start", "stop", "restart", "status", "uninstall")
	case "tun":
		return member(command[1], "status", "enable", "disable")
	case "health":
		return command[1] == "check"
	case "core":
		return member(command[1], "adopt", "list")
	}
	return false
}
func member(s string, values ...string) bool {
	for _, v := range values {
		if s == v {
			return true
		}
	}
	return false
}

// Run executes one native request. On Linux exec/direct replace the caller, so
// signals, terminal ownership and exit status have their normal exec semantics.
func Run(ctx context.Context, a platform.App, r platform.Request) (platform.Envelope, error) {
	if !Handles(r.Command) {
		e := platform.Usage("unknown-command")
		return platform.Failure(r.TopLevel(), a.Scope.Name, e), e
	}
	var doc platform.Envelope
	if !mutating(r) && !member(r.Name(), "direct", "rollback", "migrate") {
		if e := pendingRecovery(a); e != nil {
			return platform.Failure(r.TopLevel(), a.Scope.Name, e), e
		}
	}
	work := func() error { var e error; doc, e = dispatch(ctx, a, r); return e }
	var err error
	if mutating(r) {
		err = platform.WithLock(ctx, a.Scope, func() error {
			if e := preventLockInheritance(a); e != nil {
				return e
			}
			if e := recoverCompound(ctx, a); e != nil {
				return e
			}
			if e := recoverTransaction(a); e != nil {
				return e
			}
			return work()
		})
	} else {
		err = work()
	}
	if err != nil {
		return platform.Failure(r.TopLevel(), a.Scope.Name, err), err
	}
	if !mutating(r) && !member(r.Name(), "direct", "rollback", "migrate") {
		if e := pendingRecovery(a); e != nil {
			return platform.Failure(r.TopLevel(), a.Scope.Name, e), e
		}
	}
	return doc, nil
}
func mutating(r platform.Request) bool {
	if r.Has("dry-run") {
		return false
	}
	n := r.Name()
	return member(n, "init", "start", "stop", "restart", "profile-set-default", "core-adopt", "service-install", "service-start", "service-stop", "service-restart", "service-uninstall", "tun-enable", "tun-disable", "integration-install", "integration-remove") || n == "reset" && r.Has("apply") || n == "migrate" && r.Has("apply") || n == "env-export" && r.Get("output") != "" || n == "integration-export" && r.Get("output-dir") != ""
}
func dispatch(ctx context.Context, a platform.App, r platform.Request) (platform.Envelope, error) {
	doc := platform.Document(r.Name(), a.Scope.Name, nil)
	set := func(m map[string]any) (platform.Envelope, error) { doc.Data = m; return doc, nil }
	switch r.Name() {
	case "init":
		d, e := initialize(ctx, a, r, false)
		doc.Data = d
		return doc, e
	case "start", "stop", "restart", "service-start", "service-stop", "service-restart":
		action := strings.TrimPrefix(r.Name(), "service-")
		if e := lifecycle(ctx, a, action); e != nil {
			return doc, e
		}
		return status(ctx, a, r.Name(), action == "stop")
	case "status", "service-status":
		return status(ctx, a, r.Name(), false)
	case "health", "health-check":
		return health(ctx, a, r)
	case "exec", "direct":
		return doc, execute(ctx, a, r)
	case "profile-list", "profiles":
		m, e := loadManager(a)
		if e != nil {
			return doc, e
		}
		rows := []map[string]any{}
		for _, n := range sortedKeys(m.Profiles) {
			rows = append(rows, profileDoc(n, m.Profiles[n]))
		}
		return set(map[string]any{"profiles": rows})
	case "profile-show", "profile-validate", "profile-set-default":
		n := r.Arg(0)
		if n == "" {
			return doc, platform.Usage("profile-required")
		}
		m, e := loadManager(a)
		if e != nil {
			return doc, e
		}
		p, ok := m.Profiles[n]
		if !ok {
			return doc, platform.UsageDetail("profile-unknown", n, "")
		}
		if r.Name() == "profile-show" {
			return set(profileDoc(n, p))
		}
		if _, e = resolve(a, n); e != nil {
			return doc, e
		}
		if r.Name() == "profile-validate" {
			return set(map[string]any{"profile": n, "valid": true})
		}
		m.Default = n
		b, e := yaml.Marshal(m)
		if e != nil {
			return doc, e
		}
		if e = applyFiles(a, map[string][]byte{a.Scope.ManagerPath(): b}); e != nil {
			return doc, e
		}
		return set(map[string]any{"default_profile": n})
	case "config-validate", "config-check":
		return configValidate(ctx, a, r)
	case "env-show", "env-export":
		return environmentCommand(a, r)
	case "logs":
		return logs(ctx, a, r)
	case "doctor":
		return doctor(ctx, a, r)
	case "integration", "integration-list", "integration-show", "integration-check", "integration-export", "integration-install", "integration-remove":
		return integration(ctx, a, r)
	case "service-install", "service-uninstall":
		return serviceCommand(ctx, a, r)
	case "tun-status", "tun-enable", "tun-disable":
		return tunCommand(ctx, a, r)
	case "core-adopt", "core-list":
		return coreCommand(ctx, a, r)
	case "reset":
		return reset(ctx, a, r)
	case "rollback":
		return doc, platform.UsageDetail("historical-rollback-disabled", "historical rollback is not supported", "")
	case "migrate":
		doc.Command = "migrate-apply"
		if r.Has("dry-run") {
			doc.Command = "migrate-preview"
		}
		if r.Has("apply") == r.Has("dry-run") {
			return doc, platform.Usage("migration-preview-required")
		}
		if r.Has("remove-loader") || !r.Has("no-import") && r.Has("apply") {
			return doc, platform.Usage("python-migration-disabled")
		}
		return set(map[string]any{"legacy_config": false, "imported": false, "python_migration": false, "namespace": "mihomoctl-go", "changed": false, "loader_blocks": map[string]any{}, "legacy_units": []any{}})
	}
	return doc, platform.Usage("unknown-command")
}

type fileSnapshot struct {
	Path    string
	Before  []byte
	Existed bool
	After   []byte
	Delete  bool
	// PrevObject is the identity of the object that stood at Path before
	// this transaction touched it, PublishedObject the identity of the
	// object this transaction published there, RestoredObject the identity
	// of the object a rollback published there. Identical bytes are not
	// proof of ownership, so the recovery re-checks these identities
	// before it undoes anything: a replacement file carrying the same
	// content is a different object and must survive the recovery.
	PrevObject      string
	PublishedObject string
	RestoredObject  string
}
type journal struct {
	Version int
	Files   []fileSnapshot
}

func journalPath(a platform.App) string {
	return filepath.Join(a.Scope.StateRoot, "transaction.json")
}

// applyFiles journals original bytes before publication. A crashed multi-file
// write is restored under the operation lock before another mutation can run.
func applyFiles(a platform.App, files map[string][]byte) error {
	_, e := applyFilesBinding(a, files)
	return e
}

// applyFilesBinding publishes the files and reports the identity of every
// object it published. The compound journal outlives this transaction, so the
// objects are bound into it before the transaction journal is removed: the
// compound journal is the record that still names them once the transaction
// journal is gone. The binding runs for every transaction, not only for the
// compound ones, because a compound operation publishes files through
// transactions of its own.
func applyFilesBinding(a platform.App, files map[string][]byte) (map[string]string, error) {
	published := map[string]string{}
	if e := platform.CheckPath(journalPath(a)); e != nil {
		return nil, e
	}
	if _, e := os.Lstat(journalPath(a)); e == nil {
		return nil, platform.Usage("transaction-pending")
	} else if !os.IsNotExist(e) {
		return nil, e
	}
	if e := trackCompoundWrites(a, files); e != nil {
		return nil, e
	}
	j := journal{Version: 1}
	prepared := map[string]string{}
	defer func() {
		for _, temporary := range prepared {
			_ = os.Remove(temporary)
		}
	}()
	for _, p := range sortedKeys(files) {
		if !transactionPath(a, p) {
			return nil, platform.Usage("transaction-path-unsafe")
		}
		if e := platform.CheckPath(p); e != nil {
			return nil, e
		}
		v := fileSnapshot{Path: p, After: files[p], Delete: files[p] == nil}
		if _, e := os.Lstat(p); e == nil {
			b, e := readManagedFile(a, p)
			if e != nil {
				return nil, e
			}
			v.Before = b
			v.Existed = true
			// The object that stood at the path is bound here, so the
			// recovery can tell it from a foreign replacement.
			if object, oe := platform.ObjectIdentity(p); oe == nil {
				v.PrevObject = object
			}
		} else if !os.IsNotExist(e) {
			return nil, e
		}
		if !v.Delete {
			// The published object is prepared first and its identity is
			// journaled before the rename, so a crash in the publication
			// window still leaves a record of the object that was published.
			temporary, object, e := prepareArtifact(a, p, files[p])
			if e != nil {
				return nil, e
			}
			prepared[p] = temporary
			v.PublishedObject = object
		}
		j.Files = append(j.Files, v)
	}
	// The compound journal names the objects this operation replaced, the file
	// transaction journal names the objects it is about to publish. Neither
	// names the object that will stand at the path until the publication is
	// recorded, so a crash in this window leaves a foreign replacement at the
	// path indistinguishable from the operation's own file.
	compoundCheckpoint("files-prepared")
	if e := persistTransaction(a, j); e != nil {
		return nil, e
	}
	for _, f := range j.Files {
		if e := commitArtifact(a, f.Path, prepared[f.Path], f.Delete); e != nil {
			if r := restoreFiles(a, j); r != nil {
				return nil, platform.Fail("rollback-failed")
			}
			if r := durableRemove(journalPath(a)); r != nil {
				return nil, platform.Fail("transaction-journal-unavailable")
			}
			return nil, e
		}
	}
	// The publication is done, the compound journal does not name the published
	// objects yet. A crash in this window leaves the compound journal with only
	// the objects it replaced, and the recovery has to tell the published
	// objects from foreign replacements that carry identical bytes.
	compoundCheckpoint("files-publishing")
	for _, f := range j.Files {
		if object := f.PublishedObject; object != "" {
			published[f.Path] = object
		}
	}
	// A journal that outlives this transaction has to name the objects this
	// transaction published. The binding runs while the transaction journal
	// still names them, so no window leaves the published objects unnamed, and
	// it runs before the transaction journal is removed.
	if e := bindPublishedObjects(a, published); e != nil {
		if r := restoreFiles(a, j); r != nil {
			return nil, platform.Fail("rollback-failed")
		}
		if r := durableRemove(journalPath(a)); r != nil {
			return nil, platform.Fail("transaction-journal-unavailable")
		}
		return nil, e
	}
	if e := durableRemove(journalPath(a)); e != nil {
		if r := restoreFiles(a, j); r != nil {
			return nil, platform.Fail("rollback-failed")
		}
		return nil, e
	}
	return published, nil
}

// persistTransaction writes the file journal. The journal is written before
// every mutation it describes, so it always names the object a publication or
// a rollback is about to create.
func persistTransaction(a platform.App, j journal) error {
	raw, e := json.Marshal(j)
	if e != nil {
		return e
	}
	if int64(len(raw)) > fileJournalLimit {
		return platform.Usage("transaction-too-large")
	}
	if e := platform.AtomicWrite(journalPath(a), append(raw, '\n'), 0600); e != nil {
		return e
	}
	return syncDirectory(a.Scope.StateRoot)
}

func transactionPath(a platform.App, p string) bool {
	return absolute(p) && (a.Scope.Contains(p) || p == unitPath(a) || within(unitPath(a)+".d", p) || integrationPathAllowed(a, p)) && p != journalPath(a) && p != compoundPath(a)
}
func publishFile(a platform.App, p string, b []byte, remove bool) error {
	if e := platform.CheckPath(p); e != nil {
		return e
	}
	if remove {
		if _, e := os.Lstat(p); os.IsNotExist(e) {
			return nil
		}
		if _, e := readManagedFile(a, p); e != nil {
			return e
		}
		return durableRemove(p)
	}
	temporary, _, e := prepareArtifact(a, p, b)
	if e != nil {
		return e
	}
	defer os.Remove(temporary)
	return commitArtifact(a, p, temporary, false)
}

// Standard systemd parent directories may be 0755. Validate their ownership
// without changing their permissions, and always publish private managed leaves.
// prepareArtifact writes the payload into a temporary file beside the
// destination and returns that file and its identity. The temporary file is
// the object that will be published, so the journal can record it before the
// rename: the recovery then tells the published object from a foreign
// replacement that carries identical bytes.
func prepareArtifact(a platform.App, p string, b []byte) (string, string, error) {
	if e := platform.CheckPath(p); e != nil {
		return "", "", e
	}
	if _, e := os.Lstat(p); e == nil {
		if _, e = readManagedFile(a, p); e != nil {
			return "", "", e
		}
	} else if !os.IsNotExist(e) {
		return "", "", e
	}
	if e := checkArtifactDir(filepath.Dir(p)); e != nil {
		return "", "", e
	}
	f, e := os.CreateTemp(filepath.Dir(p), ".mihomoctl-go-*")
	if e != nil {
		return "", "", e
	}
	tmp := f.Name()
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		_ = os.Remove(tmp)
		return "", "", e
	}
	object, e := platform.ObjectIdentity(tmp)
	if e != nil {
		_ = os.Remove(tmp)
		return "", "", e
	}
	return tmp, object, nil
}

// commitArtifact publishes the prepared temporary file over the destination,
// or removes the destination when the transaction deletes it, and makes the
// change durable.
func commitArtifact(a platform.App, p, tmp string, remove bool) error {
	if remove {
		if _, e := os.Lstat(p); os.IsNotExist(e) {
			return nil
		}
		if _, e := readManagedFile(a, p); e != nil {
			return e
		}
		return durableRemove(p)
	}
	if err := os.Rename(tmp, p); err != nil {
		return err
	}
	// A rename is only durable once the directory entry itself is flushed.
	// The failure is reported: a publication that cannot confirm its
	// durability must not be reported as a success, and the journal that
	// describes it must not be discarded.
	return syncDirectory(filepath.Dir(p))
}

// restoreFiles publishes the recorded original bytes. A rollback publishes a
// NEW object, so the journal names it before the rename: a recovery that is
// interrupted between the restore and the journal removal recognizes its own
// work instead of refusing the transaction forever.
func restoreFiles(a platform.App, j journal) error {
	for i := len(j.Files) - 1; i >= 0; i-- {
		f := j.Files[i]
		if !f.Existed {
			// The file did not exist before the transaction, so the rollback
			// removes it instead of publishing an object.
			if e := publishFile(a, f.Path, f.Before, true); e != nil {
				return e
			}
			continue
		}
		if f.RestoredObject != "" {
			if object, oe := platform.ObjectIdentity(f.Path); oe == nil && object == f.RestoredObject {
				// The restore already published this object. Publishing a
				// second one would overwrite the only record of the first.
				continue
			}
		}
		temporary, object, e := prepareArtifact(a, f.Path, f.Before)
		if e != nil {
			return e
		}
		f.RestoredObject = object
		j.Files[i] = f
		if e := persistTransaction(a, j); e != nil {
			_ = os.Remove(temporary)
			return e
		}
		// The compound journal outlives this transaction, so it names the object
		// the rollback publishes before the rename: a recovery that finds the
		// restored object at the path recognizes its own work instead of
		// refusing the operation forever.
		if e := bindRestoredObject(a, f.Path, object); e != nil {
			_ = os.Remove(temporary)
			return e
		}
		if e := commitArtifact(a, f.Path, temporary, false); e != nil {
			_ = os.Remove(temporary)
			return e
		}
	}
	return nil
}

// validateTransactionFiles checks a pending file journal without undoing it.
// Every destination must still hold the object this transaction published or
// the object it replaced: a foreign replacement that carries identical bytes
// is a different object and must not be overwritten or removed.
func validateTransactionFiles(a platform.App, j journal) error {
	for _, f := range j.Files {
		if !transactionPath(a, f.Path) {
			return platform.Usage("transaction-invalid")
		}
		if _, e := os.Lstat(f.Path); e == nil {
			// The journal binds the objects it published and the objects
			// it replaced. A foreign replacement carrying the same bytes is
			// a different object, and the recovery must not undo it as if it
			// were the transaction's own file.
			if f.PublishedObject != "" || f.PrevObject != "" || f.RestoredObject != "" {
				object, oe := platform.ObjectIdentity(f.Path)
				if oe != nil {
					return oe
				}
				if object != f.PublishedObject && object != f.PrevObject && object != f.RestoredObject {
					return platform.Usage("transaction-conflict")
				}
			}
			current, e := readManagedFile(a, f.Path)
			if e != nil {
				return e
			}
			if !bytesEqual(current, f.Before) && !bytesEqual(current, f.After) {
				return platform.Usage("transaction-conflict")
			}
		}
	}
	return nil
}

// loadTransaction reads the pending file journal.
func loadTransaction(a platform.App) (journal, bool, error) {
	var j journal
	p := journalPath(a)
	if e := platform.CheckPath(p); e != nil {
		return j, false, e
	}
	if _, e := os.Lstat(p); os.IsNotExist(e) {
		return j, false, nil
	} else if e != nil {
		return j, false, e
	}
	b, e := readPrivateBounded(p, fileJournalLimit)
	if e != nil {
		return j, false, e
	}
	if json.Unmarshal(b, &j) != nil || j.Version != 1 || len(j.Files) > 1024 {
		return j, false, platform.Usage("transaction-invalid")
	}
	return j, true, nil
}

func recoverTransaction(a platform.App) error {
	j, pending, e := loadTransaction(a)
	if e != nil {
		return e
	}
	if !pending {
		return nil
	}
	if e = validateTransactionFiles(a, j); e != nil {
		return e
	}
	if e = restoreFiles(a, j); e != nil {
		return platform.Fail("rollback-failed")
	}
	return durableRemove(journalPath(a))
}

// discardTransaction validates a pending file journal and removes it without
// publishing anything. The compound recovery restores the same files itself
// and names every object it publishes in the compound journal, so it must not
// leave objects that no journal names.
func discardTransaction(a platform.App) error {
	j, pending, e := loadTransaction(a)
	if e != nil {
		return e
	}
	if !pending {
		return nil
	}
	if e = validateTransactionFiles(a, j); e != nil {
		return e
	}
	return durableRemove(journalPath(a))
}
func bytesEqual(a, b []byte) bool { return string(a) == string(b) }

func freePort() (int, error) {
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		return 0, e
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}
func initialize(ctx context.Context, a platform.App, r platform.Request, replacing bool) (map[string]any, error) {
	if !replacing {
		if e := platform.CheckPath(a.Scope.ManagerPath()); e != nil {
			return nil, e
		}
		if _, e := os.Lstat(a.Scope.ManagerPath()); e == nil {
			return nil, platform.Usage("already-initialized")
		} else if !os.IsNotExist(e) {
			return nil, e
		}
	}
	m, files, result, e := initialPlan(ctx, a, r)
	if e != nil {
		return nil, e
	}
	if !replacing {
		for p := range files {
			if _, e := os.Lstat(p); e == nil {
				return nil, platform.Usage("initialization-target-exists")
			} else if !os.IsNotExist(e) {
				return nil, e
			}
		}
	}
	if e = applyFiles(a, files); e != nil {
		return nil, e
	}
	if a.Scope.System {
		if e = prepareServiceFiles(ctx, a, resolved{Manager: m, Text: files[m.Core.Config]}); e != nil {
			if !replacing {
				remove := map[string][]byte{}
				for p := range files {
					remove[p] = nil
				}
				if cleanup := applyFiles(a, remove); cleanup != nil {
					return nil, platform.Fail("rollback-failed")
				}
			}
			return nil, e
		}
	}
	return result, nil
}
func initialPlan(ctx context.Context, a platform.App, r platform.Request) (manager, map[string][]byte, map[string]any, error) {
	var m manager
	bad := func(e error) (manager, map[string][]byte, map[string]any, error) { return m, nil, nil, e }
	binary := r.Get("core")
	if binary == "" {
		return bad(platform.Usage("core-required"))
	}
	binary, e := filepath.Abs(binary)
	if e != nil {
		return bad(e)
	}
	if e = trustedExecutable(binary, a.Scope.System); e != nil {
		return bad(e)
	}
	if a.Scope.System {
		if _, _, e = accountIdentity(true); e != nil {
			return bad(e)
		}
	}
	port, e := freePort()
	if e != nil {
		return bad(e)
	}
	if raw := r.Get("port"); raw != "" {
		_, e = fmt.Sscanf(raw, "%d", &port)
		if e != nil || fmt.Sprint(port) != raw || port < 1024 || port > 65535 {
			return bad(platform.Usage("port-invalid"))
		}
	}
	cp, e := freePort()
	if e != nil {
		return bad(e)
	}
	for cp == port {
		cp, e = freePort()
		if e != nil {
			return bad(e)
		}
	}
	u, e := platform.Token()
	if e != nil {
		return bad(e)
	}
	password, e := platform.Token()
	if e != nil {
		return bad(e)
	}
	secret, e := platform.Token()
	if e != nil {
		return bad(e)
	}
	creds := credentials{"user-" + u[:20], password}
	cfg := map[string]any{"mode": "rule", "listeners": []any{map[string]any{"name": "proxy", "type": "mixed", "listen": "127.0.0.1", "port": port, "users": []any{map[string]any{"username": creds.Username, "password": creds.Password}}}}, "external-controller": fmt.Sprintf("127.0.0.1:%d", cp), "secret": secret, "profile": map[string]any{"store-selected": true}, "rules": []any{"MATCH,DIRECT"}}
	if src := r.Get("config"); src != "" {
		v, e := platform.ReadYAML(src, true)
		if e != nil {
			return bad(platform.ConfigDiagnostic(e))
		}
		if platform.Bool(platform.Map(v["tun"])["enable"]) {
			return bad(platform.Usage("import-tun-forbidden"))
		}
		for _, k := range []string{"listeners", "external-controller", "secret"} {
			if _, ok := v[k]; !ok {
				v[k] = cfg[k]
			}
		}
		p, ok := v["profile"].(map[string]any)
		if v["profile"] != nil && !ok {
			return bad(invalid())
		}
		if p == nil {
			p = map[string]any{}
		}
		p["store-selected"] = true
		v["profile"] = p
		cfg = v
	}
	allowed := r.Options["allow-non-loopback"]
	eps, controller, e := parseEndpoints(cfg, a.Scope.System, allowed)
	if e != nil {
		return bad(e)
	}
	profileName := r.Get("_profile")
	if profileName == "" {
		profileName = "default"
	}
	if !namePattern.MatchString(profileName) {
		return bad(invalid())
	}
	p := defaults(profile{Credentials: filepath.Join(a.Scope.ConfigRoot, "credentials", profileName+".yaml")})
	for _, ep := range eps {
		if p.HTTP == "" && ep.http() {
			p.HTTP = ep.Name
		}
		if p.SOCKS == "" && ep.socks() {
			p.SOCKS = ep.Name
		}
	}
	for _, ep := range eps {
		if ep.Name == p.HTTP || p.HTTP == "" && ep.Name == p.SOCKS {
			port = ep.Port
			break
		}
	}
	if controller != nil {
		cp = controller.Port
	} else {
		cp = 0
	}
	if p.HTTP == "" && p.SOCKS == "" {
		return bad(platform.Usage("proxy-listener-required"))
	}
	for _, ep := range eps {
		if ep.Name == p.HTTP || ep.Name == p.SOCKS {
			if len(ep.Users) == 0 {
				return bad(platform.Usage("credentials-required"))
			}
			if creds.Username == "" {
				creds = ep.Users[0]
			} else if !hasCredential(ep, creds) {
				if r.Get("config") != "" && creds.Username == "user-"+u[:20] {
					creds = ep.Users[0]
				} else {
					return bad(platform.Usage("credentials-mismatch"))
				}
			}
		}
	}
	backend := "process"
	if a.Scope.System {
		backend = "systemd"
	}
	m = manager{Version: 1, Core: coreSettings{Binary: binary, Config: filepath.Join(a.Scope.ConfigRoot, "mihomo", "config.yaml"), Backend: backend}, Default: profileName, Profiles: map[string]profile{profileName: p}, Bindings: map[string]binding{}, Tun: tunSettings{Device: "mihomo0"}, Allow: allowed}
	if e = validateManager(a, m); e != nil {
		return bad(e)
	}
	text, e := yaml.Marshal(cfg)
	if e != nil {
		return bad(e)
	}
	if e = validateCore(ctx, a, binary, text); e != nil {
		return bad(e)
	}
	mb, e := yaml.Marshal(m)
	if e != nil {
		return bad(e)
	}
	cb, e := yaml.Marshal(creds)
	if e != nil {
		return bad(e)
	}
	files := map[string][]byte{a.Scope.ManagerPath(): mb, m.Core.Config: text, p.Credentials: cb}
	generated, e := json.Marshal(generatedConfig{Hash: platform.Hash(text), Automatic: r.Get("port") == "" && r.Get("config") == ""})
	if e != nil {
		return bad(e)
	}
	files[generatedPath(a)] = generated
	listener := p.HTTP
	if listener == "" {
		listener = p.SOCKS
	}
	return m, files, map[string]any{"manager": a.Scope.ManagerPath(), "config": m.Core.Config, "credentials": p.Credentials, "core": map[string]any{"binary": binary, "adopted": true}, "port": port, "controller_port": cp, "backend": backend, "listener": listener, "port_is_candidate": r.Get("port") == ""}, nil
}
func configValidate(ctx context.Context, a platform.App, r platform.Request) (platform.Envelope, error) {
	doc := platform.Document("config-validate", a.Scope.Name, nil)
	var text []byte
	var m manager
	var e error
	if p := r.Get("file"); p != "" {
		text, e = readManagedFile(a, p)
		doc.Data["file"] = p
		if e != nil {
			return doc, e
		}
		m, e = loadManager(a)
		if e != nil {
			if _, stat := os.Lstat(a.Scope.ManagerPath()); !os.IsNotExist(stat) {
				return doc, e
			}
			m = manager{}
		}
	} else {
		x, e := resolve(a, r.Get("profile"))
		if e != nil {
			return doc, e
		}
		text = x.Text
		m = x.Manager
		doc.Data["config"] = m.Core.Config
	}
	cfg, e := platform.DecodeYAML(text)
	if e != nil {
		return doc, platform.ConfigDiagnostic(e)
	}
	eps, _, e := parseEndpoints(cfg, a.Scope.System, m.Allow)
	if e != nil {
		return doc, e
	}
	addCheck(&doc, "config-parse", true, fmt.Sprintf("%d listening surfaces", len(eps)))
	if m.Core.Binary == "" {
		doc.Checks = append(doc.Checks, platform.Check{Name: "core-validate", Status: "UNVERIFIED", Evidence: "unavailable", Detail: "initialize a trusted core before semantic validation"})
		doc.Overall = "UNVERIFIED"
		return doc, nil
	}
	if e = validateCore(ctx, a, m.Core.Binary, text); e != nil {
		return doc, e
	}
	addCheck(&doc, "core-validate", true, "")
	return doc, nil
}
func addCheck(doc *platform.Envelope, name string, ok bool, detail string) {
	s := "PASS"
	if !ok {
		s = "FAIL"
		doc.Overall = "FAIL"
	}
	doc.Checks = append(doc.Checks, platform.Check{Name: name, Status: s, Evidence: "confirmed", Detail: detail})
}
func readLogWindow(p string) ([]byte, int64, error) {
	if e := platform.CheckPath(p); e != nil {
		return nil, 0, e
	}
	f, e := openPrivateRegular(p)
	if e != nil {
		return nil, 0, e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return nil, 0, e
	}
	if e = checkLogInfo(st); e != nil {
		return nil, 0, e
	}
	start := st.Size() - platform.Limit
	if start < 0 {
		start = 0
	}
	if _, e = f.Seek(start, io.SeekStart); e != nil {
		return nil, 0, e
	}
	b, e := io.ReadAll(io.LimitReader(f, platform.Limit))
	return b, start, e
}
func doctor(ctx context.Context, a platform.App, r platform.Request) (platform.Envelope, error) {
	doc := platform.Document(r.Name(), a.Scope.Name, map[string]any{"scope": a.Scope.Name})
	m, managerErr := loadManager(a)
	detail := ""
	if managerErr != nil {
		detail = renderError(managerErr)
	}
	addCheck(&doc, "manager-config", managerErr == nil, detail)
	if managerErr == nil {
		doc.Data["backend"] = m.Core.Backend
		e := trustedExecutable(m.Core.Binary, a.Scope.System)
		detail = m.Core.Binary
		if e != nil {
			detail = renderError(e)
		}
		addCheck(&doc, "core-binary", e == nil, detail)
	}
	s, e := status(ctx, a, "status", false)
	if e != nil {
		addCheckEvidence(&doc, "runtime", "UNVERIFIED", "confirmed", renderError(e))
	} else {
		state := s.Overall
		running := "None"
		if platform.Bool(platform.Map(s.Data["core"])["initialized"]) {
			running = "False"
			if platform.Bool(platform.Map(s.Data["runtime"])["running"]) {
				running = "True"
			}
		}
		addCheckEvidence(&doc, "runtime", state, "confirmed", "running="+running)
		snapshot := map[string]any{}
		for _, key := range []string{"scope", "backend", "listeners", "controller", "tun", "errors"} {
			snapshot[key] = s.Data[key]
		}
		doc.Data["status"] = snapshot
	}
	h, e := health(ctx, a, platform.Request{Command: []string{"health"}})
	if e != nil {
		addCheckEvidence(&doc, "health", "UNVERIFIED", "confirmed", renderError(e))
	} else {
		for _, check := range h.Checks {
			addCheckEvidence(&doc, check.Name, check.Status, check.Evidence, check.Detail)
		}
	}
	_, e = exec.LookPath("systemctl")
	state, evidence := "PASS", "confirmed"
	if e != nil {
		state, evidence = "SKIPPED", "unavailable"
	}
	addCheckEvidence(&doc, "dependency-systemctl", state, evidence, "")
	// The native product checks its running executable instead of depending on
	// the baseline's Python interpreter. No Go compiler is required at runtime.
	binary, e := os.Executable()
	if e == nil {
		_, e = os.Stat(binary)
	}
	state, evidence = "PASS", "confirmed"
	if e != nil {
		state, evidence = "SKIPPED", "unavailable"
	}
	addCheckEvidence(&doc, "dependency-go-binary", state, evidence, "")
	return doc, nil
}
func safeDetail(e error) string {
	if e == nil {
		return ""
	}
	return platform.SafeError(e)
}
