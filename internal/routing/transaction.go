package routing

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"crypto/rand"
	"encoding/hex"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

// The transaction engine is a file-level port of the original
// mihomoctl/transaction.py: staged mutations with real rollback. Phases:
// stage -> backup -> publish (atomic replace) -> commit. Rollback replays the
// journal in reverse and restores prior content AND metadata; a rollback that
// itself fails is reported as a distinct rollback-failed error, never
// silently downgraded. Runtime (service) restoration is not part of routing:
// that belongs to the runtime core.

const txJournalLimit = 16 * 1024 * 1024

// txIDPattern confines a transaction identifier to the exact shape
// beginFileTransaction generates: a filename-safe label, a hyphen, and the
// twelve lowercase hex characters of the random tail. A journal is untrusted
// input: anything whose on-disk directory or recorded id deviates from this
// shape is refused outright rather than replayed.
var txIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}-[0-9a-f]{12}$`)

// txNamePattern bounds the transaction label recorded inside a journal.
var txNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// txRecord is one journaled operation. The journal is persisted BEFORE the
// filesystem mutation, so a crash at any point leaves a recoverable plan.
type txRecord struct {
	Op     string `json:"op"` // publish | delete
	Path   string `json:"path"`
	Type   string `json:"type"` // file | dir | symlink
	Mode   string `json:"mode"` // octal permission string
	UID    int    `json:"uid"`
	GID    int    `json:"gid"`
	Backup string `json:"backup,omitempty"`
	// BackupSHA256 is the content this transaction wrote into the backup
	// file. The recovery compares the file at the path against the recorded
	// content, not against whatever the backup file happens to contain when
	// the recovery runs: a replaced backup must never decide what the
	// rollback writes over the user's configuration.
	BackupSHA256    string   `json:"backup_sha256,omitempty"`
	Existed         bool     `json:"existed,omitempty"`
	Created         bool     `json:"created,omitempty"`
	CreatedDirs     []string `json:"created_dirs,omitempty"`
	PublishedSHA256 string   `json:"published_sha256,omitempty"`
	SymlinkTarget   string   `json:"symlink_target,omitempty"`
	// PrevObject is the identity of the object that stood at Path before
	// this transaction touched it, PublishedObject the identity of the
	// object this transaction published there. A content hash cannot tell
	// the published object from a foreign replacement carrying identical
	// bytes, so the recovery re-checks these identities before it undoes
	// anything. RestoredObject names the object a rollback published: a
	// rollback writes a new object, and an interrupted rollback must stay
	// recoverable.
	PrevObject      string `json:"prev_object,omitempty"`
	PublishedObject string `json:"published_object,omitempty"`
	RestoredObject  string `json:"restored_object,omitempty"`
}

// fileTransaction is one durable multi-file mutation with rollback.
type fileTransaction struct {
	scope       platform.Scope
	system      bool
	id          string
	name        string
	staging     string
	backupRoot  string
	journal     []txRecord
	finished    bool
	journalOnly bool // recovered transaction: staging is gone, journal drives
}

func (t *fileTransaction) backupsRoot() string { return filepath.Join(t.scope.StateRoot, "backups") }
func (t *fileTransaction) stagingRoot() string { return filepath.Join(t.scope.StateRoot, "staging") }

// sanitizeFileLabel reduces a path component to filename-safe characters.
func sanitizeFileLabel(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '.', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	label := strings.Trim(b.String(), ".")
	if len(label) > 80 {
		label = label[len(label)-80:]
	}
	if label == "" {
		label = "file"
	}
	return label
}

// beginFileTransaction creates the staging area and the pending journal.
func beginFileTransaction(scope platform.Scope, name string, system bool) (*fileTransaction, error) {
	tx := &fileTransaction{scope: scope, system: system, name: name}
	id := make([]byte, 6)
	if _, err := rand.Read(id); err != nil {
		return nil, control("controller-operation-unavailable", exitUnverify)
	}
	tx.id = name + "-" + hex.EncodeToString(id)
	if !txIDPattern.MatchString(tx.id) {
		return nil, control("transaction-journal-invalid", exitUnverify)
	}
	if err := platform.PrivateDir(tx.stagingRoot()); err != nil {
		return nil, controllerFileError(err)
	}
	staging, err := os.MkdirTemp(tx.stagingRoot(), tx.id+"-")
	if err != nil {
		return nil, controllerFileError(err)
	}
	if err := os.Chmod(staging, 0700); err != nil {
		return nil, controllerFileError(err)
	}
	tx.staging = staging
	tx.backupRoot = filepath.Join(tx.backupsRoot(), tx.id)
	if err := platform.PrivateDir(tx.backupRoot); err != nil {
		return nil, controllerFileError(err)
	}
	if err := tx.persist("pending"); err != nil {
		return nil, err
	}
	return tx, nil
}

// persist writes the write-ahead journal before each filesystem mutation.
func (t *fileTransaction) persist(state string) error {
	if err := platform.PrivateDir(t.backupRoot); err != nil {
		return controllerFileError(err)
	}
	// A nil journal must marshal as [], never null: recovery rejects a
	// journal-less document, and a crash right after begin is recoverable.
	journal := t.journal
	if journal == nil {
		journal = []txRecord{}
	}
	document := map[string]any{
		"id":      t.id,
		"name":    t.name,
		"state":   state,
		"staging": t.staging,
		"journal": journal,
	}
	raw, err := json.Marshal(document)
	if err != nil {
		return control("transaction-journal-invalid", exitUnverify)
	}
	if err := platform.AtomicWrite(filepath.Join(t.backupRoot, "journal.json"), append(raw, '\n'), 0600); err != nil {
		return controllerFileError(err)
	}
	return nil
}

func (t *fileTransaction) cleanup() {
	_ = os.RemoveAll(t.staging)
	_ = os.RemoveAll(t.backupRoot)
}

// checkDestination confines publication to the managed roots, refusing
// symlinks and parent-escaping paths exactly like the original.
func (t *fileTransaction) checkDestination(destination string) error {
	refuse := func(code string) error { return control(code, exitUnverify) }
	absolute, err := filepath.Abs(destination)
	if err != nil || absolute != filepath.Clean(absolute) {
		return refuse("destination-outside-managed-roots")
	}
	for _, part := range strings.Split(filepath.ToSlash(absolute), "/") {
		if part == ".." {
			return refuse("destination-outside-managed-roots")
		}
	}
	if info, err := os.Lstat(absolute); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return refuse("refuse-symlink-destination")
	}
	roots := []string{t.scope.ConfigRoot, t.scope.DataRoot, t.scope.StateRoot, t.scope.CacheRoot}
	inside := ""
	for _, root := range roots {
		if rel, err := filepath.Rel(root, absolute); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			inside = root
			break
		}
	}
	if inside == "" {
		return refuse("destination-outside-managed-roots")
	}
	if !txAncestorsTrusted(absolute, inside) {
		return refuse("destination-outside-managed-roots")
	}
	return nil
}

// stage writes the payload into the private staging area.
func (t *fileTransaction) stage(data []byte, mode os.FileMode) (string, error) {
	name := "publish-" + fmt.Sprintf("%d", len(t.journal))
	path := filepath.Join(t.staging, name)
	if err := os.WriteFile(path, data, 0600); err != nil {
		return "", controllerFileError(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		return "", controllerFileError(err)
	}
	return path, nil
}

// captureMetadata records type and permission bits; ownership is recorded
// where the platform exposes it.
func (t *fileTransaction) captureMetadata(record *txRecord, path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return controllerFileError(err)
	}
	record.Mode = fmt.Sprintf("%o", info.Mode().Perm())
	record.UID, record.GID = fileOwnerIDs(info)
	switch {
	case info.Mode()&os.ModeSymlink != 0:
		record.Type = "symlink"
		target, err := os.Readlink(path)
		if err != nil {
			return controllerFileError(err)
		}
		record.SymlinkTarget = target
	case info.IsDir():
		record.Type = "dir"
	case info.Mode().IsRegular():
		record.Type = "file"
	default:
		return control("refuse-unusual-file", exitUnverify)
	}
	if object, err := txObjectIdentity(path); err == nil {
		record.PrevObject = object
	}
	return nil
}

// backup copies the current content beside the journal, exclusively created.
// The name is the journal index plus a sanitized basename hint; the absolute
// backup path is recorded in the journal record itself, and a path-derived
// name would embed volume colons (invalid in Windows filenames).
func (t *fileTransaction) backup(path string, record *txRecord) (string, error) {
	if err := platform.PrivateDir(t.backupRoot); err != nil {
		return "", controllerFileError(err)
	}
	label := sanitizeFileLabel(filepath.Base(path))
	saved := filepath.Join(t.backupRoot, fmt.Sprintf("%d-%s", len(t.journal), label))
	if record.Type == "symlink" {
		// The target lives in the journal record; no content file.
		return saved, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", controllerFileError(err)
	}
	if err := platform.AtomicWrite(saved, data, 0600); err != nil {
		return "", controllerFileError(err)
	}
	record.BackupSHA256 = hashSHA256(data)
	return saved, nil
}

// publish atomically replaces destination with the staged payload. The
// journal entry is durable BEFORE the replacement runs.
func (t *fileTransaction) publish(destination string, data []byte, mode os.FileMode) error {
	if err := t.checkDestination(destination); err != nil {
		return err
	}
	record := txRecord{Op: "publish", Path: destination}
	info, statErr := os.Lstat(destination)
	existed := statErr == nil
	if statErr != nil && !os.IsNotExist(statErr) {
		return controllerFileError(statErr)
	}
	if existed {
		if !info.Mode().IsRegular() {
			return control("refuse-non-file-destination", exitUnverify)
		}
		if !managedFileAcceptable(info, t.system) {
			return control("controller-path-must-be-private-owned-regular", exitUnverify)
		}
		if err := t.captureMetadata(&record, destination); err != nil {
			return err
		}
		saved, err := t.backup(destination, &record)
		if err != nil {
			return err
		}
		record.Backup = saved
		record.Existed = true
	} else {
		record.Created = true
	}
	// Create every missing component privately, remembering them for
	// rollback; existing shared directories keep their permissions.
	var missing []string
	for cursor := filepath.Dir(destination); ; {
		if _, err := os.Lstat(cursor); err == nil {
			break
		} else if !os.IsNotExist(err) {
			return controllerFileError(err)
		}
		missing = append(missing, cursor)
		parent := filepath.Dir(cursor)
		if parent == cursor {
			break
		}
		cursor = parent
	}
	for i := len(missing) - 1; i >= 0; i-- {
		if err := os.Mkdir(missing[i], 0700); err != nil && !os.IsExist(err) {
			return controllerFileError(err)
		}
	}
	record.CreatedDirs = missing
	if mode == 0 {
		mode = os.FileMode(0600)
	}
	record.PublishedSHA256 = hashSHA256(data)
	// The published object is prepared first so its identity can be
	// journaled before the rename: the journal entry is durable BEFORE
	// the replacement runs, and it names the object that the replacement
	// will publish.
	temporary, object, err := txPrepareReplace(destination, data, mode)
	if err != nil {
		return err
	}
	record.PublishedObject = object
	t.journal = append(t.journal, record)
	if err := t.persist("pending"); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	if err := txCommitReplace(destination, temporary); err != nil {
		return err
	}
	if existed {
		txRestoreOwnership(destination, record.UID, record.GID)
	}
	return nil
}

// writeBytes stages and publishes one file.
func (t *fileTransaction) writeBytes(destination string, data []byte, mode os.FileMode) error {
	if _, err := t.stage(data, mode); err != nil {
		return err
	}
	return t.publish(destination, data, mode)
}

// delete removes a file inside the transaction; rollback restores content and
// metadata. An optional managed-marker prefix refuses foreign files.
func (t *fileTransaction) delete(path, requireManagedMarker string) (bool, error) {
	if err := t.checkDestination(path); err != nil {
		return false, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, controllerFileError(err)
	}
	if info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
		return false, control("refuse-directory-delete", exitUnverify)
	}
	if requireManagedMarker != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return false, control("refuse-delete", exitUnverify)
		}
		if !bytes.HasPrefix(data, []byte(requireManagedMarker)) {
			return false, control("refuse-delete", exitUnverify)
		}
	}
	record := txRecord{Op: "delete", Path: path}
	if err := t.captureMetadata(&record, path); err != nil {
		return false, err
	}
	saved, err := t.backup(path, &record)
	if err != nil {
		return false, err
	}
	record.Backup = saved
	t.journal = append(t.journal, record)
	if err := t.persist("pending"); err != nil {
		return false, err
	}
	if err := os.Remove(path); err != nil {
		return false, controllerFileError(err)
	}
	return true, nil
}

// commit durably records completion before removing recovery data.
func (t *fileTransaction) commit() error {
	if err := t.persist("committed"); err != nil {
		return err
	}
	t.finished = true
	t.cleanup()
	return nil
}

// rollback restores every journaled path in reverse: content AND metadata. A
// failure to fully restore is a distinct rollback failure and the journal is
// retained for inspection.
func (t *fileTransaction) rollback(finish bool) error {
	// The backups are checked before the first undo. The undo runs in reverse
	// order, so an earlier backup is read last: a backup that was replaced
	// after the crash would otherwise be discovered only after the later
	// files were already restored, leaving a mixed old/new configuration
	// behind with the journal retained. Refusing before anything is undone
	// keeps the configuration uniform.
	if err := t.verifyBackups(); err != nil {
		return &controlError{
			code:       "rollback-failed",
			rc:         exitUnverify,
			safeDetail: "could not restore: " + err.Error() + "; unfinished transaction retained",
		}
	}
	var failures []string
	for i := len(t.journal) - 1; i >= 0; i-- {
		record := &t.journal[i]
		restoreErr := t.undoRecord(record)
		if restoreErr != nil {
			failures = append(failures, fmt.Sprintf("%s (%v)", record.Path, restoreErr))
			continue
		}
	}
	if len(failures) > 0 {
		sort.Strings(failures)
		return &controlError{
			code:       "rollback-failed",
			rc:         exitUnverify,
			safeDetail: "could not restore: " + strings.Join(failures, "; ") + "; unfinished transaction retained",
		}
	}
	if err := t.persist("restored"); err != nil {
		return err
	}
	if finish {
		t.finished = true
		t.cleanup()
	}
	return nil
}

// verifyBackups checks every backup the rollback would read, before the first
// undo. The digest recorded when the backup was written is the only proof
// that the backup still carries the bytes this transaction captured: a backup
// replaced after the crash is refused, and refusing it up front keeps the
// rollback from restoring some records and then failing on another, which
// would leave the configuration half old and half new.
func (t *fileTransaction) verifyBackups() error {
	for i := len(t.journal) - 1; i >= 0; i-- {
		record := &t.journal[i]
		if record.Op == "publish" && record.Created {
			// Nothing was there before; the undo removes what was created
			// and reads no backup.
			continue
		}
		if record.Type == "symlink" {
			// The target lives in the record; there is no backup file.
			continue
		}
		if record.Backup == "" || record.BackupSHA256 == "" {
			continue
		}
		if record.RestoredObject != "" {
			if object, err := txObjectIdentity(record.Path); err == nil && object == record.RestoredObject {
				// The restore already ran and published its own object: the
				// backup is not read again, so it is not checked either.
				continue
			}
		}
		data, err := os.ReadFile(record.Backup)
		if err != nil {
			return fmt.Errorf("%s (%v)", record.Path, err)
		}
		if hashSHA256(data) != record.BackupSHA256 {
			return fmt.Errorf("%s (backup replaced after the crash)", record.Path)
		}
	}
	return nil
}

func (t *fileTransaction) undoRecord(record *txRecord) (err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("panic")
		}
	}()
	path := record.Path
	switch {
	case record.Op == "publish" && record.Created:
		info, statErr := os.Lstat(path)
		switch {
		case os.IsNotExist(statErr):
			// Nothing was left at the destination; just the created dirs.
		case statErr != nil:
			return statErr
		case !info.Mode().IsRegular():
			// Anything but the regular file this transaction created — a
			// directory, FIFO, socket or device — is foreign post-crash
			// state. Refuse: the rollback-failed path retains the journal
			// for an operator instead of unlinking a foreign object and
			// reporting a clean rollback.
			return fmt.Errorf("created destination replaced by %s", fileTypeLabel(info.Mode()))
		default:
			if err := os.Remove(path); err != nil {
				return err
			}
		}
		for _, directory := range record.CreatedDirs {
			if err := os.Remove(directory); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
		return nil
	case record.Op == "delete" || record.Existed:
		return t.restoreRecord(record)
	}
	return fmt.Errorf("unknown journal record")
}

// fileTypeLabel names what actually sits at a destination for rollback
// failure details: only the type, never contents.
func fileTypeLabel(mode os.FileMode) string {
	switch {
	case mode&os.ModeSymlink != 0:
		return "a symlink"
	case mode.IsDir():
		return "a directory"
	case mode&os.ModeNamedPipe != 0:
		return "a FIFO"
	case mode&os.ModeSocket != 0:
		return "a socket"
	case mode&os.ModeDevice != 0:
		return "a device"
	}
	return "a non-regular file"
}

// restoreRecord puts back one backed-up file with its metadata. The
// restored object is a NEW object, so its identity is journaled BEFORE the
// rename: the journal entry is durable first and names the object the
// rename will publish, so an interrupted rollback leaves a pending journal
// that recognizes its own restored file instead of refusing it as a foreign
// replacement.
func (t *fileTransaction) restoreRecord(record *txRecord) error {
	path := record.Path
	if record.Type == "symlink" {
		info, statErr := os.Lstat(path)
		switch {
		case os.IsNotExist(statErr):
		case statErr != nil:
			return statErr
		case info.Mode()&os.ModeSymlink != 0:
			// Another link sits where the journaled link was: removing a
			// link destroys no foreign data.
			if err := os.Remove(path); err != nil {
				return err
			}
		default:
			// A directory, FIFO, socket or device replaced the journaled
			// link after the crash. Refuse rather than unlink it.
			return fmt.Errorf("symlink destination replaced by %s", fileTypeLabel(info.Mode()))
		}
		return os.Symlink(record.SymlinkTarget, path)
	}
	if record.Backup == "" {
		return fmt.Errorf("journal record has no backup")
	}
	// The backup restores a regular FILE. Refuse any non-regular object now
	// sitting at the destination: rename would unlink a foreign FIFO, socket
	// or device, and a directory holds foreign contents. Validation already
	// refused symlinks, so a live rollback seeing one here was raced.
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("destination replaced by %s", fileTypeLabel(info.Mode()))
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	// A rollback publishes a NEW object and journals its identity before the
	// rename. If that object is the one standing at the destination, the
	// restore already ran: restoring again would publish a second object and
	// overwrite the only record of the first one, so the recovery would no
	// longer recognize the object it finds there and would refuse its own
	// interrupted rollback forever. A restore is therefore idempotent. The
	// check comes before the backup is read: a restore that already ran does
	// not depend on what the backup file contains now.
	if record.RestoredObject != "" {
		if object, ierr := txObjectIdentity(path); ierr == nil && object == record.RestoredObject {
			return txRestoreOwnershipVerified(path, record.UID, record.GID)
		}
	}
	data, err := os.ReadFile(record.Backup)
	if err != nil {
		return err
	}
	// The backup file is the source of the bytes this rollback publishes. The
	// journal recorded the content it wrote there, so a backup that was
	// replaced after the crash is refused instead of being published over
	// the user's configuration.
	if record.BackupSHA256 != "" && hashSHA256(data) != record.BackupSHA256 {
		return fmt.Errorf("backup replaced after the crash")
	}
	mode := os.FileMode(0600)
	fmt.Sscanf(record.Mode, "%o", &mode)
	temporary, object, err := txPrepareReplace(path, data, mode)
	if err != nil {
		return err
	}
	record.RestoredObject = object
	if err := t.persist("pending"); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	if err := txCommitReplace(path, temporary); err != nil {
		return err
	}
	return txRestoreOwnershipVerified(path, record.UID, record.GID)
}

// txTempWrite sets the mode and writes the payload of a staged temporary,
// returning the FIRST failure so nothing is silently discarded. It is a
// variable so tests can force the write path to fail partway through.
var txTempWrite = func(temporary *os.File, mode os.FileMode, data []byte) error {
	if err := temporary.Chmod(mode); err != nil {
		return err
	}
	_, err := temporary.Write(data)
	return err
}

// txAtomicReplace is the original _atomic_write_bytes: a fresh 0600 temporary
// in the destination directory (no umask window, no predictable name), fsync,
// then rename over a proven-regular destination, then a durable directory.
// A chmod or write failure must abort BEFORE the rename: publishing a
// truncated or empty file and reporting success would commit a configuration
// that was never fully written.
func txAtomicReplace(destination string, data []byte, mode os.FileMode) error {
	temporary, _, err := txPrepareReplace(destination, data, mode)
	if err != nil {
		return err
	}
	return txCommitReplace(destination, temporary)
}

// txPrepareReplace writes the payload into a temporary file beside the
// destination. The temporary file is the object that will be published, so
// its identity is returned as well: the journal records it before the
// rename, and the recovery re-checks it against the object that is found at
// the path afterwards.
func txPrepareReplace(destination string, data []byte, mode os.FileMode) (string, string, error) {
	if err := platform.CheckPath(destination); err != nil {
		return "", "", controllerFileError(err)
	}
	if info, err := os.Lstat(destination); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return "", "", control("refuse-symlink-destination", exitUnverify)
	}
	temporary, err := os.CreateTemp(filepath.Dir(destination), "."+filepath.Base(destination)+"-")
	if err != nil {
		return "", "", controllerFileError(err)
	}
	name := temporary.Name()
	err = txTempWrite(temporary, mode, data)
	if err == nil {
		err = temporary.Sync()
	}
	closeErr := temporary.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(name)
		return "", "", controllerFileError(err)
	}
	object, err := txObjectIdentity(name)
	if err != nil {
		_ = os.Remove(name)
		return "", "", controllerFileError(err)
	}
	return name, object, nil
}

// txCommitReplace publishes the prepared temporary file over the destination
// and makes the rename durable.
func txCommitReplace(destination, temporary string) error {
	defer os.Remove(temporary)
	if err := os.Rename(temporary, destination); err != nil {
		return controllerFileError(err)
	}
	if err := fsyncDir(filepath.Dir(destination)); err != nil {
		return controllerFileError(err)
	}
	return nil
}

// runFileTransaction recovers previous crashes, then runs action(tx) under
// the scope's operation lock: on any error everything is rolled back for
// real, and a rollback failure replaces the original error.
func runFileTransaction(ctx context.Context, scope platform.Scope, name string, system bool, action func(*fileTransaction) (map[string]any, error)) (map[string]any, error) {
	var result map[string]any
	err := platform.WithLock(ctx, scope, func() error {
		if err := recoverTransactions(scope, system); err != nil {
			return err
		}
		tx, err := beginFileTransaction(scope, name, system)
		if err != nil {
			return err
		}
		outcome, actionErr := action(tx)
		if actionErr == nil {
			if err := tx.commit(); err != nil {
				return err
			}
			result = outcome
			return nil
		}
		if !tx.finished {
			if rollbackErr := tx.rollback(true); rollbackErr != nil {
				return rollbackErr
			}
		}
		return actionErr
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// txRestoredObject reports whether the object standing at the path is one
// that a rollback of this transaction published. A rollback writes a new
// object, so the journal has to name it: without that name the recovery
// finds bytes it recognizes at an object it does not, and the transaction
// would be blocked forever instead of being finished.
func txRestoredObject(tx *fileTransaction, path, object string) bool {
	if object == "" {
		return false
	}
	for _, step := range tx.journal {
		if step.Path == path && step.RestoredObject != "" && step.RestoredObject == object {
			return true
		}
	}
	return false
}

// recoverTransactions replays write-ahead journals left behind by crashes.
// Pending operations are rolled back unless an operator manually edited a
// published file afterwards; completed journals are cleaned up.
func recoverTransactions(scope platform.Scope, system bool) error {
	root := filepath.Join(scope.StateRoot, "backups")
	if _, err := os.Lstat(root); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return controllerFileError(err)
	}
	if err := platform.PrivateDir(root); err != nil {
		return controllerFileError(err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return controllerFileError(err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		if !txIDPattern.MatchString(name) {
			return control("transaction-journal-invalid", exitUnverify)
		}
		directory := filepath.Join(root, name)
		if err := platform.PrivateDir(directory); err != nil {
			return control("transaction-recovery-required", exitUnverify)
		}
		journalPath := filepath.Join(directory, "journal.json")
		info, err := os.Lstat(journalPath)
		if err != nil {
			if os.IsNotExist(err) {
				return control("transaction-recovery-required", exitUnverify)
			}
			return controllerFileError(err)
		}
		if info.Size() > txJournalLimit {
			return control("transaction-journal-invalid", exitUnverify)
		}
		raw, err := platform.ReadPrivate(journalPath)
		if err != nil {
			return controllerFileError(err)
		}
		var document struct {
			ID      string     `json:"id"`
			Name    string     `json:"name"`
			State   string     `json:"state"`
			Staging string     `json:"staging"`
			Journal []txRecord `json:"journal"`
		}
		if json.Unmarshal(raw, &document) != nil || document.ID != name || document.Journal == nil {
			return control("transaction-journal-invalid", exitUnverify)
		}
		if !txIDPattern.MatchString(document.ID) || !txNamePattern.MatchString(document.Name) {
			return control("transaction-journal-invalid", exitUnverify)
		}
		// The journal's staging field is untrusted: a forged journal must
		// never steer cleanup at a directory it names itself. Only the one
		// location beginFileTransaction can create — a direct child of the
		// scope's staging root prefixed with the transaction id — is ever
		// eligible for removal, and it must be a plain directory.
		staging, err := txValidatedStaging(scope, document.Staging, document.ID)
		if err != nil {
			return err
		}
		switch document.State {
		case "pending", "committed", "restored":
		default:
			return control("transaction-journal-invalid", exitUnverify)
		}
		tx := &fileTransaction{
			scope: scope, system: system, id: document.ID, name: document.Name,
			staging: staging, backupRoot: directory,
			journal: document.Journal, journalOnly: true,
		}
		for _, record := range tx.journal {
			if record.Op != "publish" && record.Op != "delete" {
				return control("transaction-journal-invalid", exitUnverify)
			}
			if err := tx.checkDestination(record.Path); err != nil {
				return err
			}
			if record.Backup != "" {
				saved := record.Backup
				if filepath.Dir(saved) != directory {
					return control("transaction-journal-invalid", exitUnverify)
				}
				if info, err := os.Lstat(saved); err == nil && info.Mode()&os.ModeSymlink != 0 {
					return control("transaction-journal-invalid", exitUnverify)
				}
			}
			for _, created := range record.CreatedDirs {
				if rel, err := filepath.Rel(created, record.Path); err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
					return control("transaction-journal-invalid", exitUnverify)
				}
			}
		}
		if document.State == "pending" {
			// Type preflight across EVERY destination before anything is
			// undone: only a regular file (or nothing) at a journaled path
			// is state this transaction can faithfully restore or remove.
			// A directory, FIFO, socket or device appeared after the crash
			// and is foreign; refusing before the first reverse mutation
			// means a later record's foreign object can never follow a
			// partial undo of earlier records. Lstat only — a FIFO must
			// never be opened, so nothing here can block. checkDestination
			// has already refused symlinks during validation, so whatever
			// non-regular object is found now is genuinely foreign.
			for _, record := range tx.journal {
				info, err := os.Lstat(record.Path)
				if err != nil {
					if os.IsNotExist(err) {
						continue
					}
					return controllerFileError(err)
				}
				if !info.Mode().IsRegular() {
					return &controlError{
						code: "rollback-failed",
						rc:   exitUnverify,
						safeDetail: fmt.Sprintf(
							"could not restore: %s (destination replaced by %s); unfinished transaction retained",
							record.Path, fileTypeLabel(info.Mode())),
					}
				}
			}
			// Refuse to overwrite an unrelated manual edit made after a crash.
			latest := map[string]txRecord{}
			for _, record := range tx.journal {
				latest[record.Path] = record
			}
			for path := range latest {
				info, err := os.Lstat(path)
				if err != nil || !info.Mode().IsRegular() {
					continue
				}
				current, err := os.ReadFile(path)
				if err != nil {
					continue
				}
				digest := hashSHA256(current)
				expected := map[string]bool{}
				previousDigest := ""
				for _, step := range tx.journal {
					if step.Path == path {
						if step.PublishedSHA256 != "" {
							expected[step.PublishedSHA256] = true
						}
						if step.Backup != "" {
							// The journal records the content it wrote into
							// the backup, so the preflight compares the file
							// at the path against a fact from the journal
							// and not against whatever the backup file
							// happens to contain now.
							previous := step.BackupSHA256
							if previous == "" {
								if saved, err := os.ReadFile(step.Backup); err == nil {
									previous = hashSHA256(saved)
								}
							}
							if previous != "" {
								expected[previous] = true
								previousDigest = previous
							}
						}
					}
				}
				if !expected[digest] {
					return control("transaction-current-drifted", exitUnverify)
				}
				// Identical bytes are not proof that the file at the path
				// is still an object this transaction owns. The recorded
				// content says which object belongs there: the published
				// one when the replacement already ran, the previous one
				// when it never did. The recorded identity must match, so
				// a replacement carrying the same bytes is refused
				// instead of being undone as if it were our own file.
				rec := latest[path]
				if rec.PrevObject == "" && rec.PublishedObject == "" && rec.RestoredObject == "" {
					// A journal written before identities were recorded
					// keeps the content-only preflight.
					continue
				}
				object, oerr := txObjectIdentity(path)
				if oerr != nil {
					return control("transaction-current-drifted", exitUnverify)
				}
				// A rollback publishes a NEW object, so a rollback that was
				// interrupted after restoring a file leaves an object at the
				// path that neither the published nor the previous identity
				// names. The journal names it, and the recovery recognizes
				// its own work instead of refusing the transaction forever.
				// The check comes first: that object is the one the rollback
				// published, and the previous object it replaced was freed by
				// the publication, so it must not stay a candidate.
				if txRestoredObject(tx, path, object) {
					continue
				}
				candidates := map[string]bool{}
				if rec.PublishedSHA256 != "" && rec.PublishedSHA256 != previousDigest {
					if rec.PublishedSHA256 == digest {
						candidates[rec.PublishedObject] = true
					} else {
						candidates[rec.PrevObject] = true
					}
				} else {
					// The published content equals the previous content, so
					// the two objects cannot be told apart by the bytes.
					candidates[rec.PrevObject] = true
					candidates[rec.PublishedObject] = true
				}
				if !candidates[object] {
					return control("transaction-current-drifted", exitUnverify)
				}
			}
			if err := tx.rollback(true); err != nil {
				return err
			}
			continue
		}
		tx.cleanup()
	}
	return nil
}

// txValidatedStaging re-derives the only staging location recovery may touch:
// a plain directory directly inside the scope's staging root whose name
// starts with the transaction id. Anything else the journal claims — an
// arbitrary path, an escaping prefix, a symlink — is refused before any
// cleanup can run. A missing directory removes nothing and is accepted.
func txValidatedStaging(scope platform.Scope, recorded, id string) (string, error) {
	if recorded == "" {
		return "", nil
	}
	cleaned := filepath.Clean(recorded)
	base := filepath.Base(cleaned)
	if filepath.Dir(cleaned) != filepath.Join(scope.StateRoot, "staging") ||
		!strings.HasPrefix(base, id+"-") || len(base) <= len(id)+1 ||
		!txNamePattern.MatchString(base) {
		return "", control("transaction-journal-invalid", exitUnverify)
	}
	info, err := os.Lstat(cleaned)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", controllerFileError(err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", control("transaction-journal-invalid", exitUnverify)
	}
	return cleaned, nil
}
