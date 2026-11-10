# Changelog

## 0.2.0 — 2026-11-10

- The compound recovery keeps the proof of every object it published. A crash
  between the file publication and the journal that binds it is closed: the
  identities the file journal names are taken over into the compound journal
  before the file journal is discarded, so discarding it can no longer destroy
  the only record of what was published, and an interrupted recovery leaves a
  journal that still tells a published object from a foreign replacement. The
  identity check runs whenever the journal names an object at all, including
  the one it replaced, so a foreign replacement carrying identical bytes is
  refused (`compound-file-conflict`) instead of being overwritten or deleted
  as if it were the operation's own file. The recovery never touches a foreign
  object: a path whose recorded original content already stands on it —
  whether the operation never reached it or an operator restored the bytes —
  is left exactly as it stands, because there is nothing left to undo there.
  A rollback publishes its restored objects into the compound journal before
  the rename as well. Records written before this protocol bound objects stay
  usable under the guarantee they were written with.

- A lost install root no longer leaves a dead launcher behind. The receipt is
  copied outside the program root when an installation is published, so an
  installation whose root was deleted or lost still names its launcher:
  `installation status` reports `orphaned` instead of `not-installed`, and a
  later install or uninstall removes the leftover launcher by identity —
  never a foreign replacement carrying identical bytes — instead of refusing
  every later installation with `installation-command-exists`. When the
  installation moves to a different directory, the repair covers only the
  recorded launcher: a requested destination that already holds a foreign
  command is refused (`installation-command-exists`) before anything is
  removed or published — removing the recorded launcher and then failing to
  link over the foreign file would leave a half-installed root behind a
  journal no recovery can finish. A record from
  before the receipt bound the launcher object is not unconditional deletion
  authority either: it keeps the content guarantee it was written with, so a
  launcher that still hashes to the recorded digest is ours and any other
  object at the path is foreign and never removed. An installation that
  predates the copy gets one the next time the installer sees it — from
  bootstrap and from the update path alike — and a receipt
  that becomes unreadable while the installer is reporting an already
  installed program is reported instead of a success the copy was silently
  skipped for. A missing launcher is not drift: an uninstall of an
  installation whose launcher was deleted still removes the program root,
  because nothing at the path means nothing foreign to refuse and nothing to
  delete.

- The managed configuration and the compound service files are bound by object
  identity across every rollback path. The recovery verified each destination
  before undoing it; the immediate rollback that runs in-process when a later
  publication fails now refuses a path whose object the journal does not name
  (`transaction-conflict`) instead of overwriting or removing whatever stands
  there — including a path the transaction created. Records written before
  identities were journaled keep the guarantee they were written with.

- An installation published by the previous protocol is still recognized as
  already installed. Its receipt carries no installation id and no launcher
  object; the installer verifies it under the guarantee that receipt was
  written with — content, exactly as the release that wrote it did — and
  writes the external record for it, so a later loss of the program root
  stays detectable and repairable instead of wedging on a surviving launcher.

- A percent sign in a managed core path is rendered correctly in the unit.
  The path-list settings (`TemporaryFileSystem=`, `BindPaths=`,
  `BindReadOnlyPaths=`, `ReadWritePaths=`) keep it literal, because systemd
  does not expand specifiers there (verified on systemd 249 and 255: the
  mount resolves to the literal path, and a doubled percent sign would point
  at a different directory), while the command line escapes it as `%%`,
  because systemd expands specifiers there and an unknown one makes the unit
  fail to load. The privileged acceptance now adopts a core that lives at a
  path containing a percent sign and starts it, so both renderings are proven
  against the real systemd of both supported releases.

- First publication now uses a write-ahead journal: the staged tree, the launcher and
  the receipt are written and flushed before the install root is published, so a
  crash at any publication window leaves a recoverable record instead of a
  half-installed program. The launcher is published by exclusive hard link and by
  `renameat2(RENAME_NOREPLACE)`; a foreign launcher is never adopted, replaced or
  deleted. Recovery verifies the staged tree byte for byte, including inode, device,
  mode and SHA-256. Installing again over an installation this project owns
  reports `already_installed` instead of refusing. A publication whose objects are
  gone is rolled back instead of refusing every later command, and a filesystem
  that cannot publish the root atomically is reported as
  `bootstrap-publish-unsupported` with the staged tree and journal discarded.
  A publication whose staged launcher is removed before it can be linked can
  never be completed, because the receipt binds the exact launcher object and a
  replacement carrying identical bytes is a different object; the recovery
  rolls that publication back, removing the published root and the journal,
  instead of retaining a half-installed program that no command can roll back
  or clear. The rollback renames the published root out of the way before it
  removes it, so an interrupted rollback leaves a private directory the next
  recovery finishes, never a partly removed tree at the published path that
  would fail the inventory check for good. The staged tree is renamed out of
  the way before it is removed too, so an interruption during the rollback of
  a never-published installation resumes the same way instead of leaving a
  partly deleted staged tree that no recovery could finish. A filesystem that
  cannot publish the launcher at all — it refuses hard links outright, with
  `EOPNOTSUPP`, `EPERM`, `EXDEV` or the like — fails after the root is
  already public, and every later recovery would retry the same impossible
  link forever; such a publication is rolled back with
  `bootstrap-launcher-link-unsupported` instead of wedging the scope, while
  failures an operator can fix without a new installation (permissions,
  space, a read-only mount) stay retryable with the journal retained.

- Full program uninstall now quarantines the receipt-bound installation atomically,
  journals exact file ownership outside the program root, and resumes interrupted
  deletion without touching replacement installations. The removal journal is
  flushed to disk before the program root is renamed into the quarantine, so a
  power loss can never leave a quarantined tree behind without the journal that
  describes it. Every journalled object is bound by device and inode as well as
  content hash, and the launcher is bound by
  identity too, so a replacement file carrying identical bytes is refused instead
  of being deleted as program-owned. It is idempotent and permits
  reinstall. Corrupt status fails; only true absence reports not-installed.
  Configuration and independent cores remain; uninstall refuses configured cores
  located inside program generations, and equally refuses a manager that points
  the active configuration or profile credentials into the program tree
  (`uninstall-config-inside-program-root`) instead of deleting them with the
  generation. The installation receipt now binds the launcher object itself by
  device and inode, so a launcher replaced by a file carrying identical bytes is
  a foreign object: the uninstall refuses it (`uninstall-launcher-drift`) and the
  installation status no longer reports it as valid.

- A preview never replays a recovery journal. The subscription preview — the
  command-line one and the guided console input alike — refuses a pending
  recovery instead of replaying it, exactly as a dry run does, and the scope lock
  it takes does not recover: replaying a journal would replace the live
  configuration the preview describes, and a description is not a repair. Only an
  authorized mutation, or an explicit `installation recover`, replays a journal.
  The apply path still recovers before its first configuration read, so a plan
  is always validated against the state it describes.

- An abandoned publication removes only the objects its journal inventoried.
  The interrupted rollback — the private `.install-abandoned-<token>` tree — is
  resumed object by object, and an object the journal never recorded is
  foreign: it survives the removal, the private directory keeps it, and the
  scope stays usable instead of being wedged by a refusal. An inventoried
  object that cannot be observed — a filesystem error, not a verdict that the
  object is foreign — fails the abandonment and keeps the journal, instead of
  being skipped as foreign and reporting success while an owned object is
  still on disk.

- The rollback checks every backup before it undoes anything. A backup that was
  replaced after the crash fails the whole rollback before the first restore,
  so a transaction can no longer restore one file and then fail on another and
  leave a mixed old/new configuration behind with the journal retained.

- A health check that cannot read the socket table reports the listener state as
  unavailable. It never reports a confirmed "not listening" for an observation
  that was never made.

- Configuration file transactions preflight the type of every journalled
  destination before the first undo. A path replaced by a directory, FIFO, socket
  or device makes the rollback fail with `rollback-failed` and keeps the journal,
  instead of partially undoing earlier records and then removing a foreign object.
  A failed write aborts before the rename, so a truncated file is never published.
  The journal also binds every destination by device and inode, and the recorded
  content decides which object belongs at the path — the published one when the
  replacement already ran, the previous one when it never did. Capturing that
  identity is an observation like any other: a filesystem error during the
  capture fails the publication before anything is journaled, instead of
  writing a record that names the object it will publish but not the object it
  replaces — a crash before the rename in that state would leave a recovery
  that refuses the intact original on every retry. The runtime's file and
  compound snapshot captures refuse identically. A foreign
  replacement that carries identical bytes is therefore refused
  (`transaction-current-drifted`) instead of being overwritten or deleted as if
  it were the transaction's own file. A transaction that publishes the same
  path more than once still rolls back: the ownership check accepts every
  object the journal names at the path through any of its records, so the
  object a later record's restore published is recognized as the
  transaction's own intermediate state instead of refusing it and wedging
  the scope with a journal every retry fails on identically. The live rollback — a later operation
  fails and the transaction is rolled back in the same process, without the
  recovery's verification pass first — owes the same protection: a path whose
  object the journal does not name fails the rollback (`rollback-failed`)
  instead of being overwritten with the backup, and a foreign object on a
  path the transaction created is not deleted. The ownership of every
  destination is verified before anything is undone, exactly as the backups
  are, so a foreign replacement of an earlier record cannot leave a mixed
  old/new configuration behind after the later files were already restored.
  The same preflight verifies the CONTENT of every destination against the
  bytes the journal recorded, because an in-place edit of our own object
  keeps its device and inode and is invisible to the identity check:
  overwriting such an edit with the backup — or deleting the edited file on
  a path the transaction created — would destroy a concurrent writer's
  configuration change, so the rollback refuses (`rollback-failed`) and
  retains its journal instead. The runtime's file transactions owe the
  identical protection on their immediate rollback: every destination's
  object AND content is verified before the first undo, and an in-place edit
  is refused with `transaction-conflict` instead of being restored over or
  deleted, the same rule the crash recovery already ran. A rollback writes new objects, so the
  journal names them before the rename as well: a rollback interrupted between
  restoring a file and finishing leaves a journal that recognizes its own
  restored object, and the recovery resumes the transaction instead of refusing
  it forever. A foreign replacement carrying the restored bytes is still
  refused after such an interruption.
  A rollback is idempotent: a restore that already published its object is
  recognized by the journal and never publishes a second one, so the record of
  the first publication is not overwritten by the recovery that follows it. The
  backup a rollback restores is compared against the digest recorded when the
  backup was written, so a backup replaced after the crash fails the rollback
  (`rollback-failed`) instead of deciding what is written over the user's
  configuration.

- State recorded before this project bound its objects stays usable under the
  guarantee it was written with. A receipt that names no launcher object is
  verified by content, exactly as the release that wrote it verified it; every
  receipt this project writes binds the launcher object itself. A removal
  journal written before the removal inventory was bound cannot be finished
  under this protocol and is refused with `uninstall-legacy-journal` and a
  documented manual remediation, instead of guessing at leftover state.

- The managed configuration and the compound service files are bound by object
  identity as well as by content. A replacement that carries identical bytes is
  a different object and is refused (`transaction-conflict`,
  `compound-file-conflict`) instead of being adopted as the managed file.

- A publication is only reported as successful once the directory entry that
  carries it has been flushed. A directory that cannot be flushed is reported
  as a failure instead of being ignored, so a write that cannot confirm its
  durability never discards the journal that describes it.

- An option value that looks like an option is refused, exactly as the
  reference implementation refuses it. A lone `-` and a negative number are
  values; every other option-looking token is not.

- Health checks report an evidence level (`confirmed`, `inferred`, `unavailable`)
  and a readable detail, skip listener and controller probes while the runtime is
  stopped, and read the endpoints with the five-second allowance of the reference
  implementation. A missing manager reports a structured `UNVERIFIED` result
  instead of failing, and `doctor` checks the running executable rather than a
  Python interpreter.

- Configuration errors report a line and column, duplicate and invalid keys are
  distinguished, and every failure envelope carries a remediation hint. Unknown
  options and retired commands are refused with the same command grouping and
  option lists as the reference implementation. A refusal is reported under the
  requested command word, as the reference implementation reports it. A dry run
  never enters the mutation lock and therefore never replays a recovery journal.

- Release bundles record their source commit and whether the source tree was
  dirty in `BUILD.json` and `build-receipt.json`. Review evidence is checked in
  with the exact reviewed candidate commit.

- The system-scope service stages the reviewed core into its private binary
  directory once and keeps that copy's inode while the copy still carries
  exactly the reviewed bytes. Re-staging an identical core no longer replaces
  the executable of a running core, so the kernel no longer reports
  `/proc/<pid>/exe` with a ` (deleted)` suffix and the fail-closed identity
  proof no longer rejects the process it has just verified
  (`systemd-identity-unverified`, `systemd-transition-unverified`). Helper
  tools such as `ip` and `journalctl` are resolved once before they run, so
  distributions that ship them as symlinks into a merged `/usr` no longer fail
  every device and route check with `symlink-refused` and `tun enable` can
  succeed. The reviewed core itself still has to be a regular file.
  A system core whose path contains a space is quoted per path in the unit's path
  lists (`TemporaryFileSystem=`, `BindPaths=`, `BindReadOnlyPaths=`,
  `ReadWritePaths=`), because systemd splits those lists on whitespace and a
  quoted pair would hide the `:` that separates source and destination. A path
  that systemd cannot express at all is refused instead of producing a unit that
  cannot start. A unit file an earlier development build of this project
  rendered under the previous quoting is still recognized as this project's
  own for the manager it was written for, so an upgrade across those builds
  keeps managing — and can uninstall — the service it installed; the next
  rewrite publishes the current rendering.

- Independent native Go project `mihomoctl-go`, repository `liuzq1103/mihomoctl`, command `mihomoctl`.
- Bounded official-host release downloads with explicit caller-reviewed SHA-256 for acquisition and latest updates. Remote unsigned checksums are consistency evidence, not independent trust.
- Managed installation receipt, exact manifest inventories, immutable generations, atomic activation record, failure rollback and recovery journal. Updates preserve runtime configuration and active core paths.
- Explicit core install/update stages immutable candidates; activation uses the runtime `core adopt` command. Reviewed amd64 pins are inherited verbatim from mihomo-userctl v1.5.1; the v1.19.33 arm64 pin was independently verified by the coordinator through the official GitHub API on 2026-11-05. Local `--asset` and builder `-core-cache` allow strict offline acquisition with identical digest checks.
- Go source/basic release builder and offline bundles with pinned core, optional local dashboard/geodata inputs. No Python runtime or build tooling.
- Linux CI and draft-only candidate workflow require independent review before manual public publication. Local builds are not acceptance evidence for unavailable platforms.
