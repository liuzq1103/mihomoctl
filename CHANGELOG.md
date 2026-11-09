# Changelog

## 0.2.0 — 2026-11-10

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
  or clear.

- Full program uninstall now quarantines the receipt-bound installation atomically,
  journals exact file ownership outside the program root, and resumes interrupted
  deletion without touching replacement installations. Every journalled object is
  bound by device and inode as well as content hash, and the launcher is bound by
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

- Configuration file transactions preflight the type of every journalled
  destination before the first undo. A path replaced by a directory, FIFO, socket
  or device makes the rollback fail with `rollback-failed` and keeps the journal,
  instead of partially undoing earlier records and then removing a foreign object.
  A failed write aborts before the rename, so a truncated file is never published.
  The journal also binds every destination by device and inode, and the recorded
  content decides which object belongs at the path — the published one when the
  replacement already ran, the previous one when it never did. A foreign
  replacement that carries identical bytes is therefore refused
  (`transaction-current-drifted`) instead of being overwritten or deleted as if
  it were the transaction's own file. A rollback writes new objects, so the
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
  cannot start.

- Independent native Go project `mihomoctl-go`, repository `liuzq1103/mihomoctl`, command `mihomoctl`.
- Bounded official-host release downloads with explicit caller-reviewed SHA-256 for acquisition and latest updates. Remote unsigned checksums are consistency evidence, not independent trust.
- Managed installation receipt, exact manifest inventories, immutable generations, atomic activation record, failure rollback and recovery journal. Updates preserve runtime configuration and active core paths.
- Explicit core install/update stages immutable candidates; activation uses the runtime `core adopt` command. Reviewed amd64 pins are inherited verbatim from mihomo-userctl v1.5.1; the v1.19.33 arm64 pin was independently verified by the coordinator through the official GitHub API on 2026-11-05. Local `--asset` and builder `-core-cache` allow strict offline acquisition with identical digest checks.
- Go source/basic release builder and offline bundles with pinned core, optional local dashboard/geodata inputs. No Python runtime or build tooling.
- Linux CI and draft-only candidate workflow require independent review before manual public publication. Local builds are not acceptance evidence for unavailable platforms.
