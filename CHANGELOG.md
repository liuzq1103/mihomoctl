# Changelog

## 0.2.0 — 2026-11-09

- First publication now uses a write-ahead journal: the staged tree, the launcher and
  the receipt are written and flushed before the install root is published, so a
  crash at any publication window leaves a recoverable record instead of a
  half-installed program. The launcher is published by exclusive hard link and by
  `renameat2(RENAME_NOREPLACE)`; a foreign launcher is never adopted, replaced or
  deleted. Recovery verifies the staged tree byte for byte, including inode, device,
  mode and SHA-256. Installing again over an installation this project owns
  reports `already_installed` instead of refusing.

- Full program uninstall now quarantines the receipt-bound installation atomically,
  journals exact file ownership outside the program root, and resumes interrupted
  deletion without touching replacement installations. It is idempotent and permits
  reinstall. Corrupt status fails; only true absence reports not-installed.
  Configuration and independent cores remain; uninstall refuses configured cores
  located inside program generations.

- Configuration file transactions preflight the type of every journalled
  destination before the first undo. A path replaced by a directory, FIFO, socket
  or device makes the rollback fail with `rollback-failed` and keeps the journal,
  instead of partially undoing earlier records and then removing a foreign object.
  A failed write aborts before the rename, so a truncated file is never published.

- Health checks report an evidence level (`confirmed`, `inferred`, `unavailable`)
  and a readable detail, skip listener and controller probes while the runtime is
  stopped, and read the endpoints with the five-second allowance of the reference
  implementation. A missing manager reports a structured `UNVERIFIED` result
  instead of failing, and `doctor` checks the running executable rather than a
  Python interpreter.

- Configuration errors report a line and column, duplicate and invalid keys are
  distinguished, and every failure envelope carries a remediation hint. Unknown
  options and retired commands are refused with the same command grouping and
  option lists as the reference implementation. A dry run never enters the
  mutation lock and therefore never replays a recovery journal.

- Release bundles record their source commit and whether the source tree was
  dirty in `BUILD.json` and `build-receipt.json`. Review evidence is checked in
  with the exact reviewed candidate commit.

- Independent native Go project `mihomoctl-go`, repository `liuzq1103/mihomoctl`, command `mihomoctl`.
- Bounded official-host release downloads with explicit caller-reviewed SHA-256 for acquisition and latest updates. Remote unsigned checksums are consistency evidence, not independent trust.
- Managed installation receipt, exact manifest inventories, immutable generations, atomic activation record, failure rollback and recovery journal. Updates preserve runtime configuration and active core paths.
- Explicit core install/update stages immutable candidates; activation uses the runtime `core adopt` command. Reviewed amd64 pins are inherited verbatim from mihomo-userctl v1.5.1; the v1.19.33 arm64 pin was independently verified by the coordinator through the official GitHub API on 2026-11-05. Local `--asset` and builder `-core-cache` allow strict offline acquisition with identical digest checks.
- Go source/basic release builder and offline bundles with pinned core, optional local dashboard/geodata inputs. No Python runtime or build tooling.
- Linux CI and draft-only candidate workflow require independent review before manual public publication. Local builds are not acceptance evidence for unavailable platforms.
