# Changelog

## 0.2.0 — unreleased

- Independent native Go project `mihomoctl-go`, repository `liuzq1103/mihomoctl`, command `mihomoctl`.
- Bounded official-host release downloads with explicit caller-reviewed SHA-256 for acquisition and latest updates. Remote unsigned checksums are consistency evidence, not independent trust.
- Managed installation receipt, exact manifest inventories, immutable generations, atomic activation record, failure rollback and recovery journal. Updates preserve runtime configuration and active core paths.
- Explicit core install/update stages immutable candidates; activation uses the runtime `core adopt` command. Reviewed amd64 pins are inherited verbatim from mihomo-userctl v1.5.1; the v1.19.33 arm64 pin was independently verified by the coordinator through the official GitHub API on 2026-11-05. Local `--asset` and builder `-core-cache` allow strict offline acquisition with identical digest checks.
- Go source/basic release builder and offline bundles with pinned core, optional local dashboard/geodata inputs. No Python runtime or build tooling.
- Linux CI and draft-only candidate workflow require independent review before manual public publication. Local builds are not acceptance evidence for unavailable platforms.
