# Delivery verification record — 2026-11-05

Overall: delivery-focused checks passed; final shared-root source/build acceptance
is incomplete. No commit, push, draft creation, or public release was performed.

Verified locally:

- `go test ./internal/delivery ./scripts/...`, focused `go vet`, and focused
  `go test -race` passed. Race used cgo with the installed MinGW compiler.
- The compiled delivery suite ran natively in Ubuntu 22.04 WSL: archive traversal,
  symlink/hardlink/special-file rejection, duplicate JSON/inventory checks, bounded
  transfers, redirected-host refusal, cache digest/architecture checks, version
  probes, managed-receipt checks, both injected update failure boundaries, and
  recovery before/after activation and with corrupt/conflicting journals passed.
- Real official v1.19.33 amd64 and arm64 compressed core assets matched the
  recorded reviewed pins. Both architectures' basic/offline candidates were built;
  all four exact manifest inventories and outer checksums were verified. Native
  amd64 CLI/core version execution passed. Arm64 native execution was not available.
- Real amd64 offline bundle installation and the public product commands
  installation status/recover, core list, init, config validate, start, update,
  stop and uninstall passed in a temporary private WSL user scope. An actual
  offline-to-basic generation switch preserved manager/core hashes and the real
  running core's PID. The smoke redirected proxies to an unreachable loopback
  endpoint; core acquisition used the local pinned gzip.
- Legacy `version` keys `mihomoctl`, `schema`, and nullable `core` are preserved
  alongside the new fields. Linux tests confirm a trusted configured core reports
  its first version line, missing/untrusted binaries become null, and manager bytes
  remain unchanged. `release check` retains the original keys and numeric Unix
  `checked_at`.
- Workflow YAML and shell syntax checks passed. The pending checked-in review
  evidence was rejected as intended. Gate tests reject three GPT reviews, missing
  families, arbitrary labels, candidate mismatch, incomplete reviews and report
  hash mismatch. Only the three exact approved model profiles are supported.

Concrete packaging findings and fixes:

- Standalone source testing found missing routing `dashboard.html`; the builder
  now copies embedded package assets. A second inspection found agent-generated
  `.test` binaries under internal; source copies now exclude `.test` and `.exe`.
  Regression tests cover both cases.
- The final rebuild after those fixes is blocked outside delivery: the latest
  observed root `native_source.go` uses `time.Second` without importing `time`.
  An earlier full run also failed `TestPickerReturnsToTheParentLevel` (four
  returned items). Those shared-root files were not modified by this task.
  Earlier full-suite/vet passes and earlier candidate execution do not establish
  acceptance of the final moving shared worktree. Rebuild and independently test
  the extracted source archive once the root owner completes its edits.

Required external acceptance remains:

- Ubuntu 24.04 and arm64 execution (the CI matrix explicitly runs arm64 under QEMU).
- Actual privileged systemd/TUN/two-UID/SSH/crash-recovery acceptance on both Ubuntu
  versions. Both workflows now compile `runtimecore` tests, install SSH/iproute
  prerequisites, derive a root-owned core from the pinned gzip, and run exactly
  `TestPrivilegedSystemdTunAndSSH` with explicit opt-in. The wrapper requires the
  named test to exist and emit an explicit PASS, then checks receipt-bound fixture
  cleanup before running system installation smoke. WSL lacks the necessary
  privileged systemd environment; no local PASS is claimed.
- Actual GPT/GLM/MiniMax source reports for an exact candidate commit and later
  asset reviews. `.github/release-evidence.json` intentionally remains pending.
  There is no human approval environment and no automatic public publication.
- No external geodata/dashboard payloads were available for pinning. Optional
  locally reviewed inputs are supported and inventoried; their availability is
  not claimed by the produced core-complete bundles. The application embeds its
  own dashboard HTML independently.

Generated local candidates and test binaries are under ignored
`scripts/.validation/`. They are worktree verification artifacts, not reviewed
publication assets. Use a fresh output directory after final source review.
