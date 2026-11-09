# Delivery verification record — 2026-11-06

This record supersedes the earlier partial delivery report and the failed d92373b
uninstall review. It records local checks; it does not assert a completed CI matrix,
model review, or public release.

Implemented program uninstall:

- A private journal outside the program root binds the exact receipt SHA-256,
  current generation/manifest, complete validated file inventory, device/inode,
  and a unique quarantine path. New installations have unique receipt identities.
- Before deletion, the owned installation root is atomically renamed to that
  quarantine. Recovery deletes only captured unchanged files. It rejects foreign
  modifications, symlinks, special files and replacement installations.
- Recovery is idempotent across journal publication, root quarantine, launcher
  deletion, partial file deletion and complete program-root deletion. Bootstrap
  recovers or refuses outstanding uninstall state before installing new code.
- Status reports not-installed only for true absence; existing corrupt or drifted
  installations fail. Pending valid deletion reports recovery required. Public
  installation recover returns a nonnil data object.
- Configuration, independent cores and runtime state remain. Uninstall refuses
  configured/adopted or recorded running cores inside program generations, with
  an actionable error. Bootstrap labels its bundled core as program-owned.
- Delivery registers recovery/pending callbacks at order 30 in the shared scope
  coordinator. Callbacks never take a nested lock.

Local checks completed:

- Full project tests and vet passed. Delivery and release-tool race tests passed
  on the Windows host using cgo/MinGW.
- The complete delivery suite executed natively in Ubuntu 22.04 WSL, including
  TestLinuxBootstrapAndUninstall (not skipped), all five deletion interruption
  points, old-journal/new-install conflicts with identical code, foreign bytes/
  files/symlinks, corrupt status, configured/adopted core refusal, repeat uninstall,
  reinstall, and shared update/uninstall recovery coordination.
- The real pinned Mihomo v1.19.33 amd64 bundle smoke passed: init/start with a
  bundled core; uninstall refusal preserving its running PID and executable;
  explicit adoption into independent core storage; controller generation switch
  preserving the independent core PID/configuration; full program uninstall;
  status not-installed; repeat uninstall; reinstall; a second full uninstall.
  The native compiled helper installs/recovers without Go or Python on the target.
- Both reviewed amd64/arm64 core archives matched their pins. Basic and offline
  candidates for both architectures were built and had all SHA-256 inventories
  verified. Native amd64 CLI/core probes passed; arm64 native execution was not
  available locally.
- The extracted source archive passed full tests and vet as a standalone project.
  Embedded package assets are included; local inputs, validation artifacts and
  generated .test/.exe binaries are excluded.
- Archive traversal/link/special-file rejection, nonblocking FIFO refusal,
  bounded/cancelled transfers, official-host redirects, pinned cache integrity,
  version probes, update rollback/recovery, and legacy version JSON fields passed.

CI changes and remaining external acceptance:

- Ubuntu 22.04/24.04 arm64 jobs run on GitHub's native arm runners, covering
  normal tests, real CLI/core smoke and race. An earlier QEMU-based gate was
  removed: qemu-user does not give a multi-threaded guest a stable /proc start
  time, so the kernel ownership proof fails closed under emulation and
  emulation cannot gate the release.
- Privileged core inputs stage in a fresh root-owned /root directory; no arbitrary
  system directories have their trust permissions weakened.
- Both Ubuntu privileged jobs compile and explicitly opt in to the actual
  TestPrivilegedSystemdTunAndSSH (two UIDs, SSH, systemd, TUN, crash recovery),
  require that named test to exist and explicitly pass, verify fixture cleanup,
  then run system installation smoke. WSL lacks the privileged systemd environment.
  Those jobs must still pass on CI.
- The draft gate requires the exact GPT, GLM and MiniMax approved profiles, the
  same full candidate SHA, completed PASS records and checked-in report digests.
  Evidence remains pending. No human approval environment or automatic public
  publication was added. Source and asset reviews must be rerun for the final fix.

Generated local candidates and logs live under ignored scripts/.validation/.
They are review artifacts; no commit, push, draft or public release was performed
by this delivery task.
