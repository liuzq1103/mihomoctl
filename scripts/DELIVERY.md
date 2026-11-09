# Delivery contract and review procedure

`internal/delivery` is independent of the Python project. The only inherited
inputs are the original reviewed amd64 `mihomo-digests.json` pins and the upstream
core license. Their provenance is retained verbatim. A v1.19.33 arm64 pin was added
after the coordinator verified the official GitHub release API through the GitHub
connector on 2026-11-05 (recorded asset size 20824326). No signature verification
is claimed. Never promote the digest returned by a remote request into a new
reviewed pin automatically.

The public CLI must expose:

- `version` (retains `data.mihomoctl`, `data.schema`, nullable `data.core`, adds `data.version`).
- `release check` (stable metadata observation only).
- `release fetch --output-dir ABSOLUTE --sha256 HEX [--version vX.Y.Z] [--kind basic|offline] [--target linux-amd64|linux-arm64]`.
  Legacy `linux-x86_64` and `linux-aarch64` targets are aliases. Python kit targets are refused.
- `update [SOURCE] [--source SOURCE] [--latest] [--sha256 HEX] [--dry-run] [--reinstall|--allow-same-version] [--allow-downgrade]`.
  `--latest` requires an independently reviewed `--sha256`. Directory/archive sources are caller-selected trusted local inputs;
  hashes in their manifest establish consistency only. All updates, including previews, require a managed receipt.
- `core install|update --version vX.Y.Z [--sha256 HEX] [--asset LOCAL_GZIP] [--dry-run]`.
  Unknown version/architecture combinations require a caller-reviewed digest. Installation publishes an immutable candidate,
  never switches the manager or overwrites an active core. `core adopt --path` handles explicit activation in runtimecore.
- `installation install --source DIRECTORY [--bin-dir DIRECTORY] [--dry-run]`;
  `installation status`; `installation recover`; `installation uninstall [--dry-run]`.

The helper `scripts/deliveryctl` provides that delivery-only grammar for bundle
installation and recovery. `install.sh` executes the shipped native helper, so
neither Go nor Python is needed on the target. System installs require explicit
`--system`; user mutation refuses root. Run shell scripts with `sh` after reviewing
the complete bundle and independently checking its outer SHA-256.

Build candidates with `go run ./scripts/release -arch amd64,arm64 -out OUTPUT`.
Add `-offline` for core-complete amd64/arm64 bundles. The default pinned core is
v1.19.33. Every architecture needs its own reviewed pin. The builder refuses
unreviewed combinations before building partial output. It never substitutes
the amd64 core or auto-trusts an API digest.

`-core-cache DIRECTORY` disables core network acquisition and requires either
the canonical asset name from the pin table or `mihomo-linux-amd64.gz` /
`mihomo-linux-arm64.gz` under that directory. Missing or mismatched input is a
hard failure, with no network fallback. `PrepareCoreFromFile` exposes this path
to Go callers; the CLI exposes it as `core install|update --asset FILE`.

`-optional-inputs DIRECTORY` accepts only locally reviewed `dashboard/` and/or
`geodata/` directories; every included byte enters the exact manifest inventory.
No such payloads are supplied by the reference project's assets directory. Bundles
without them must not claim dashboard/geodata availability. Any config requiring
those resources still needs separately reviewed inputs. An offline bundle includes
the native CLI, native installer/recovery helper, reviewed core and original pinned gzip (so binary/asset correspondence can be rechecked), license/provenance,
install/uninstall scripts, and exact manifest. Installation does not initialize
configuration or start services. Its result labels the bundled core as program-owned.
For an independent core that survives program uninstall, use
`mihomoctl core install --version v1.19.33 --asset /BUNDLE/core/CANONICAL_ASSET.gz`,
then explicitly init/adopt the returned path under managed `cores/` storage.
Uninstall refuses a configured/adopted core inside program generations, preserves
its executable and returns an actionable error; it never silently deletes that core.
The same protection covers the active configuration and the profile credentials:
a manager pointing `core.config` or a profile `credentials_file` into the program
tree is refused with `uninstall-config-inside-program-root` instead of losing those
files with the deleted generation.

Check a bundle with `go run ./scripts/verifyrelease -archive BUNDLE -sha256 REVIEWED_HASH`.
Use `-execute` only for explicitly reviewed native inputs; this verifies actual CLI
and core version execution. Cross-building does not constitute architecture acceptance.

Every bundle includes `BUILD.json` with the full source commit and an explicit
dirty-worktree flag, covered by its manifest inventory. The source archive and
external `build-receipt.json` carry the same provenance. Official candidates must
be built from the exact clean reviewed commit. Chinese/English usage, installation
instructions, the command parity matrix and acceptance record accompany bundles.

All previews, including program install/uninstall and service uninstall dry runs,
are read-only. They refuse pending recovery instead of replaying journals. A real
mutation or explicit `installation recover` performs recovery under the scope lock.
An existing foreign launcher is never adopted, replaced or deleted; choose a
different `--bin-dir` when another project owns the command there.

Log output fails closed when a referenced credentials file is missing, unsafe or
unreadable. This avoids exposing historical credentials whose values cannot be
loaded for redaction. Restore the private credential file or repair the profile
reference before reading CLI, journal or live console logs.

The owned launcher executes `install/generations/<id>/bin/mihomoctl`, selecting its
generation from the atomically replaced private `install/current` file. It is not
a symlink. The private receipt binds the exact launcher path and bytes. The update
journal records the old/new manifest hashes. Before a switch, all payload bytes
are staged, hashed, fsynced and inventoried; after an interrupted switch, recovery
validates the selected generation and either finishes or restores the intact old
generation. Ambiguous/corrupt journals are retained and refused. Previous generations
are retained until program uninstall. No historical rollback/pruning is implemented here.
Uninstall removes the owned launcher, receipt, current pointer and all program
generations. Configuration, runtime state and independent `cores/` storage remain.
A private journal outside the program root binds the exact receipt SHA-256,
current manifest identity, root inode/device, unique quarantine and complete file
inventory. Each journalled object is additionally bound by its own device/inode
pair, and the launcher is bound by identity as well as by its hash: the launcher
script is fully reproducible, so a replacement file carrying identical bytes is a
foreign file and is refused instead of deleted. The verified program root is
renamed atomically into that quarantine.
Only captured unchanged files are removed; symlinks, special files, foreign changes
and replacement installations fail closed. Recovery resumes partial deletion,
and Bootstrap recovers or refuses an outstanding journal before installing new code.
New installations receive unique receipt identities. Only true program-root absence
with no pending journal is reported as `not-installed`; corruption and drift fail.
Repeated uninstall succeeds without deleting configuration or cores, and subsequent
installation works. A bundle's native helper can recover even after its launcher
has been removed. Use an external copy of the bundle to reinstall/recover.

A structurally invalid bootstrap journal is refused rather than guessed at: the
journal is read back with `bootstrap-journal-invalid`, and because recovery is
what reads it, that state blocks every later mutation and `installation recover`
until an operator removes it. The journal lives at
`<state-root>/delivery-bootstrap.json`; `<state-root>` is `XDG_STATE_HOME` in user
scope and `/var/lib/mihomoctl-go` in system scope. The staged tree it names lives
under `<data-root>/.install-bootstrap-<token>` and the pending launcher under
`<launcher-dir>/.mihomoctl-bootstrap-<token>`. Remove the journal file and those
two directories, then install again. A staged directory left behind by an
interrupted publication is private and is never adopted and never guessed away,
so it is safe to delete once no installation is pending. Removing the journal
discards an unfinished publication; it does not delete an installed program.

A removal journal written before the removal protocol bound the inventory is
refused rather than guessed at: it is read back with `uninstall-legacy-journal`,
and because recovery is what reads it, that state blocks every later mutation
and `installation recover` until an operator removes it. Such a journal lives at
`<state-root>/delivery-uninstall.json`, and the program state the old protocol
staged lives under `<data-root>/.install-uninstall-partial`. Remove the journal
file and that directory, then install again. The old protocol copied the program
root into the staging directory before it deleted anything, so an installation
whose root was already partly removed has to be removed by hand as well; the
staged copy is private program state and is safe to delete once no removal is
pending.

A publication whose objects are gone is rolled back instead of refused. When the
staged tree and the install root are both absent, recovery removes the launcher
that this journal still owns, discards the journal and leaves the scope usable
again, so an interrupted publication never wedges every later command. When the
kernel or the filesystem cannot publish the install root atomically at all, the
staged tree and the journal are rolled back and the installation reports
`bootstrap-publish-unsupported`; no public path is changed and the attempt can
be repeated on a supported filesystem.

A publication whose staged launcher is gone before the launcher could be linked
can never be completed: the receipt binds the exact launcher object, and that
object was released together with the staging directory, so a replacement
carrying identical bytes would be a different object and would break the
binding. Recovery rolls that publication back instead of refusing every later
command: it removes the published install root, the staged launcher and the
journal, and reports `bootstrap-launcher-source-missing`. The installation has
to be run again; nothing outside the journal's own objects is touched.

CI runs race/vet/full-package tests and product CLI/bundle smoke on Ubuntu 22.04
and 24.04, both architectures on native hardware (the arm64 gate uses GitHub's
native arm runners). Race tests run on both architectures. An earlier QEMU
arm64 gate was removed: qemu-user gives a multi-threaded guest no stable /proc
start time, so the kernel ownership proof fails closed under emulation. The draft
matrix also includes privileged real-systemd amd64 jobs on both Ubuntu versions;
they fail if PID 1 is not systemd, or real core init/service/start/health cannot
be verified. These are acceptance jobs, not local evidence of a systemd pass. The draft
workflow requires checked-in `.github/release-evidence.json` for a full candidate
commit SHA, with three completed PASS records from the exact approved profiles
`gpt-6.1-sol`, `zcode/GLM-5.3[1m]`, and `minimax-cn/MiniMax-M3.1-Flash[1m]`.
Unknown labels, missing families and three GPT reviews are refused. Each record
binds the same SHA, a completion time, and a checked-in report under `.github/reviews/`
with its SHA-256. The initial file is pending and must fail the gate. No review
PASS is fabricated and no human approval environment is added. Evidence may be
committed after the reviewed source commit; the workflow separately checks out
that exact candidate for CI and builds. It creates drafts only; public publication
is a separate agent action after actual asset review.
