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
configuration or start services; its result gives the bundled core path for explicit init/adopt.

Check a bundle with `go run ./scripts/verifyrelease -archive BUNDLE -sha256 REVIEWED_HASH`.
Use `-execute` only for explicitly reviewed native inputs; this verifies actual CLI
and core version execution. Cross-building does not constitute architecture acceptance.

The owned launcher executes `install/generations/<id>/bin/mihomoctl`, selecting its
generation from the atomically replaced private `install/current` file. It is not
a symlink. The private receipt binds the exact launcher path and bytes. The update
journal records the old/new manifest hashes. Before a switch, all payload bytes
are staged, hashed, fsynced and inventoried; after an interrupted switch, recovery
validates the selected generation and either finishes or restores the intact old
generation. Ambiguous/corrupt journals are retained and refused. Previous generations
are retained. No historical rollback/pruning is implemented here. Uninstall removes
only the owned launcher, retaining data and generations deliberately.

CI runs race/vet/full-package tests and product CLI/bundle smoke on Ubuntu 22.04
and 24.04, amd64 natively and arm64 via explicit QEMU Ubuntu containers. The draft
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
