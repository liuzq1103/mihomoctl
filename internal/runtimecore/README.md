# Native runtime implementation

`Run(context.Context, platform.App, platform.Request)` and `Handles([]string)`
provide the native runtime command surface. Core download/install/update and
release handling belong to the delivery package. No Python interpreter, legacy
shell loader, or Python-managed installation is consulted or migrated.

Private routing/TUI callers can use
`CommitAndStart(ctx, app, configPath, before, after) (map[string]any, error)`
without holding the scope lock. It acquires the lock, recovers pending work,
checks the reviewed base, forbids security-envelope changes, validates the core,
and durably saves/restarts or starts the runtime. Only verified process/socket
health and an unchanged published candidate permit success. A pending restart
receipt is cleared transactionally and restored on failure. Candidate activation
failure restores the original configuration and running/stopped state, including
after interruption. It is a private helper, not an additional public command.

`NewLogRedactor(app) (func(string) string, error)` resolves an immutable secret
snapshot once for a streaming client, including all configured profile password
files. The returned function reads no files per line and is safe for concurrent
callers. If creation fails, a client must drop log messages rather than fall back
to unredacted output. Recreate the snapshot when creating a new source client.

`Journal(ctx, app, since, until, lines) (platform.Envelope, error)` is the private
history API. It checks scope and runtime/unit ownership and returns redacted
`data.entries`. Journal time arguments use separate `--since=`/`--until=` argv
values, with bounded length and control-character rejection. Process history
filters timestamped records; unavailable timestamp formats fail explicitly.
CLI logs returns the same entries contract. Snapshots and follow streams redact
configured sensitive values recursively, URL userinfo, sensitive query values,
and control characters, with a 4096-character output bound per entry. Follow
buffers incomplete lines so credentials split across writes cannot leak, and
drops oversized raw lines as a whole. `Request.JSON` plus follow is rejected
before output. Local binary/journal/log readers use regular-file checks and
Linux `O_NOFOLLOW|O_NONBLOCK` opens, so FIFOs cannot hang recovery or history.

The manager document uses version 1, with `core`, `default_profile`, `profiles`,
`bindings`, `tun`, and `allow_non_loopback` fields. All paths, service names,
accounts, receipts, and process state belong to `mihomoctl-go`. Retired commands
are not recognized. `rollback` intentionally returns
`historical-rollback-disabled`, matching the v1.5.1 public behavior.

Runtime mutations use the shared scope lock. Its descriptor is marked close-on-exec
locally so a child cannot retain the lock after manager death. File and compound
transactions live in persistent state, retain private original bytes and runtime
intent, and recover before another mutation. Readers refuse outstanding journals.
The package registers its recovery callback as `runtimecore`, order 20, with
`platform.RegisterRecovery`. It restores compound state then file transactions
inside the coordinator's existing lock without reacquiring it. Its pending
predicate inspects only persistent `StateRoot/compound.json` and
`StateRoot/transaction.json`. Routing recovery must register at an earlier order
so paired journals restore their shared files in the right sequence. Command
integration tests cover runtime recovery triggered by a routing handler and
paired routing/runtime snapshots of the same file.
Adoption, reset, and TUN changes commit only after their required runtime effects.
An interrupted change restores the original files, reloads owned definitions,
restarts a previously running runtime, and re-verifies TUN ownership and routes.
Recovery can itself be interrupted and replayed. A successful reset still leaves
the runtime stopped, as intended. Generated listener ports can be reassigned only while the initial
configuration still matches its private generation receipt; explicit and edited
ports remain pinned. Process identity includes PID, UID, boot ID, procfs start
time, executable, and argv. Linux stop uses pidfds and refuses kernels without
pidfd support instead of falling back to an unsafe PID-only signal.

Health checks require process socket ownership, anonymous HTTP rejection,
authenticated HTTP acceptance, anonymous SOCKS rejection, authenticated SOCKS
acceptance, and both anonymous and authenticated controller results. Egress is
optional. Exec requires local health and uses `execve`; direct removes only the
eight proxy variables and also uses `execve`.
Local probes allow up to five seconds per response, matching the original
reader timeout. The default startup budget remains ten seconds. A real child
regression delays its authenticated HEAD response for four seconds and must
still pass the default startup gate.

Systemd installation never enables a service, starts it, changes linger, or
restarts consuming application units. Existing unit text, loaded definitions,
drop-ins, and integration receipt hashes are checked before operating on them.
System scope uses a dedicated `mihomoctl-go` account and exposes only the
service-owned core directory through a systemd bind mount at
`/run/mihomoctl-go-core`. Canonical and staged system core configurations are
root-owned 0640 with the service GID. A nested read-only bind mount protects the
staged configuration while keeping the manager and credential roots private.
Root-private cores installed by delivery are validated through an isolated
executable copy after dropping privilege. Systemd hides the private data root
with a read-only tmpfs in its mount namespace, exposes the service-owned home
at `/run/mihomoctl-go-core`, and binds a reviewed,
root-owned read-only executable at the original configured path. The source
binary and private host ancestor permissions are preserved.
TUN changes require explicit system scope, a running
owned service, an authorization receipt, kernel file-descriptor ownership,
device identity, and observed routes. Foreign network devices are never deleted.

Validation runs the supplied core in an isolated temporary directory with
sanitized environment and an unprivileged identity. Provider paths cannot escape
the managed home; cached resources are copied into staging. Core diagnostic
output is discarded. Private export files are 0600. Integration install/remove
requires unchanged artifacts matching a private receipt, not a marker alone.

Launch intent, an unpredictable nonce, the executable digest, UID, boot identity,
and exact argv are persisted before child creation. Recovery verifies the nonce
in procfs and rechecks process identity before signalling through pidfds. This
also finds a child whose parent was killed before publishing `runtime.json`.
The persistent scope comparison tolerates a new runtime directory after reboot.
Foreign file edits, executable changes, PIDs, definitions, and devices stop
recovery and retain its journal; no foreign network device is removed.

Geodata uses streaming binary copies with a 128 MiB per-file cap, providers use
8 MiB, executable fingerprints use 256 MiB, and staged validation resources have
a combined 512 MiB cap. The six original geodata filenames are matched without
case sensitivity. Source hashes are checked again after validation. Binary data
does not pass through the 16 MiB YAML reader. File and compound journal metadata
have separate bounded readers (64 and 128 MiB) for base64 snapshots of multiple
YAML documents.

Custom adapters are private `adapters/NAME.json` documents (JSON or YAML), with
exact fields `format: 1`, `kind`, and `template`. The v1.5.1 placeholder allowlist,
64 Ki-character template bound, namespace host requirement, standalone literal
quoting, Unicode JSON escaping, and Supervisor escaping are preserved. Templates
are data and never executed. Export without flags previews redacted artifacts;
`--output-dir` writes real credentials privately, while `--reveal` controls the
display independently. `core list` accepts delivery's `receipt.json` format 1,
requires the `mihomoctl-go` project identity, and checks its binary digest.

## Verification and host requirements

The Windows package tests and vet checks pass. The Linux Go 1.23.12 test suite
runs from a private user-home source copy as an unprivileged WSL user. It exercises actual child executables,
HTTP/SOCKS/controller sockets, PID identity, socket ownership, pidfd stopping,
lock contention, isolated validation, failed-init publication, generated-port
collision recovery, live core adoption and recovery, reset stale proofs and
repair, private exports, receipt drift, file journal recovery, and exec exit and
signal semantics. SIGKILL tests cover each durable adoption/reset checkpoint,
unpublished children, changed runtime directories, commit markers, foreign-edit
refusal, and interruption during recovery. Adapter and resource tests cover
redaction, combined reveal/output, schema and placeholder errors, data-only
escaping, 20 MiB binary geodata, aggregate and role limits, special files,
symlinks, and large multi-document file journal recovery. Linux amd64 and arm64
compile successfully.

The test core is a purpose-built child executable, not upstream Mihomo. A
privileged test host with a running systemd manager and `/dev/net/tun` is still
needed to verify service activation and TUN transitions end to end. The root-owned
file recovery tests use controlled systemd/kernel boundaries and verify replay
ordering, retained journals after failed TUN verification, repeated recovery,
and committing a newly observed interface index. They do not change host
accounts, services, devices, capabilities, or routes. This WSL environment has no
running systemd manager; no end-to-end service/TUN activation is claimed. `migrate`
supports inspection and an explicit `--apply --no-import` no-op; requests to
import Python state or remove its shell loader fail with
`python-migration-disabled`.

## Required privileged CI suite

`TestPrivilegedSystemdTunAndSSH` is intended for a fresh disposable Ubuntu
GitHub VM, outside a job container. It requires PID 1 to be systemd, euid 0,
`/dev/net/tun`, a reviewed real Mihomo executable, and `systemctl`, `ip`,
`useradd`, `userdel`, `groupdel`, `chpasswd`, `runuser`, `ssh`, `sshd`, and `ssh-keygen`
(install `openssh-server` in the CI setup). No tests download a core.

The required job should build the test executable and run exactly this entry
point with opt-in explicitly set, for example:

```sh
go test -c -o "$RUNNER_TEMP/runtimecore-privileged.test" ./internal/runtimecore
sudo -n env MIHOMOCTL_GO_PRIVILEGED=1 \
  MIHOMOCTL_GO_TEST_CORE="$REVIEWED_MIHOMO_BINARY" \
  "$RUNNER_TEMP/runtimecore-privileged.test" \
  -test.run='^TestPrivilegedSystemdTunAndSSH$' -test.v -test.timeout=5m
```

An unset opt-in skips this destructive-host test in ordinary unit jobs. Once
`MIHOMOCTL_GO_PRIVILEGED=1` is set, missing root, systemd, the real core, tools,
or TUN cause a failure, never a skip. A separate negative test verifies this
guard. Release must require the privileged job's successful exit, not accept an
ordinary unit job in which the privileged suite was skipped. Workflow files are
outside this package's ownership; the job above must be wired into the required
CI/release checks by the workflow owner.

The suite refuses existing `/etc/mihomoctl-go`, `/var/lib/mihomoctl-go`,
`/var/cache/mihomoctl-go`, `/run/mihomoctl-go`, the fixed unit/drop-ins,
the `mihomoctl-go` account, or an existing `mihomo0`. It claims a private receipt
in the fixed system scope and creates two independent disposable non-root UIDs.
Executable fixtures select an existing trusted parent from `/opt`,
`/usr/local/lib`, `/usr/lib`, `/etc`, or `/`. Every ancestor must be root-owned,
non-symlinked, and not writable by group or others before a disposable child is
created. Hosted-image directories such as `/usr/local/lib` or `/opt` are skipped
when they fail these checks; their ownership and permissions are never changed.
The executable trust check remains strict. Isolated root tests reproduce both a
writable parent and a safe-looking leaf below a writable ancestor, and verify
that selection falls back without modifying foreign directories.
It checks concurrent user runtimes, different listener ports, private
credentials and cross-UID refusal, then installs/starts/checks the real system
service. An isolated loopback sshd and generated public keys verify both users'
SSH sessions and exec/direct environments before and during real TUN operation.
Witnessed SIGKILL checkpoints interrupt TUN enable and disable; subsequent mutations
must restore the previous running service and verified kernel device/routes.
The rapid transition tests reset only the owned unit's start-limit counter;
they do not weaken the installed unit's normal rate limit. Finally the suite
disables TUN, stops/checks the service, exercises an interrupted stopped-system
reset and malformed-config repair, uninstalls the service, and removes only
receipt-owned fixtures. It never enables a service or changes the host SSH
configuration. Failure to prove cleanup ownership retains the namespace and
fails the test. Run only one such suite per disposable VM.
