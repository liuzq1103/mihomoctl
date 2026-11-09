# mihomoctl: independent native Go Mihomo manager

Go CLI and ten-page terminal console for shared Linux servers. Both call the same native service. Functional reference: `mihomo-userctl v1.5.1`; this independent project is `mihomoctl-go`, repository `liuzq1103/mihomoctl`, command `mihomoctl`.

**0.2.0 is released.** [中文](README.md) · [Behavior and acceptance matrix](https://github.com/liuzq1103/mihomoctl/blob/main/docs/feature-parity.md)

Build with Go 1.23+: `go build -trimpath -o mihomoctl .`. Installed binaries need neither Go nor Python. Runtime mutations target Linux; builds, unit tests and demo rendering on other platforms do not establish Linux acceptance.

```sh
./mihomoctl --help
./mihomoctl version --json
./mihomoctl init --core /absolute/path/to/trusted/mihomo --json
./mihomoctl start --json
./mihomoctl tui
./mihomoctl tui --plain
./mihomoctl -demo -render -page overview
```

Initialization creates private configuration without downloading or starting the core. First-use interactive preparation can use a verified bundled core or trusted PATH core. Invalid existing configuration is not silently reset.

XDG directories use `mihomoctl-go`. System roots are `/etc/mihomoctl-go`, `/var/lib/mihomoctl-go`, `/var/cache/mihomoctl-go` and `/run/mihomoctl-go`; service and system account use `mihomoctl-go`. Root mutations require global `--system` before the command. The program does not elevate itself, edit shell startup files or import Python state. Use absolute paths when keeping both projects' `mihomoctl` commands.

```sh
mihomoctl status --json
mihomoctl exec -- command args
mihomoctl direct -- command args
mihomoctl subscription preview --source-file /private/subscription.yaml --policy auto --json
mihomoctl subscription apply PREVIEW_ID --sha256 REVIEWED_HASH --json
```

Subscription apply commits reviewed configuration; restart explicitly to activate it. Private URLs use masked input, stdin or private files. Output is redacted by default; `--reveal` and `connections --details` disclose information explicitly. Child arguments follow `--`; proxy variables affect that child only. JSON retains the `mihomoctl/v1` envelope. Version data retains `mihomoctl`, `schema` and nullable `core`, with added `version` and `project`; no initialization is required. Bridged controller payloads remain in `data.legacy`.

The console supports dark/light themes, ASCII, log levels, filtering and options. Use `?` for help, `:` for commands, `/` to filter, `o` for options and `q` to quit. Legacy demo/render/page flags remain accepted. `-mihomoctl` no longer launches an external CLI. Legacy curses/textual labels select the Go console; plain selects the task menu. Optional trusted JavaScript overrides need Node.js and are restricted to user scope; Node vm is not a security sandbox. Agents should use explicit CLI commands for mutations.

From a separately verified, extracted **binary bundle**, run:

```sh
sh ./install.sh --bin-dir "$HOME/.local/bin"
"$HOME/.local/bin/mihomoctl" installation status --json
mihomoctl update /absolute/path/to/reviewed/bundle --dry-run --json
mihomoctl release check --json
```

The installer invokes shipped binaries without a Go toolchain and refuses foreign launchers. Updates require a managed receipt, verify the manifest and switch program generations atomically while preserving the active core. Online acquisition requires a separately reviewed `--sha256`; `--kind basic|offline` selects the bundle. An unsigned checksum or metadata response is not an upstream signature or independent review. `core install --version v1.19.33 --asset /absolute/path/to/reviewed/core.gz` stages an offline core; adoption is a separate explicit action.

Program uninstall removes only receipt-owned program artifacts, preserving configuration, independent cores and runtime state. It refuses if the configured or recorded running core lives inside program generations: install and adopt an independent core first. Recovery uses receipt-bound quarantine and refuses foreign changes. `installation recover` handles unfinished transactions; historical `rollback` is rejected. Python wheels, wheelhouses, extras, interpreter selection and legacy-state migration are intentional exclusions.

Run `go test ./...`, `go vet ./...` and `CGO_ENABLED=1 go test -race ./...`. Set `MIHOMOCTL_GO_TEST_CORE` for real-core tests. Acceptance still requires Ubuntu 22.04/24.04 amd64/arm64 execution, privileged systemd/TUN/SSH checks with two non-root UIDs, and terminal evidence. QEMU arm64 ThreadSanitizer VMA incompatibility is not a pass: race runs on amd64; ordinary arm64 tests and real-core execution remain required.

Do not infer platform or model passes from this documentation. Draft creation requires CI and checked-in evidence for the same candidate SHA from completed GPT, GLM and MiniMax family reviews, without an added human-approval environment. Public publication follows independent review of the actual assets. Skips, quota failures and failed model calls are not approvals. See the [matrix](docs/feature-parity.md) for named cases and gaps.

Controller code: [MIT](LICENSE). Bundled Mihomo is separately licensed GPL-3.0; offline bundles carry its license and source provenance.