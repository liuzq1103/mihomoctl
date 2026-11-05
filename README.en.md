# mihomoctl ? independent native Go Mihomo manager

Go CLI and ten-page terminal console for shared Linux servers. Both call the same native service; neither invokes Python. Functional baseline: `mihomo-userctl v1.5.1`. The projects remain independent.

**0.2.0 is an unreleased acceptance candidate.** [??](README.md) ? [Parity index](docs/feature-parity.md)

Build with Go 1.23+: `go build -trimpath -o mihomoctl .`. Linux supports the full runtime; other platforms support builds, tests and headless demo rendering. Trusted JavaScript overrides optionally require Node.js.

```sh
./mihomoctl --help
./mihomoctl init --core /absolute/path/to/mihomo --json
./mihomoctl start --json
./mihomoctl tui
./mihomoctl tui --plain
./mihomoctl -demo -render -page overview
```

Initialization creates private configuration without downloading or starting the core. First-use interactive preparation can use a verified bundled core or a trusted `mihomo` on PATH. Existing invalid configuration is never silently reset.

XDG directories, service units and system accounts use `mihomoctl-go`. System roots are `/etc/mihomoctl-go`, `/var/lib/mihomoctl-go`, `/var/cache/mihomoctl-go` and `/run/mihomoctl-go`; the unit is `mihomoctl-go.service`. Root mutations require explicit `--system`. Python state is never imported or adopted. Because both commands are called `mihomoctl`, use absolute paths when keeping both installations.

```sh
mihomoctl status --json
mihomoctl exec -- command args
mihomoctl direct -- command args
mihomoctl subscription preview --source-file /private/subscription.yaml --policy auto --json
mihomoctl subscription apply PREVIEW_ID --sha256 REVIEWED_HASH --json
```

Subscription apply commits the reviewed configuration; restart explicitly to activate it. Private URLs use interactive input, stdin or a private URL file. Output is redacted unless explicitly requested with `--reveal`. Child arguments follow `--`.

The console supports dark/light themes, ASCII, log levels, guided subscriptions, filtering and disconnected-state recovery. Use `?` for help, `:` for commands and `o` for options. Legacy demo/render/page flags remain accepted. The old external CLI path flag no longer launches another program. Legacy curses/textual engine names select the Go console; plain selects the task menu.

Verify and extract a release bundle, then run `sh install.sh --user`. Installation does not start the core or overwrite a foreign command. Uninstall removes only receipt-owned program artifacts and preserves runtime configuration and core. Local updates use `mihomoctl update /absolute/reviewed/bundle --dry-run`; online acquisition requires a separately reviewed SHA-256. Hash verification is not an upstream digital signature. Python packaging options are explicitly rejected.

Run `go test ./...`, `go vet ./...` and Linux `CGO_ENABLED=1 go test -race ./...`. Set `MIHOMOCTL_GO_TEST_CORE` for real-core validation. Release acceptance requires Ubuntu 22.04/24.04 amd64/arm64 execution, isolated privileged checks, independent GPT/GLM/MiniMax reviews of the candidate commit and actual release assets. Skips and failed model calls are not approvals.

Controller code: [MIT](LICENSE). Bundled Mihomo is separately licensed GPL-3.0; its license and source provenance accompany offline bundles.
