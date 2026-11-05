# v1.5.1 ?????????

???`liuzq1103/mihomo-userctl`?tag `v1.5.1`??? `f33204dd5e0c7a52d2df4df4d9aa3188b2e7f385`?

?? 70 ???????????? `internal/command/spec.json`??? 4 ? Go ?????????????????????????????????????????????????????

| ?? | ???? | ???? |
|---|---|---|
| `init` | runtimecore | internal/runtimecore/*_test.go |
| `start` | runtimecore | internal/runtimecore/*_test.go |
| `stop` | runtimecore | internal/runtimecore/*_test.go |
| `restart` | runtimecore | internal/runtimecore/*_test.go |
| `status` | runtimecore | internal/runtimecore/*_test.go |
| `logs` | runtimecore | internal/runtimecore/*_test.go |
| `config validate` | runtimecore | internal/runtimecore/*_test.go |
| `config check` | runtimecore | internal/runtimecore/*_test.go |
| `profile list` | runtimecore | internal/runtimecore/*_test.go |
| `profile show` | runtimecore | internal/runtimecore/*_test.go |
| `profile validate` | runtimecore | internal/runtimecore/*_test.go |
| `profile set-default` | runtimecore | internal/runtimecore/*_test.go |
| `env show` | runtimecore | internal/runtimecore/*_test.go |
| `env export` | runtimecore | internal/runtimecore/*_test.go |
| `exec` | runtimecore | internal/runtimecore/*_test.go |
| `direct` | runtimecore | internal/runtimecore/*_test.go |
| `integration list` | runtimecore | internal/runtimecore/*_test.go |
| `integration show` | runtimecore | internal/runtimecore/*_test.go |
| `integration check` | runtimecore | internal/runtimecore/*_test.go |
| `integration export` | runtimecore | internal/runtimecore/*_test.go |
| `integration install` | runtimecore | internal/runtimecore/*_test.go |
| `integration remove` | runtimecore | internal/runtimecore/*_test.go |
| `service install` | runtimecore | internal/runtimecore/*_test.go |
| `service start` | runtimecore | internal/runtimecore/*_test.go |
| `service stop` | runtimecore | internal/runtimecore/*_test.go |
| `service restart` | runtimecore | internal/runtimecore/*_test.go |
| `service status` | runtimecore | internal/runtimecore/*_test.go |
| `service uninstall` | runtimecore | internal/runtimecore/*_test.go |
| `tun status` | runtimecore | internal/runtimecore/*_test.go |
| `tun enable` | runtimecore | internal/runtimecore/*_test.go |
| `tun disable` | runtimecore | internal/runtimecore/*_test.go |
| `core install` | delivery | internal/delivery/*_test.go |
| `core update` | delivery | internal/delivery/*_test.go |
| `core adopt` | runtimecore | internal/runtimecore/*_test.go |
| `core list` | runtimecore | internal/runtimecore/*_test.go |
| `health` | runtimecore | internal/runtimecore/*_test.go |
| `doctor` | runtimecore | internal/runtimecore/*_test.go |
| `migrate` | runtimecore | internal/runtimecore/*_test.go |
| `reset` | runtimecore | internal/runtimecore/*_test.go |
| `rollback` | runtimecore | internal/runtimecore/*_test.go |
| `release check` | delivery | internal/delivery/*_test.go |
| `release fetch` | delivery | internal/delivery/*_test.go |
| `update` | delivery | internal/delivery/*_test.go |
| `rules status` | routing | internal/routing/*_test.go |
| `rules check` | routing | internal/routing/*_test.go |
| `version` | delivery | internal/delivery/*_test.go |
| `profiles` | runtimecore | internal/runtimecore/*_test.go |
| `export` | runtimecore | internal/runtimecore/*_test.go |
| `controller status` | routing | internal/routing/*_test.go |
| `controller initialize` | routing | internal/routing/*_test.go |
| `controller setup` | routing | internal/routing/*_test.go |
| `controller token` | routing | internal/routing/*_test.go |
| `nodes` | routing | internal/routing/*_test.go |
| `groups` | routing | internal/routing/*_test.go |
| `select` | routing | internal/routing/*_test.go |
| `latency` | routing | internal/routing/*_test.go |
| `connections` | routing | internal/routing/*_test.go |
| `traffic` | routing | internal/routing/*_test.go |
| `subscription preview` | routing | internal/routing/*_test.go |
| `subscription apply` | routing | internal/routing/*_test.go |
| `tui` | TUI | tui_parity_test.go / tui_plain_test.go / PTY |
| `providers` | routing | internal/routing/*_test.go |
| `provider refresh` | routing | internal/routing/*_test.go |
| `dns` | routing | internal/routing/*_test.go |
| `mode` | routing | internal/routing/*_test.go |
| `health-check` | routing | internal/routing/*_test.go |
| `manual` | routing | internal/routing/*_test.go |
| `override` | routing | internal/routing/*_test.go |
| `ui` | routing | internal/routing/*_test.go |
| `dashboard` | routing | internal/routing/*_test.go |
| `installation install` | delivery | internal/delivery/*_test.go |
| `installation status` | delivery | internal/delivery/*_test.go |
| `installation recover` | delivery | internal/delivery/*_test.go |
| `installation uninstall` | delivery | internal/delivery/*_test.go |

## ???????

- ????? `mihomoctl`?????????????? `mihomoctl-go`?Python ????????????
- Python ????wheel?wheelhouse?extras ?????????????????????
- ? `curses` / `textual` ??????? Go ?????`plain` ???????
- `rollback` ?????????????????????????
- GLM/MiniMax ????????????????????????????????

## ?????????

Ubuntu 22.04/24.04?amd64/arm64 ??????? Mihomo v1.19.33?? root/root?? UID?systemd?TUN?SSH/PT Y?? Python ????????????vet?race?GPT/GLM/MiniMax ??? SHA ???????????????? PASS?
