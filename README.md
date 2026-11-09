# mihomoctl：独立的 Go Mihomo 管理工具

面向共享 Linux 服务器的 Go 命令行与十页终端控制台。两者调用同一套原生服务，不调用 Python。功能参照 `mihomo-userctl v1.5.1`，但这是独立项目：`mihomoctl-go`，仓库 `liuzq1103/mihomoctl`，命令名 `mihomoctl`。

**0.2.0 已发布。** [English](README.en.md) · [逐项行为与验收索引](https://github.com/liuzq1103/mihomoctl/blob/main/docs/feature-parity.md)

## 构建与首次使用

构建需要 Go 1.23 或更新版本；安装后的程序不需要 Go 或 Python。实际进程、systemd 与 TUN 功能面向 Linux；其他平台的编译、单元测试和无终端演示不代表 Linux 运行验收通过。

```sh
go build -trimpath -o mihomoctl .
./mihomoctl --help
./mihomoctl version --json
./mihomoctl init --core /absolute/path/to/trusted/mihomo --json
./mihomoctl start --json
./mihomoctl tui
./mihomoctl tui --plain
./mihomoctl -demo -render -page overview
```

`init` 必须显式指定可信核心，只创建私有配置，不下载或启动核心。交互式首次准备可以使用经过校验的包内核心或可信 PATH 核心；已有配置损坏时不会静默重置。

## 命名空间与安全边界

用户配置遵循 XDG 目录，使用 `mihomoctl-go` 子目录。系统目录为 `/etc/mihomoctl-go`、`/var/lib/mihomoctl-go`、`/var/cache/mihomoctl-go`、`/run/mihomoctl-go`；服务与系统账号名为 `mihomoctl-go`。root 修改系统状态必须显式使用全局 `--system`，放在命令之前。程序不会自行提权、修改 shell 启动文件或导入 Python 项目状态。两套项目的命令都叫 `mihomoctl`，并存时请使用绝对路径。

```sh
mihomoctl status --json
mihomoctl profile list --json
mihomoctl env show --json
mihomoctl exec -- command args
mihomoctl direct -- command args
mihomoctl subscription preview --source-file /private/subscription.yaml --policy auto --json
mihomoctl subscription apply PREVIEW_ID --sha256 REVIEWED_HASH --json
```

订阅先预览，再用预览摘要应用。`subscription apply` 保存配置，不代表运行中的核心已经采用新配置；需要显式重启。私有订阅地址通过私有文件、标准输入或遮蔽输入提供，不要放进命令行。默认输出脱敏，`--reveal` 和连接的 `--details` 是显式披露选项。`exec` 仅在本地健康检查通过后向子进程注入代理变量，`direct` 清除子进程的代理变量；子命令参数放在 `--` 后。

JSON 使用 `mihomoctl/v1` 信封。`version` 保留原有的 `mihomoctl`、`schema`、可空的 `core` 字段，并补充 `version`、`project` 等信息；未初始化时也能查询。控制器桥接的兼容载荷保留在 `data.legacy`。

## 终端界面

控制台支持深浅主题、ASCII、日志级别、筛选、配置选项、订阅预览和断线提示。`?` 查看帮助，`:` 打开命令输入，`/` 筛选，`o` 打开选项，`q` 退出。交互式操作可能修改配置或运行状态；自动化应使用显式 CLI 命令。

```sh
mihomoctl tui --theme light --ascii
mihomoctl -demo
mihomoctl -render -demo -page logs -width 90 -height 20
```

兼容旧的 `-page/-config/-demo/-render/-width/-height/-mihomoctl` 参数；`-mihomoctl` 不再启动外部 CLI。`curses`、`textual` 引擎名称映射到 Go 控制台，`plain` 使用任务菜单。可信 JavaScript 覆盖是可选功能，需要 Node.js，只允许用户作用域；Node vm 不是安全沙箱。系统作用域拒绝执行这类脚本。

## 安装、更新与卸载

先独立核验并解压二进制发行包，再在包目录执行以下命令。源码目录不等同于可安装二进制包，安装脚本使用随包程序，不要求 Go 工具链。

```sh
sh ./install.sh --bin-dir "$HOME/.local/bin"
"$HOME/.local/bin/mihomoctl" installation status --json
mihomoctl update /absolute/path/to/reviewed/bundle --dry-run --json
mihomoctl release check --json
```

安装拒绝覆盖已有外来命令。更新要求受管安装收据，验证清单后原子切换程序版本，并保留活动核心。在线 `release fetch` 和 `update --latest` 必须提供独立审阅的 `--sha256`，`--kind basic|offline` 选择包种类；远程未签名摘要和 API 元数据本身不建立信任。离线核心可用 `core install --version v1.19.33 --asset /absolute/path/to/reviewed/core.gz` 暂存，随后显式 `core adopt --path /absolute/path/to/independent/core` 激活。

`installation uninstall` 只移除收据所属的启动器和程序安装树，保留配置、独立核心与运行状态。若配置或记录中的运行核心位于程序安装树内，卸载会拒绝；请先安装并采用独立核心。管理文档把活动配置或档案凭据指到程序安装树内同样会被拒绝，因为这些文件必须保留。卸载恢复使用收据绑定的隔离目录，拒绝外来文件与内容漂移。`installation recover` 用于完成待处理事务；不要把它当成历史版本回滚。`rollback` 明确返回不支持。Python 的 wheel、wheelhouse、extras、解释器选择和旧配置导入不属于本项目，相关参数或迁移行为被拒绝。

## 验证与发布状态

```sh
go test ./...
go vet ./...
CGO_ENABLED=1 go test -race ./...
```

真实核心测试使用 `MIHOMOCTL_GO_TEST_CORE=/trusted/path/to/mihomo`。发布验收还需要 Ubuntu 22.04/24.04、amd64/arm64 实际执行、真实核心、隔离的 systemd/TUN/SSH 与两个非 root UID 检查，以及终端交互证据。arm64 QEMU 下 ThreadSanitizer 的 VMA 限制不算通过；race 在 amd64 执行，arm64 常规测试和真实核心仍须实际运行。

当前不宣称全部平台、特权测试或模型审阅已经通过。同一候选 SHA 必须有 GPT、GLM、MiniMax 三个模型家族的真实完成审阅和签入的证据，再由自动流程构建草稿；不增加人工审批环境。公开发布仍需独立审阅实际资产，候选版本不是已发布版本。跳过、配额不足或失败的模型调用不能算批准。逐项证据和缺口见[验收索引](docs/feature-parity.md)。

控制器代码采用 [MIT](LICENSE)；随包 Mihomo 核心单独采用 GPL-3.0，离线包应附带其许可证和来源信息。