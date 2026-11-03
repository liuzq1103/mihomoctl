# mihomoctl — mihomo 交互式终端控制台(Go TUI)

mihomo(Clash.Meta 内核)的交互式终端控制台:**零第三方依赖**的单包 Go 程序,
以 htop 同款立即模式渲染技术提供十个页面的实时查看与操控。

- **快速读路径**(版本/流量/分组/节点/连接/规则/日志流)直连 mihomo 控制器 REST API;
- **事务性变更**(订阅应用、服务启停、健康检查、诊断等)全部经配套的 `mihomoctl --json`
  Python CLI 子进程执行,复用其审计过的安全逻辑;
- 双缓冲字符网格 + 单元格 diff,未变化的帧输出 0 字节,按键永不被 I/O 阻塞。

> **平台要求**:交互模式仅支持 **Linux 终端**(termios)。Windows / macOS 可正常编译,
> 但只支持 headless 用法(`-render` 单帧输出、`go test`);进入交互模式会得到
> `tui-requires-linux-terminal` 错误。

## 前置条件

- Linux 终端(交互模式);
- mihomo 运行中,且控制器配置满足(程序强制校验,不满足直接拒绝启动):
  - `external-controller` 绑定**回环地址**(127.0.0.1 / [::1]);
  - `secret` 为 32–256 位 URL-safe 令牌;
- 配套 Python CLI `mihomoctl` 在 PATH(或用 `-mihomoctl` 指定路径)。

`-demo` 模式使用合成数据,无需以上任何依赖即可体验全部页面。

## 安装

**Release 二进制**(推荐):从 [Releases](https://github.com/liuzq1103/mihomoctl/releases)
下载对应架构的压缩包:

```sh
tar xzf mihomoctl-tui-v*-linux-amd64.tar.gz
chmod +x mihomoctl-tui
./mihomoctl-tui -demo    # 合成数据体验
./mihomoctl-tui          # 连接真实控制器
```

**go install**(需 Go ≥ 1.23):

```sh
go install github.com/liuzq1103/mihomoctl@latest
```

注意:`go install` 生成的二进制名为 `mihomoctl`,与前置的 Python CLI 同名;
若两者同机使用,建议重命名为 `mihomoctl-tui`,或直接使用 Release 二进制。

**源码构建**(交叉编译,产物为静态二进制约 7 MB):

```sh
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o mihomoctl-tui .
```

## 用法

```sh
./mihomoctl-tui                                  # 读取 ~/.config/mihomo/config.yaml 并连接
./mihomoctl-tui -config /path/to/config.yaml     # 指定 mihomo 配置
./mihomoctl-tui -page proxies                    # 指定初始页
./mihomoctl-tui -demo                            # 合成数据演示
./mihomoctl-tui -mihomoctl /path/to/mihomoctl    # 指定 Python CLI 路径
go run . -render -demo -page logs -width 120 -height 40   # 无 tty 单帧输出
```

| 旗标 | 说明 |
|---|---|
| `-config` | mihomo 配置路径,默认 `$XDG_CONFIG_HOME/mihomo/config.yaml` |
| `-page` | 初始页面,默认 overview |
| `-demo` | 使用合成数据,不连真实控制器 |
| `-render` | 渲染单帧到 stdout 后退出(无需 tty,可进 CI 断言) |
| `-mihomoctl` | 事务操作所用的 Python CLI,默认 PATH 中的 `mihomoctl` |
| `-width` / `-height` | `-render` 模式尺寸,默认 100×30 |

## 页面与按键

| 页 | 快捷键 | 数据来源 |
|---|---|---|
| 首页 overview | 1 | 控制器 API 直连(版本/模式/流量/内存/分组/最近连接) |
| 节点 proxies | 2 | API 直连:双栏分组/节点、选择、单点/批量测速(8 并发,可 cancel) |
| 订阅 subscriptions | 3 | `u` 输入 URL → 预览 → `y` 保存并启动(URL 只存内存,经 stdin 传给 CLI);`f` 文件;`p` 策略切换 |
| 连接 connections | 4 | API 直连,过滤/排序 |
| 规则 rules | 5 | API 直连 + `: rules-check` / `rules-status` |
| 日志 logs | 6 | `/logs` 流式订阅,暂停/过滤/滚动 |
| 接入 profile | 7 | `profiles` + `integration list` + `env show`(只读,脱敏) |
| 提供商 providers | 8 | API `/providers/proxies` + `/providers/rules`,Enter 刷新 |
| 诊断 diagnostics | 9 | `h` health / `d` doctor / `j` journal / `u` diagnose url / `: diagnose process PID` |
| 服务 runtime | 0 | `mihomoctl status --json` 运行时事实 |

```
通用:Tab/Shift+Tab 切页或切栏 | ↑↓ 移动 | Enter 确认 | / 过滤 | r 刷新 | v 上次结果 | : 命令 | q 退出
节点:t 测速 | T 批量(8 并发) | s 排序 | [ ] 换组 | Tab 切换分组/节点栏
订阅:u 输入 URL | f 选择文件 | p 切换策略 | y 保存并启动
诊断:h health | d doctor | j journal | u diagnose url
```

**`:` 命令**:`page` / `mode` / `start` / `stop` / `restart` / `init` / `dns` /
`provider` / `journal` / `chain` / `cancel` / `health` / `doctor` / `status` /
`rules-status` / `rules-check` / `release check` / `version` / `core list` /
`tun status` / `config validate` / `migrate --dry-run` / `reset --dry-run` /
`profiles` / `env show`;
**任何其他命令原样透传给 `mihomoctl --json` 并渲染信封**——命令面因此完整。
`exec/direct/update/rollback` 留在 Shell(与原 Textual 控制台一致)。

行为已对齐上游 Python CLI v1.4.3 / v1.5.1:批量测速 8 并发、上限 1000;
提供商节点带 `[provider]` 标识并走专属 healthcheck 路由,同名节点按
(name, provider) 区分;连接页列为目标/协议/链路/规则/上传/下载。

## 安全设计

- 控制器地址强制回环、secret 强度强制校验,不满足即拒绝启动;
- API 客户端强制校验 401(凭据错误立刻失败,绝不静默降级);
- 订阅私有 URL 不进 argv、不落盘:UI 直连下载(不走代理)后经 stdin 交给 CLI;
- 进程诊断只显示代理环境变量**是否存在**,永不显示其值。

## 与 Python 版(Textual 控制台)的已知差异

- 订阅策略无 "simple"(引导式);用 auto/provider/nodes/policy 四档,auto 等价引导判断;
- 日志流离开页面后继续接收(上限 1000 行),原版会停止流;
- `theme` / `log-level` 命令未移植(单一暗色主题;日志 level 固定 info);
- `manual` / `override` / `health-check`(探测设置调整)无专用页面,可经透传执行;
- 连接页列宽固定,窄终端截断;`/` 过滤作用于节点/连接/日志页,其余页面暂不生效。

## 已知限制(v0.1.0)

- 批量测速 `: cancel` 后,已在途的探测会继续完成(最长约 5 秒)才停止派发;
- CLI 子进程超时(120 s)只终止直接子进程,其拉起的后台服务不受影响;stdout 超过 16 MB 会被拒绝;
- 订阅下载器接受 http/https URL(令牌会出现在 URL 中,请务必使用 https 订阅地址);
- `go install` 产出的二进制名与前置 Python CLI 同名,见「安装」节的说明。

## 测试

```sh
go test ./...                              # 单元 + 基准
go run . -render -demo -page <页>          # 无 tty 渲染,可进 CI 断言
```

基准:100×40 中文全帧 69µs、单格 diff 31µs(60fps 预算 16ms)。
**CI 断言注意**:交互渲染是逐格 diff,除首帧外字符串在字节流中不连续——
断言必须用 `-render` 输出或终端模拟器重建屏幕,不能用原始字节子串。

## 许可证

[MIT](LICENSE)
