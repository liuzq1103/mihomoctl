# v1.5.1 行为与验收矩阵

固定参照：[mihomo-userctl v1.5.1 command_spec.py](https://github.com/liuzq1103/mihomo-userctl/blob/f33204dd5e0c7a52d2df4df4d9aa3188b2e7f385/mihomoctl/command_spec.py)，提交 `f33204dd5e0c7a52d2df4df4d9aa3188b2e7f385`。前 70 项对应原公开命令，后 4 项是 Go 独立安装协议；语法来源为 [spec.json](../internal/command/spec.json)。

表中的测试是**可定位的验收用例索引，不是执行通过记录**。未标特权的 Linux 生命周期测试可能使用受控核心夹具；不能替代真实 Mihomo 或 systemd/TUN/SSH 验收。“待补”表示覆盖缺口，“待平台验收”表示需要目标环境证据。仅语法、入口分派或共享辅助函数测试不证明整条命令行为。基线测试只定义参考语义，不证明 Go 实现通过。

正式发布前，这些缺口必须由对应的具名行为用例与实际运行证据关闭；测试文件出现、通用包测试通过或删除“待补”文字，都不能代替缺失的验收。

所有入口通用证据：[TestEveryContractHelpBeforeInitialization](../internal/command/parser_test.go) 检查 74 个帮助入口无需初始化；[TestEveryLeafReachesNativeImplementation](../internal/command/execute_test.go) 检查分派；[TestRejectedArgumentsDoNotLeakSecrets](../internal/command/parser_test.go) 检查拒绝及脱敏。这些不代替下列行为测试。

| 入口 | 具体行为 | 安全边界或拒绝 | 具名验收证据及缺口 |
|---|---|---|---|
| `init` | 显式可信核心初始化私有配置，不下载或启动 | 已有状态、无效核心不覆盖 | [`TestRejectedInitPublishesNothing`](../internal/runtimecore/lifecycle_linux_test.go) |
| `start` | 启动受管进程并验证认证监听 | 拒绝外来端口或 PID | [`TestNativeLifecycleAndAuthentication`](../internal/runtimecore/lifecycle_linux_test.go) |
| `stop` | 停止有身份凭据的受管进程 | 不收养或终止外来进程 | [`TestOwnershipRejectsForeignProcess`](../internal/runtimecore/lifecycle_linux_test.go) |
| `restart` | 停止并重新启动以应用配置 | 失败不能伪报运行 | [`TestNativeLifecycleAndAuthentication`](../internal/runtimecore/lifecycle_linux_test.go) |
| `status` | 报告进程与监听的所有权证据 | PID 或 socket 不匹配失败 | [`TestSocketOwnershipAndPIDIdentity`](../internal/runtimecore/lifecycle_linux_test.go) |
| `logs` | 快照或跟随受管日志，边界脱敏 | JSON follow 拒绝，先验证日志来源 | [`TestLogJSONFollowRejectedBeforeOutputAndConfigAccess`](../internal/runtimecore/logs_test.go) |
| `config validate` | 隔离验证当前或指定配置 | 不影响活动核心，错误脱敏 | [`TestValidationIsIsolatedAndErrorsRedacted`](../internal/runtimecore/lifecycle_linux_test.go) |
| `config check` | 兼容配置检查入口，成功命令名为 config-validate；报告未验证状态 | 无受管核心时只承认 YAML 解析结果，不伪报语义验证 | [`TestConfigCheckCanonicalCommandWithoutManager`](../internal/runtimecore/parity_contract_test.go)、[`TestConfigValidationSuccessContract`](../internal/runtimecore/parity_contract_linux_test.go)；分别检查未初始化与 Linux 核心夹具成功载荷；最新完整 Linux 记录两项均 PASS |
| `profile list` | 列出已声明代理配置 | 不披露凭据 | [`TestRunProfileAndRedactedEnv`](../internal/runtimecore/runtime_test.go) |
| `profile show` | 解析指定配置及监听 | 凭据不匹配拒绝 | [`TestProfileCredentialsMismatchFailsClosed`](../internal/runtimecore/runtime_test.go) |
| `profile validate` | 验证配置引用和认证信息 | 无效类型拒绝 | [`TestRunProfileAndRedactedEnv`](../internal/runtimecore/runtime_test.go) |
| `profile set-default` | 事务保存默认配置，不改已有子进程环境 | 解析成功后才保存，保留显式字段 | [`TestProfileSetDefaultNormalizesSchema`](../internal/runtimecore/parity_contract_test.go) 最新 Linux PASS；差异用例 managed-stopped/profile set-default default 与 missing 均为明确 ACCEPTED；已覆盖规范化、显式 TUN 字段及实际 CLI 的默认/缺失配置分支，不据此声称任意新增字段或另一配置切换已单独验证。基线 test_v1_domain.py::test_setting_default_profile_preserves_newer_manager_fields |
| `env show` | 显示选定配置的代理变量，默认脱敏 | 仅显式 reveal 披露 | [`TestEnvironmentEncodingAndRedaction`](../internal/runtimecore/runtime_test.go) |
| `env export` | 导出私有环境文件，不修改调用 shell | 文件权限 0600，预览不恢复事务 | [`TestExportsWritePrivateFilesAndLogsTail`](../internal/runtimecore/lifecycle_linux_test.go) |
| `exec` | 健康检查后仅向子进程注入代理变量 | 保留参数、退出及信号语义 | [`TestDirectExecPreservesExitAndSignal`](../internal/runtimecore/lifecycle_linux_test.go) |
| `direct` | 清除大小写代理变量后执行子命令 | 不修改父 shell | [`TestCleanChildEnvironment`](../internal/runtimecore/runtime_test.go) |
| `integration list` | 列出声明式应用绑定 | 不隐式安装或重启应用 | [`TestRunProfileAndRedactedEnv`](../internal/runtimecore/runtime_test.go) |
| `integration show` | 解析绑定模板和目标 | 错误模板或占位符拒绝 | [`TestCustomAdapterSchemaAndMalformedPlaceholders`](../internal/runtimecore/adapters_test.go)；模板验证；独立 show 入口验收待补 |
| `integration check` | 检查声明绑定与模板 | JSON 值按数据处理，不执行模板注入；未部署不伪报成功 | [`TestIntegrationExportRedactedPreviewAndCombinedRevealOutput`](../internal/runtimecore/adapters_test.go)；已覆盖公开 Run 在绑定未部署时返回 FAIL/live_environment=UNVERIFIED；成功检查与目标漂移的完整入口用例待补；模板注入边界见 TestCustomTemplateJSONIsData |
| `integration export` | 导出绑定工件或脱敏预览 | 私有权限，不重启第三方服务 | [`TestIntegrationExportRedactedPreviewAndCombinedRevealOutput`](../internal/runtimecore/adapters_test.go) |
| `integration install` | 安装声明且受管的绑定文件 | 缺失收据、外来 drop-in 拒绝 | [`TestIntegrationOwnershipRequiresReceiptAndUnchangedBytes`](../internal/runtimecore/runtime_test.go) |
| `integration remove` | 删除收据所属且内容未变的绑定 | 目标改变或字节漂移拒绝 | [`TestIntegrationOwnershipRequiresReceiptAndUnchangedBytes`](../internal/runtimecore/runtime_test.go) |
| `service install` | 安装所属 systemd 单元与命名空间 | 外来单元和 drop-in 拒绝 | [`TestSystemdOwnershipAndEnvironmentEncoding`](../internal/runtimecore/runtime_test.go)；真实 systemd：TestPrivilegedSystemdTunAndSSH/service-install-start-status 待平台验收 |
| `service start` | 通过 systemd 启动所属服务并查状态 | 校验已加载定义，不自提权 | [`TestPrivilegedSystemdTunAndSSH`](../internal/runtimecore/privileged_linux_test.go)；特权用例 service-install-start-status；待 CI 实跑证据 |
| `service stop` | 停止所属服务 | 不操作其他用户单元 | [`TestPrivilegedSystemdTunAndSSH`](../internal/runtimecore/privileged_linux_test.go)；特权用例 tun-disable-service-stop；待 CI 实跑证据 |
| `service restart` | 重启所属服务应用配置 | 先检查服务所有权 | [`TestPrivilegedSystemdTunAndSSH`](../internal/runtimecore/privileged_linux_test.go)；特权用例 service-install-start-status；待 CI 实跑证据 |
| `service status` | 读取所属服务的实际运行事实 | 停止不报健康通过 | [`TestPrivilegedSystemdTunAndSSH`](../internal/runtimecore/privileged_linux_test.go)；特权用例 tun-disable-service-stop；待 CI 实跑证据 |
| `service uninstall` | 预览或删除所属服务定义 | 只处理受管单元，预览不声称已移除 | [`TestPrivilegedSystemdTunAndSSH`](../internal/runtimecore/privileged_linux_test.go)；特权用例 service-uninstall；待 CI 实跑证据；基线 test_v1_domain.py::test_service_uninstall_preview_never_claims_a_removal_it_did_not_perform |
| `tun status` | 读取配置中的 TUN 状态 | 不创建设备 | [`TestRunProfileAndRedactedEnv`](../internal/runtimecore/runtime_test.go) |
| `tun enable` | 系统作用域事务启用 TUN | 显式 system，保留 SSH；中断可恢复 | [`TestPrivilegedSystemdTunAndSSH`](../internal/runtimecore/privileged_linux_test.go)；特权用例 real-tun-enable-and-ssh / interrupted-tun-enable-restores-running-service；待 CI 实跑证据 |
| `tun disable` | 系统作用域事务关闭 TUN | 中断后恢复原设备与运行态 | [`TestTunCompoundRecoveryBoundary`](../internal/runtimecore/tun_recovery_linux_test.go)；Linux 事务夹具；真实 TUN 另需特权用例 interrupted-tun-disable-recreates-owned-device |
| `core install` | 获取固定审阅核心或本地 asset，暂存而不激活 | 摘要、版本和平台校验，损坏缓存不覆盖 | [`TestCachedCoreValidationPreservesDestination`](../internal/delivery/artifact_test.go) |
| `core update` | 暂存显式版本，不切换活动核心 | 不把远程未审阅摘要当信任来源 | [`TestPinsAndCoreValidation`](../internal/delivery/artifact_test.go) |
| `core adopt` | 采用可信已有核心，必要时重启所属运行态 | 失败恢复旧核心与运行态 | [`TestFailedCoreAdoptionRestoresPreviousRuntime`](../internal/runtimecore/lifecycle_linux_test.go) |
| `core list` | 列出受管核心，初始化前也可查询 | 严格解析 delivery format1 收据 | [`TestCoreListAcceptsDeliveryV1ReceiptAndRejectsFractionalFormat`](../internal/runtimecore/resources_test.go) |
| `health` | 检查配置、认证代理和控制器；可显式探测出口 | 匿名可用端口不能算认证成功 | [`TestHealthRejectsAnonymousProxyAndController`](../internal/runtimecore/lifecycle_linux_test.go)；读不到 socket 表只报 `unavailable`，不谎报未监听：[`TestLinuxHealthReportsUnavailableListenerState`](../internal/runtimecore/health_listener_linux_test.go) |
| `doctor` | 汇总配置、核心、隔离校验与健康事实 | 缺失前提不伪报健康 | [`TestDoctorUninitializedContract`](../internal/runtimecore/parity_contract_test.go)；已覆盖公开 Run 的未初始化检查与载荷；已初始化状态的完整诊断验收待补 |
| `migrate` | 支持预览或显式 apply/no-import 的独立项目边界 | 拒绝 Python 导入和 remove-loader | [`TestMigrationSuccessCommandNames`](../internal/runtimecore/parity_contract_test.go)；已覆盖处理函数的预览/应用名称与成功状态；Linux 公开 Run、Python 导入/loader 拒绝及无副作用用例待补。基线旧导入行为有意不迁移 |
| `reset` | 预览后以 plan-sha256 确认重置受管配置 | 运行态或配置变化使预览失效 | [`TestResetPreviewStaleAndApply`](../internal/runtimecore/lifecycle_linux_test.go) |
| `rollback` | 保留入口但拒绝历史回滚 | 不读取任意备份路径，不等同事务恢复 | [`TestRollbackRefusalContract`](../internal/runtimecore/parity_contract_test.go)；检查 historical-rollback-disabled 及兼容错误字段；基线 test_v1_installation.py::test_historical_rollback_fails_without_reading_a_supplied_path |
| `release check` | 观察稳定版元数据及版本差异 | 不证明已安装最新版，不构成资产信任 | [`TestMetadataStableAndTrust`](../internal/delivery/network_test.go)；受控 HTTP 测试；不是在线发布验收 |
| `release fetch` | 按 target/kind 和审阅 sha256 获取包，验证后发布到输出目录 | 拒绝错误摘要、不可信跳转与清单漂移 | [`TestFetchVerifiesManifestBeforePublication`](../internal/delivery/network_test.go) |
| `update` | 本地或 latest 更新受管程序，支持预览、重装和显式降级 | 收据与清单必需；保留活动核心；预览不宣称资产已验证 | [`TestUpdateRollbackAtBothBoundaries`](../internal/delivery/install_test.go) |
| `rules status` | 报告自定义规则和 provider 文件状态 | 错误文件类型或不受管路径拒绝 | [`TestFileStatusMapsFailures`](../internal/routing/rules_test.go) |
| `rules check` | 解析验证规则与 provider 契约 | 拒绝不支持 YAML 与非法字段 | [`TestParseRuleFileRejectsUnsupportedYAML`](../internal/routing/rules_test.go) |
| `version` | 无初始化查询 CLI/schema/可空 core，保留兼容字段 | 核心探测只读且有界 | [`TestVersionPreservesLegacyJSONWithoutInitialization`](../internal/delivery/delivery_test.go) |
| `profiles` | profile list 的兼容入口 | 同一解析与脱敏边界 | [`TestRunProfileAndRedactedEnv`](../internal/runtimecore/runtime_test.go) |
| `export` | 按 binding 转发 integration export | 保留私有工件与 reveal 边界 | [`TestPublicGrammar`](../internal/command/parser_test.go)；别名语法；共享行为见 TestIntegrationExportRedactedPreviewAndCombinedRevealOutput，别名单独端到端待补 |
| `controller status` | 返回已验证本地控制器状态 | 只接受 loopback，错误映射 overall | [`TestControllerStatusEnvelope`](../internal/routing/commands_test.go) |
| `controller initialize` | 幂等准备控制器与持久选择配置 | 已有有效配置不重写；禁止弱化监听 | [`TestControllerInitializeIdempotent`](../internal/routing/commands_test.go) |
| `controller setup` | 按审阅摘要安装本地 dashboard，保存配置并提示需重启 | 错误摘要不发布资产、不改配置；保留原控制器与密钥；已有 dashboard 拒绝隐式替换 | [`TestLinuxControllerSetupDigestBoundArchive`](../internal/routing/parity_e2e_linux_test.go)；完整 Go Run、归档落盘与 0600 权限断言；穿越/链接拒绝另见 TestArchiveUIRejectsUnsafeArchives |
| `controller token` | 仅向私有终端显示密钥 | JSON 与非私有终端拒绝 | [`TestControllerTokenRefusesJSONBeforeAnyOutput`](../internal/routing/verify_test.go) |
| `nodes` | 列出精确节点及 provider 身份 | 不凭重名猜测身份 | [`TestNodesListingKeepsProviderIdentities`](../internal/routing/commands_test.go) |
| `groups` | 列出组、选择链及标注 | 保留层级，不隐式切换 | [`TestGroupsSelectionChainAndAnnotations`](../internal/routing/commands_test.go) |
| `select` | 选择组成员并读回确认及影响 | 拒绝非成员，跨层需显式授权 | [`TestSelectRejectsNonMemberNode`](../internal/routing/commands_test.go) |
| `latency` | 按节点身份测延迟 | 未知节点脱敏；探测不等于应用出口证据 | [`TestLatencyMeasuresDelay`](../internal/routing/commands_test.go)；HTTP 夹具，不代表真实远端节点连通 |
| `connections` | 展示连接链，默认隐藏目标主机 | details 才披露 | [`TestConnectionsRedactHostsByDefault`](../internal/routing/commands_test.go) |
| `traffic` | 采样控制器上传下载数值 | 不据此推断应用路径 | [`TestTrafficSnapshotNumbers`](../internal/routing/commands_test.go) |
| `subscription preview` | 读取私有输入，生成可审阅配置计划 | 取消、FIFO、宽权限文件和高级路由不安全合并拒绝 | [`TestLinuxSubscriptionInputFileRefusals`](../internal/routing/subscriptions_linux_test.go) |
| `subscription apply` | 按计划 ID 与摘要事务保存配置 | 陈旧计划拒绝，失败恢复；需显式重启 | [`TestLinuxSubscriptionStaleRefusal`](../internal/routing/subscriptions_linux_test.go) |
| `tui` | 原生十页控制台及 plain 菜单，服务内调用 | 信任脚本须显式选择，失败如实呈现；退出恢复终端模式、屏幕与光标 | [`TestConsolePTYAllPagesResizeUTF8AndRestore`](../tui_pty_linux_test.go)：真实 Linux PTY、demo 服务、遍历十页按键/UTF-8/日志级别/主题/选项/取消/缩放/退出恢复；流生命周期单元测试见 [`TestLogStreamStopsOnLeaveAndReconnectsOnReturn`](../tui_parity_test.go)，保存结果见 TestSubscriptionSaveReportsWhatTheServiceActuallyDid；真实控制器流断线/重连仍待补 |
| `providers` | 读取 provider 状态 | 只连接已验证本地控制器 | [`TestProvidersListingAndRefresh`](../internal/routing/commands_test.go) |
| `provider refresh` | 请求指定 provider 刷新 | 请求成功不代表刷新完成 | [`TestProvidersListingAndRefresh`](../internal/routing/commands_test.go) |
| `dns` | 通过控制器发送 DNS 查询 | 本地认证控制器边界 | [`TestDNSQuery`](../internal/routing/commands_test.go) |
| `mode` | 修改运行核心模式并读回确认 | 不声称保存配置或关闭旧连接 | [`TestModePatchAndConfirm`](../internal/routing/commands_test.go) |
| `health-check` | 预览或保存组/provider 探测设置，报告受影响组；保存需重启 | 预览不落盘；幂等应用不重写；保留预设中未指定字段、控制器和密钥 | [`TestLinuxHealthCheckPreviewApplyAndIdempotence`](../internal/routing/parity_e2e_linux_test.go)；完整 Go Run 覆盖 group/provider、预设及部分覆盖；URL 验证另见 TestPublicHTTPSURLContract。此项不执行远端延迟探测，不据此宣称远端可达；基线 test_health.py::test_read_only_preset_override_preservation_and_idempotence |
| `manual` | 预览或保存 Selector 转换 | 无效组拒绝；预览不改服务 | [`TestManualPolicyConvertsGroupToSelect`](../internal/routing/policy_test.go) |
| `override` | 执行显式可信 Node 脚本，预览或保存路由覆盖；支持 FlClash provider 缓存适配 | 预览不落盘；拒绝修改监听/密钥；超时失败不改配置；系统作用域拒绝 | [`TestLinuxOverrideTrustedScriptEndToEnd`](../internal/routing/parity_e2e_linux_test.go)、[`TestLinuxOverrideFlClashAdaptationEndToEnd`](../internal/routing/parity_e2e_linux_test.go)；完整 Go Run + 真实 Node，provider 引用转换为 use/filter 而非内联缓存节点；UI 信任边界另见 TestOverrideNeedsATrustedScript。基线 test_policy_portable.py::test_script_cannot_replace_proxy_listener_or_auth |
| `ui` | 显示已配置 dashboard 访问地址 | 无 dashboard 配置拒绝 | [`TestLinuxUIDashboardAliasParity`](../internal/routing/parity_e2e_linux_test.go)；完整 Go Run，已配置与未配置两个分支均与别名比较 |
| `dashboard` | ui 的兼容入口 | 同一控制器和 dashboard 安全边界；未配置时同样拒绝 | [`TestLinuxUIDashboardAliasParity`](../internal/routing/parity_e2e_linux_test.go)；对比兼容载荷与拒绝错误，不只检查语法注册 |
| `installation install` | 从已验证本地包初装启动器及版本树；相同受管包重试不重写 | 外来启动器绝不替换；根目录和启动器发布前写持久身份日志 | [`TestBootstrapCrashPublicEntryRecovery`](../internal/delivery/bootstrap_linux_test.go)；七个中断窗口 × 三个公开处理入口；正常生命周期另见 TestLinuxBootstrapAndUninstall |
| `installation status` | 只读报告收据、版本树与安装状态 | 仅真正不存在为 not-installed；损坏失败，待恢复不算健康 | [`TestCorruptInstallationStatusFails`](../internal/delivery/uninstall_test.go) |
| `installation recover` | 持锁恢复安装、更新或卸载事务，可再次中断后继续 | 拒绝外来替换和路径漂移，返回非空状态 | [`TestBootstrapInterruptedRecoveryAndSharedMutation`](../internal/delivery/bootstrap_linux_test.go)；外来启动器、同字节替换与链接拒绝见 TestBootstrapRecoveryRefusesForeignIdentity；卸载协调见 TestSharedRecoveryCoordinatesDeliveryUninstall |
| `installation uninstall` | 移除收据所属启动器及程序树，可重复卸载再安装 | 隔离目录绑定原收据身份；拒绝活动核心在程序树内 | [`TestOldJournalRefusesNewInstallation`](../internal/delivery/uninstall_test.go)；另见 TestRemovalPreservesRecordedRunningCoreWhenManagerDiffers / TestRemovalRefusesForeignFilesAndChangedBytes |

## 有意差异与兼容字段

- 命令名保留 `mihomoctl`，配置、数据、缓存、运行目录、服务与账号均使用独立的 `mihomoctl-go` 命名空间，不读取或改写 Python 项目安装。
- 原 Python 的 wheel、wheelhouse、extras、解释器参数和导入/删除旧 loader 的迁移行为被排除。参考基线 [test_v1_contract.py](https://github.com/liuzq1103/mihomo-userctl/blob/f33204dd5e0c7a52d2df4df4d9aa3188b2e7f385/tests/test_v1_contract.py) 的 `test_update_extra_flags_reach_local_and_latest_installers` 和 [test_v1_domain.py](https://github.com/liuzq1103/mihomo-userctl/blob/f33204dd5e0c7a52d2df4df4d9aa3188b2e7f385/tests/test_v1_domain.py) 的 `test_migration_imports_real_configuration_is_idempotent_and_preserves_custom_loader`；它们不作为 Go 应实现的包装行为。Go 拒绝 Python 更新参数见 `TestRejectedArgumentsDoNotLeakSecrets`。
- `rollback` 维持已退役的拒绝语义；自动事务恢复不是恢复用户指定历史备份。基线 [test_v1_installation.py](https://github.com/liuzq1103/mihomo-userctl/blob/f33204dd5e0c7a52d2df4df4d9aa3188b2e7f385/tests/test_v1_installation.py) 的 `test_historical_rollback_fails_without_reading_a_supplied_path`。
- 原 `curses/textual` 名称映射 Go 控制台，plain 为任务菜单；不加载 Python UI。可信脚本可选依赖 Node.js，Node vm 不是安全沙箱。上述完整 Go/Node 用例验证配置行为和拒绝边界，不借用基线成功记录替代，也不证明远端代理节点可用。
- JSON 信封保留 `mihomoctl/v1`。version 数据保留 `mihomoctl/schema/core`；控制器桥接保留 `data.legacy`，内部 UI 适配由 [TestBridgeUnwrapsControllerPayload](../cli_integration_test.go) 检查。release check 的 `current_version/observed_version/newer_available/checked_at/release_url` 与 fetch 的 `source/output_dir/version/target/wheelhouse` 保留适用兼容字段，wheelhouse 为 null；Go 补充信任说明与摘要。
- 远端 API 或未签名 checksum 仅是观测，不能独立建立下载信任。固定核心使用审阅 pin；本地缓存仍须摘要、版本与平台校验。basic 包不冒充含核心的 offline 包，缺少可审阅 dashboard/geodata 时不宣称完整资产已验收。

## 发布前仍需独立完成的验收

0.2.0 已发布。本页不在此处标记最终平台、模型或资产 PASS；最终候选 SHA 与三家族审阅记录绑定在 `.github/release-evidence.json` 与 `.github/reviews/`，差异结果绑定在 [.github/parity-evidence.json](../.github/parity-evidence.json)，发布资产另有独立 SHA-256 审阅；工作树变化后须重新确认。

最新差异记录为 `.work/parity/20261109T225752Z/`：**298 项，265 项精确匹配、33 项明确接受的架构差异（记录在案的 63 条授权差异）、0 项 FAIL，整体 PASS**；固定基线仍为上述 f33204dd。该记录保存的源码摘要为 `401b6094bcaf65d74ef78a031f1d7c20ac0079b5155b6657724b4645457affa2`，覆盖根 `*.go`、`go.mod`、`go.sum` 与 `internal/**` 的非测试源码，用 POSIX 路径分隔符计算（在 Windows 上重算只会差在分隔符上）。同一记录内的 Go 校验为 test PASS（37.436 秒）与 vet PASS（14.562 秒），并明确记录 Node v20.18.1 的两项真实 override 端到端用例与真实 PTY 用例通过。**Linux race 因校验机上没有 cc/gcc 被记录为 UNAVAILABLE，不是 PASS，仍须 CI 完成。**

先前 GLM 的 `.work/inputs/last-linux-run.txt` 记录 125 个顶层用例 PASS、无顶层 FAIL，其中包含上述 controller setup、health-check、两项真实 Node override 和 ui/dashboard 别名测试；最新差异记录也包含 Node 与 PTY 通过事件。这些证据验证相应配置行为，不证明远端探测或节点延迟。矩阵中仍明确列出的专用分支与真实流重连限制没有被本次有限差异集覆盖，不能仅凭 298 项整体 PASS 消除；最终 SHA 的 CI、独立源代码和资产审阅仍须另行完成。

1. Ubuntu 22.04/24.04、amd64/arm64 实际执行常规测试、CLI 和真实 Mihomo v1.19.33。交叉编译不能代替 arm64 执行；arm64 门在 GitHub 原生 arm 运行器上实际执行（qemu-user 不给多线程 guest 稳定的 /proc 启动时间，内核归属证明在模拟下必然拒绝，因此模拟执行不作为门）。amd64 与 arm64 都执行 race 与 vet。
2. `MIHOMOCTL_GO_TEST_CORE` 指定独立校验核心：[TestLinuxSubscriptionRealCoreValidation](../internal/routing/subscriptions_linux_test.go)、[TestLinuxSaveAndStartRealCore](../internal/routing/activation_linux_test.go)；未提供核心的 skip 不构成证据。
3. [TestPrivilegedSystemdTunAndSSH](../internal/runtimecore/privileged_linux_test.go)：两个真实非 root UID、systemd、SSH、TUN 与中断恢复；本地不具备 PID1 systemd 的 WSL 不能替代此项。必须明确 opt-in，跳过不算通过。该用例的系统范围核心路径**含空格**，用来证明 systemd 路径列表按路径逐侧加引号后服务仍能启动（[TestSystemdPathValueQuotesOnlyWhatNeedsIt](../internal/runtimecore/service_unit_test.go)、[TestSystemdUnitQuotesSpacedPaths](../internal/runtimecore/service_unit_test.go) 覆盖渲染本身）。
4. 最终候选的真实终端 PTY、非交互拒绝、两个用户隔离、SSH 保持，以及原 Python 安装未被修改的证据。最新 `go-verification.json` 明确记录 TestConsolePTYAllPagesResizeUTF8AndRestore Linux PASS（3.49 秒）：真实 PTY 遍历十页按键、UTF-8、日志级别、主题、选项、取消、缩放及退出恢复，使用 demo 服务，不能冒充真实控制器流重连验收。此前已读取 `real-cli-results.json` 的部分页面冒烟与终端恢复记录（捕获摘要 `3b659543e6a96e0fd927ed329d1f4491f45bc703e6e87630a2db1c94dc40e6d0`）；这些既有证据仍需绑定最终候选 SHA。SSH 证据也不代替 TUI 流行为。
5. bootstrap 首次发布的持久日志、每个发布窗口崩溃、公开 install/recover/uninstall 重试及同字节外来替换拒绝，按上述专项测试保存原始运行日志并绑定候选 SHA；正常生命周期不证明崩溃一致性。首次发布前的私有随机暂存目录在无日志中断后可能保留，重试不会将其收养或猜测删除。卸载恢复的每个日志对象与启动器都按 device/inode 绑定，[TestRemovalRefusesSameByteForeignReplacement](../internal/delivery/uninstall_test.go) 覆盖"内容相同但对象不同"的替换拒绝。收据按 device/inode 绑定启动器对象，[TestUninstallRefusesForeignLauncherWithIdenticalBytes](../internal/delivery/uninstall_test.go) 覆盖安装完成后启动器被同字节文件替换时的卸载拒绝与状态拒绝。路由事务的日志同样按 device/inode 绑定目标对象，[TestTransactionRecoveryRefusesForeignObjectWithIdenticalBytes](../internal/routing/transaction_identity_test.go) 覆盖发布后被同字节外来文件替换时的恢复拒绝。回滚自身写出的对象也按 device/inode 记录在日志里（`restored_object`），因此**被中断的回滚可以继续**：恢复在日志中认出自己写出的对象，而不是把它当成外来替换拒绝；[TestTransactionRecoveryAcceptsItsOwnInterruptedRollback](../internal/routing/transaction_identity_test.go) 覆盖"回滚已还原文件但未写完"后恢复仍能完成，[TestTransactionRecoveryRefusesForeignObjectAfterInterruptedRollback](../internal/routing/transaction_identity_test.go) 覆盖中断之后被同字节外来文件替换时依然拒绝。同样被拒绝的还有把活动配置或档案凭据指到程序树内的卸载，[TestRemovalRefusesConfigurationWithinProgram](../internal/delivery/uninstall_test.go) 覆盖 core.config 与 credentials_file 两种情形发布对象已消失的未完成发布会回滚而不是拒绝后续命令，[TestBootstrapAbandonsPublicationWhoseObjectsAreGone](../internal/delivery/bootstrap_linux_test.go) 覆盖暂存树被删与已发布根被删两种情形。启动器在链接发布前被移除时，本次发布无法完成（收据绑定的是启动器对象，同字节替换文件是另一个对象），恢复把发布回滚、删除已发布根与日志，而不是留下任何命令都无法回滚的半安装程序，[TestBootstrapRollsBackWhenTheStagedLauncherIsGone](../internal/delivery/bootstrap_linux_test.go) 覆盖暂存启动器目录被移除的两种情形（发布前与发布后）。放弃发布只删除日志清单内的对象：日志从未记录的外来对象不会被删除，私有目录保留它，作用域仍然可用，[TestBootstrapAbandonmentPreservesForeignObjects](../internal/delivery/bootstrap_linux_test.go) 覆盖。回滚是幂等的：已经发布恢复对象的路径不会被再次发布，[TestTransactionRecoveryKeepsTheRestoredObjectItAlreadyPublished](../internal/routing/transaction_identity_test.go) 覆盖该性质；回滚使用的备份按写入时的摘要校验，崩溃后被替换的备份让回滚失败（`rollback-failed`）而不是决定写回用户配置的内容，[TestTransactionRecoveryRefusesAReplacedBackup](../internal/routing/transaction_identity_test.go) 覆盖。**回滚在撤销任何文件之前先校验全部备份**：撤销是逆序的，先被替换的备份最后才会被读到，所以备份被替换时整笔回滚在第一次撤销之前就失败，不会先恢复后面的文件再报错、把配置留在新旧各半的状态，[TestLinuxRollbackRefusesReplacedBackupBeforeAnyUndo](../internal/routing/transaction_linux_test.go) 覆盖。受管配置与复合服务文件按对象身份绑定，同字节外来替换被拒绝（`transaction-conflict`、`compound-file-conflict`），[TestTransactionRefusesForeignObjectWithIdenticalBytes](../internal/runtimecore/runtime_test.go) 与 [TestCompoundRecoveryRefusesSameByteForeignReplacement](../internal/runtimecore/compound_linux_test.go) 覆盖；恢复自己写出的对象被日志认出而不是被当成外来替换，[TestTransactionRecoveryRecognizesItsOwnRestoredObject](../internal/runtimecore/runtime_test.go) 覆盖。旧状态按其当时的保证继续可用：没有绑定启动器对象的旧收据按内容校验，[TestLegacyReceiptWithoutLauncherBindingIsStillUsable](../internal/delivery/install_test.go) 覆盖；旧卸载日志按 `uninstall-legacy-journal` 拒绝并给出人工清理步骤，[TestUninstallRemovesALegacyInstallation](../internal/delivery/uninstall_test.go) 覆盖。命令行按参考实现拒绝看起来像选项的值，[TestOptionValuesRefuseOptionLookingTokens](../internal/command/parser_test.go) 覆盖单独的 `-` 与负数仍然是值的情形。**预览只描述、不修复**：订阅预览（命令行与控制台引导输入）遇到待恢复的日志都拒绝（`transaction-recovery-required`），不重放日志，也不因为预览而创建锁文件，[TestLinuxPreviewRefusesPendingRecovery](../internal/routing/subscriptions_linux_test.go) 与 [TestExecuteSubscriptionPreviewRefusesPendingRecovery](../internal/command/preview_recovery_linux_test.go) 覆盖；apply 路径仍然先恢复再校验，计划校验的始终是它描述的那份状态，[TestLinuxApplyRecoversBeforeSnapshot](../internal/routing/subscriptions_linux_test.go) 覆盖。
6. 同一候选 SHA 的真实三家族审阅：`gpt-6.1-sol`、`zcode/GLM-5.3[1m]`、`minimax-cn/MiniMax-M3.1-Flash[1m]`。签入审阅与 CI 证据后自动构建草稿，不增加人工审批环境；失败、配额受限、未完成调用均不计为通过。审阅记录与报告签入 `.github/release-evidence.json` 与 `.github/reviews/`，其中 `candidate_sha` 即被审阅提交，字面 SHA 不写回被审阅的源码树。
7. 对实际 source、basic amd64/arm64、offline amd64/arm64 的清单、来源、许可证、BUILD.json 以及独立 SHA-256 做资产审阅；公开发布由后续显式发布操作完成，草稿不是公开发布。草稿资产的 `SHA256SUMS`、`BUILD.json` 的 `source_commit` 与 `source_dirty` 必须与候选一致（`source_dirty` 为 false）。
8. 最新 `20261109T225752Z` 差异集已 PASS 298 项（265 精确匹配 + 33 明确接受，0 FAIL）；该结果与源码摘要一并记录在 [.github/parity-evidence.json](../.github/parity-evidence.json)，源码变化时重跑。该有限集合不包含特权 systemd/TUN/SSH、交互式 TUI、远程订阅或发行下载；Node/PTY 由独立 Go 测试提供证据。不能把整体 PASS 扩大为这些未测场景均已通过。arm64 门在原生 arm 硬件上运行全部用例（含内核归属证明），不跳过任何身份用例。

本表的具名测试索引不替代候选版本的原始日志和独立审阅报告。
