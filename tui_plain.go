package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
)

// The plain console is the fallback for a session that cannot run the
// full-screen console: a task menu that needs nothing but a line reader.
//
// It follows the audited plain console of the Python implementation: the
// same menu, the same confirmations, the same guided subscription preview,
// the same honest refusals. Nothing here pretends to have succeeded: a
// failed operation prints why and the menu continues.

// MaskedInputReader is an optional capability of the input: read one secret
// without echoing it.
//
// A caller that knows how to mask (a terminal helper, a test double) can
// implement it; the console uses it instead of reading the line itself.
type MaskedInputReader interface {
	// ReadMasked reads one secret and returns it without echoing it.
	ReadMasked(prompt string) (string, error)
}

// plainConsole holds the state of one plain session.
type plainConsole struct {
	src Source
	cli CliSource
	raw io.Reader
	out io.Writer
}

// runPlainConsole runs the plain task menu until the operator quits.
//
// The caller owns the terminal check: this function only reads lines, so it
// also works with a pipe (a script, a test). It returns nil when the menu
// ends normally and an error when the input cannot be read.
func runPlainConsole(src Source, cli CliSource, in io.Reader, out io.Writer) error {
	console := &plainConsole{src: src, cli: cli, raw: in, out: out}
	return console.run()
}

// readLine reads one line from the reader.
//
// The console reads one byte at a time on purpose: a masked input reads the
// same stream through its own reader, and a buffered read would swallow the
// bytes the masked read has to see.
func readLine(reader io.Reader) (string, error) {
	var line strings.Builder
	buffer := make([]byte, 1)
	for {
		count, err := reader.Read(buffer)
		if count > 0 {
			if buffer[0] == '\n' {
				return strings.TrimRight(line.String(), "\r"), nil
			}
			line.WriteByte(buffer[0])
		}
		if err != nil {
			if line.Len() > 0 {
				// The last line of a stream may end without a newline.
				return strings.TrimRight(line.String(), "\r"), nil
			}
			return "", err
		}
	}
}

// print writes one line to the output.
func (c *plainConsole) print(format string, args ...any) {
	fmt.Fprintf(c.out, format+"\n", args...)
}

// ask reads one answer. An empty last line (end of input) ends the menu.
func (c *plainConsole) ask(prompt string) (string, error) {
	fmt.Fprint(c.out, prompt)
	line, err := readLine(c.raw)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

// askSecret reads a secret. A subscription URL must not end up on the screen
// or in the scrollback, so the input is masked when the terminal allows it.
//
// The masking is best effort and never fatal: a reader that cannot mask
// (a pipe, a script, a test) is read normally.
func (c *plainConsole) askSecret(prompt string) (string, error) {
	// An optional capability wins: the caller may know how to mask.
	if masked, ok := c.raw.(MaskedInputReader); ok {
		value, err := masked.ReadMasked(prompt)
		if err == nil {
			return strings.TrimSpace(value), nil
		}
	}
	// A terminal gets its echo switched off while the line is read.
	if file, ok := c.raw.(*os.File); ok && isTerminal(file) {
		fmt.Fprint(c.out, prompt)
		value, err := readMaskedLine(c.raw, file)
		// The Enter key was not echoed either, so the line is closed here.
		fmt.Fprintln(c.out)
		if err != nil && value == "" {
			return "", err
		}
		return strings.TrimSpace(value), nil
	}
	return c.ask(prompt)
}

// confirm asks for an explicit yes. Anything else is a no.
func (c *plainConsole) confirm(message string) bool {
	answer, err := c.ask(message + " [y/N]: ")
	if err != nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(answer), "y")
}

// run is the menu loop.
func (c *plainConsole) run() error {
	c.print("使用代理：mihomoctl exec -- <命令>")
	// A first run has no manager yet. The console says which steps to take
	// instead of failing every command with the same error. The check reads
	// the envelope as well as the Go error: a service that answers with a
	// failure envelope has not failed loudly, and the operator would never
	// learn that the setup is missing.
	if env, err := c.cli.Run("status"); err != nil {
		c.print("配置尚未就绪：%s", err.Error())
		c.print("首次配置：选择 3 导入订阅，再选择 2 选择节点。")
	} else if failure := serviceError(env, nil); failure != nil {
		c.print("配置尚未就绪：%s", failure.Error())
		c.print("首次配置：选择 3 导入订阅，再选择 2 选择节点。")
	}
	for {
		c.print("\nMihomo 管理\n1. 运行时状态  2. 选择节点  3. 导入订阅\n4. 初始化控制器  5. 启动  6. 停止  7. 重启生效\n8. 切换模式  10. 探测配置  11. 历史日志\n12. 代理档案与接入  q. 退出")
		choice, err := c.ask("请选择: ")
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		choice = strings.ToLower(strings.TrimSpace(choice))
		if choice == "q" || choice == "quit" {
			return nil
		}
		if err := c.dispatch(choice); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			c.print("操作未完成：%s", err.Error())
			c.print("检查私有配置、订阅连通性与核心是否存在后重试。")
		}
	}
}

// dispatch runs one menu entry.
func (c *plainConsole) dispatch(choice string) error {
	switch choice {
	case "1":
		return c.runtimeStatus()
	case "2":
		return c.selectNode()
	case "3":
		return c.importSubscription()
	case "4":
		return c.initializeController()
	case "5", "6", "7":
		return c.lifecycle(map[string]string{"5": "start", "6": "stop", "7": "restart"}[choice])
	case "8":
		return c.switchMode()
	case "10":
		return c.probeConfig()
	case "11":
		return c.journal()
	case "12":
		return c.profilesAndBindings()
	default:
		c.print("未知选项：%s", choice)
		return nil
	}
}

// runtimeStatus prints the runtime facts and the controller state.
func (c *plainConsole) runtimeStatus() error {
	env, err := c.cli.Run("status")
	if err != nil {
		return err
	}
	c.print("运行时（作用域 %s）", stringOr(env.Data, "scope", "unknown"))
	for _, line := range runtimeFacts(env.Data) {
		c.print("  %s", line)
	}
	// The controller state comes from the source: it is the part that says
	// whether a core answered at all.
	controller, version, mode := "connected", "未知", "未知"
	if v, err := c.src.Version(); err == nil {
		version = v.Version
	} else {
		controller = "unavailable"
	}
	if cfg, err := c.src.Configs(); err == nil {
		mode = cfg.Mode
	} else {
		controller = "unavailable"
	}
	c.print("控制器: %s  核心: %s  模式: %s", controller, version, mode)
	c.print("待重启: %s", yesNo(boolValue(env.Data["pending_restart"])))
	if code := stringOr(env.Data, "error", ""); code != "" {
		c.print("尚未连接: %s；可选 4 初始化，再选 7 重启或检查配置。", code)
	}
	if proxies, err := c.src.Proxies(); err == nil {
		for _, name := range plainGroupNames(proxies) {
			c.print("%s → %s", name, orAuto(proxies.Proxies[name].Now))
		}
	}
	return nil
}

// selectNode lists the groups, then the members of one group, and switches
// the selection. A cross-level selection needs an explicit authorisation.
func (c *plainConsole) selectNode() error {
	proxies, err := c.src.Proxies()
	if err != nil {
		return err
	}
	groups := plainGroupNames(proxies)
	c.print("\nMihomo · 策略组 / Groups (q: quit, Enter: refresh)")
	for index, name := range groups {
		group := proxies.Proxies[name]
		c.print("%d. %s [%s] → %s", index+1, name, group.Type, orAuto(group.Now))
	}
	answer, err := c.ask("选择策略组 / Group: ")
	if err != nil {
		return err
	}
	if strings.EqualFold(answer, "q") {
		return nil
	}
	index, ok := plainIndex(answer, len(groups))
	if !ok {
		return nil
	}
	group := proxies.Proxies[groups[index]]
	if group.Type != "Selector" {
		c.print("自动/负载均衡组只读；请选择 Selector。 / Automatic group is read-only.")
		return nil
	}
	for position, member := range group.All {
		marker := ""
		if member == group.Now {
			marker = " ✓"
		}
		c.print("%d. %s%s", position+1, member, marker)
	}
	answer, err = c.ask("切换到 / Select (Enter: cancel): ")
	if err != nil {
		return err
	}
	position, ok := plainIndex(answer, len(group.All))
	if !ok {
		return nil
	}
	node := group.All[position]
	if !c.confirm(fmt.Sprintf("确认将 %s 切换为 %s？共享入口影响见上方", groups[index], node)) {
		return nil
	}
	applied, err := c.selectMember(groups[index], node)
	if err != nil {
		c.print("操作未完成：%s", err.Error())
		return nil
	}
	if !applied {
		// The authorisation was refused: nothing was switched, and the
		// console must not claim otherwise.
		c.print("已取消跨层切换；当前选择未改变。")
		return nil
	}
	c.print("已确认切换；已有连接不强制断开。 / Selection confirmed; existing connections unchanged.")
	return nil
}

// selectMember performs the selection. The service refuses a selection that
// skips the group hierarchy; that refusal is only overridden with an
// explicit authorisation.
//
// The first result reports whether the selection was applied.
func (c *plainConsole) selectMember(group, node string) (bool, error) {
	err := c.src.Select(group, node)
	if err == nil {
		return true, nil
	}
	if !strings.Contains(err.Error(), "cross-level-selection-refused") {
		return false, err
	}
	if !c.confirm("此选择将跳过子组层级。明确授权跨层切换？") {
		return false, nil
	}
	authorizer, ok := c.src.(CrossLevelSelectSource)
	if !ok {
		return false, errors.New("cross-level-selection-refused: 本机服务未提供跨层切换授权")
	}
	if err := authorizer.SelectAllowCrossLevel(group, node); err != nil {
		return false, err
	}
	return true, nil
}

// importSubscription previews a subscription under the guided policy and
// saves it after an explicit confirmation.
func (c *plainConsole) importSubscription() error {
	answer, err := c.ask("来源：1 订阅 URL / 2 YAML 文件 [1]: ")
	if err != nil {
		return err
	}
	kind := "url"
	if strings.TrimSpace(answer) == "2" {
		kind = "file"
	}
	prompt := "YAML 文件路径: "
	if kind == "url" {
		prompt = "HTTPS 订阅 URL（隐藏输入）: "
	}
	var value string
	if kind == "url" {
		value, err = c.askSecret(prompt)
	} else {
		value, err = c.ask(prompt)
	}
	if err != nil {
		return err
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return errors.New("subscription-source-empty")
	}
	env, effective, err := c.previewSubscription(value, kind)
	if err != nil {
		return err
	}
	for _, line := range previewSummary(env.Data) {
		c.print("%s", line)
	}
	for _, line := range clearingWarnings(env.Data) {
		c.print("%s", line)
	}
	if overwrites, ok := env.Data["probe_overwrites"].([]any); ok && len(overwrites) > 0 {
		c.print("订阅会覆盖现有探测设置：%d 项", len(overwrites))
	}
	if effective != "simple" {
		c.print("本次按 %s 预览：%s", policyLabel(effective), policyHelp[effective])
	}
	identifier := stringValue(env.Data["id"])
	digest := stringValue(env.Data["sha256"])
	if identifier == "" || digest == "" {
		return errors.New("subscription-preview-incomplete")
	}
	if !c.confirm("保存订阅并启动或重启当前用户的代理？不保留历史备份。") {
		// The abandoned preview is released, so the backend can drop its
		// temporary candidate file.
		if discarder, ok := c.cli.(SubscriptionDiscardCli); ok {
			_, _ = discarder.SubscriptionDiscard(identifier)
		}
		return nil
	}
	applied, lines, err := saveSubscription(c.cli, identifier, digest)
	if err != nil {
		return err
	}
	for _, line := range lines {
		c.print("%s", line)
	}
	if stringValue(applied.Data["state"]) == "restart-required" {
		// The file is written, but the runtime still serves the old
		// configuration: saying "saved and started" would be a lie.
		c.print("已保存，尚未生效，请选择 7 重启。")
		return nil
	}
	c.print("已保存并启动。选择 2 搜索、测速和选择节点。")
	return nil
}

// previewSubscription asks the service for a preview of the private payload.
//
// The guided import ("simple") is a service-level operation: it looks at the
// local configuration to decide between a full provider import and a
// nodes-only merge. When the service does not know it, the request falls
// back to the automatic judgement and says so out loud.
func (c *plainConsole) previewSubscription(value, kind string) (Envelope, string, error) {
	guided, hasGuided := c.cli.(SubscriptionInputCli)
	request := func(policy string) (Envelope, error) {
		switch {
		case hasGuided:
			return guided.SubscriptionInput(value, kind, policy)
		case kind == "url":
			raw, err := c.src.Download(value)
			if err != nil {
				return Envelope{}, err
			}
			return c.cli.RunWithStdin(raw, "subscription", "preview", "--stdin", "--policy", policy)
		default:
			return c.cli.Run("subscription", "preview", "--source-file", value, "--policy", policy)
		}
	}
	env, err := request("simple")
	effective := "simple"
	if policyRefused(env, err) {
		env, err = request("auto")
		effective = "auto"
		if err == nil {
			c.print("本机服务未提供引导导入（simple），本次按自动判断预览；" +
				"引导导入会在本地仍是简单结构时导入完整节点，在本地已有路由策略时只合并节点。")
		}
	}
	if err != nil {
		return Envelope{}, effective, err
	}
	if env.Overall != "PASS" || env.Data == nil {
		for _, line := range envelopeLines(env) {
			c.print("%s", line)
		}
		return Envelope{}, effective, errors.New("subscription-preview-refused")
	}
	return env, effective, nil
}

// initializeController creates the local controller and its secret.
func (c *plainConsole) initializeController() error {
	if !c.confirm("创建本机控制器和随机密钥？") {
		return nil
	}
	env, err := c.cli.Run("controller", "initialize")
	if err != nil {
		return err
	}
	state := stringValue(env.Data["state"])
	if state == "" {
		state = env.Overall
	}
	c.print("配置状态：%s；如有变更，请选择 7 重启。", state)
	return nil
}

// lifecycle starts, stops or restarts the runtime.
func (c *plainConsole) lifecycle(action string) error {
	if !c.confirm("确认更改当前用户的代理服务？") {
		return nil
	}
	env, err := c.cli.Run(action)
	if err != nil {
		return err
	}
	if env.Overall != "PASS" {
		reason := stringOr(env.Data, "reason", "运行时不可用")
		c.print("未完成：%s", reason)
		return nil
	}
	c.print("操作已完成。")
	return nil
}

// switchMode changes the running core's routing mode.
func (c *plainConsole) switchMode() error {
	answer, err := c.ask("1 规则 / 2 全局 / 3 直连: ")
	if err != nil {
		return err
	}
	mode := map[string]string{"1": "rule", "2": "global", "3": "direct"}[strings.TrimSpace(answer)]
	if mode == "" {
		return nil
	}
	if err := c.src.SetMode(mode); err != nil {
		return err
	}
	c.print("运行模式已切换。")
	return nil
}

// probeConfig previews and saves the probe settings of a group or a
// provider.
func (c *plainConsole) probeConfig() error {
	c.print("必须以 group 或 provider 开头：group \"组名\" 或 provider \"名称\"；" +
		"可加 --preset resilient 或 --url / --expected-status / --interval / --timeout / --lazy / --tolerance。")
	answer, err := c.ask("探测配置: ")
	if err != nil {
		return err
	}
	kind, name, options, err := parseProbeRequest(answer)
	if err != nil {
		return err
	}
	env, err := c.cli.Run(append([]string{"health-check", kind, name}, options...)...)
	if err != nil {
		return err
	}
	for _, line := range envelopeLines(env) {
		c.print("%s", line)
	}
	if stringValue(env.Data["state"]) != "preview" {
		return nil
	}
	if !c.confirm("校验、保存探测设置？需单独重启。") {
		return nil
	}
	applied, err := c.cli.Run(append([]string{"health-check", kind, name}, append(options, "--apply")...)...)
	if err != nil {
		return err
	}
	for _, line := range envelopeLines(applied) {
		c.print("%s", line)
	}
	c.print("已保存，请选择 7 重启。")
	return nil
}

// journal prints the managed runtime journal.
//
// The journal belongs to the runtime this scope manages. There is no CLI
// verb for it, so the console asks the service for it through the optional
// capability; without that capability it says that the journal is not
// available instead of reading an unrelated unit's log.
func (c *plainConsole) journal() error {
	since, err := c.ask("开始时间（留空不限）: ")
	if err != nil {
		return err
	}
	until, err := c.ask("结束时间（留空不限）: ")
	if err != nil {
		return err
	}
	reader, ok := c.cli.(JournalCli)
	if !ok {
		return errors.New("journal-not-supported")
	}
	env, err := reader.Journal(strings.TrimSpace(since), strings.TrimSpace(until), 200)
	if err != nil {
		return err
	}
	if failure := serviceError(env, nil); failure != nil {
		return failure
	}
	for _, line := range envelopeLines(env) {
		c.print("%s", line)
	}
	return nil
}

// profilesAndBindings prints the proxy profiles, the declared bindings and
// the fixed environment boundaries.
func (c *plainConsole) profilesAndBindings() error {
	env, err := c.cli.Run("profiles")
	if err != nil {
		return err
	}
	for _, line := range envelopeLines(env) {
		c.print("%s", line)
	}
	bindings, err := c.cli.Run("integration", "list")
	if err != nil {
		return err
	}
	for _, line := range envelopeLines(bindings) {
		c.print("%s", line)
	}
	environment, err := c.cli.Run("env", "show")
	if err != nil {
		return err
	}
	for _, line := range envelopeLines(environment) {
		c.print("%s", line)
	}
	return nil
}

// parseProbeRequest reads a probe configuration request: the kind, the exact
// name and the options that follow.
func parseProbeRequest(text string) (kind, name string, options []string, err error) {
	tokens := splitProbeTokens(text)
	if len(tokens) < 2 {
		return "", "", nil, errors.New("探测配置需要 group 或 provider 与名称")
	}
	kind = strings.ToLower(tokens[0])
	if kind != "group" && kind != "provider" {
		return "", "", nil, errors.New("探测配置只能以 group 或 provider 开头")
	}
	return kind, tokens[1], tokens[2:], nil
}

// splitProbeTokens splits a request into tokens. A double quoted name keeps
// its spaces.
func splitProbeTokens(text string) []string {
	tokens := []string{}
	current := strings.Builder{}
	quoted := false
	for _, char := range text {
		switch {
		case char == '"':
			quoted = !quoted
		case (char == ' ' || char == '\t') && !quoted:
			if current.Len() > 0 {
				tokens = append(tokens, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(char)
		}
	}
	if current.Len() > 0 {
		tokens = append(tokens, current.String())
	}
	return tokens
}

// plainGroupNames lists the groups of a proxy document in a stable order.
func plainGroupNames(proxies ProxiesDoc) []string {
	names := make([]string, 0, len(proxies.Proxies))
	for name, group := range proxies.Proxies {
		if group.Type == "Selector" || group.Type == "URLTest" ||
			group.Type == "Fallback" || group.Type == "LoadBalance" || group.Type == "Relay" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// plainIndex reads a one-based menu answer.
func plainIndex(answer string, count int) (int, bool) {
	answer = strings.TrimSpace(answer)
	if answer == "" {
		return 0, false
	}
	value, err := strconv.Atoi(answer)
	if err != nil || value < 1 || value > count {
		return 0, false
	}
	return value - 1, true
}

// orAuto names an automatic selection.
func orAuto(now string) string {
	if now == "" {
		return "自动"
	}
	return now
}

// yesNo renders a boolean observation.
func yesNo(value bool) string {
	if value {
		return "是"
	}
	return "否"
}
