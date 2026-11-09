package routing

import (
	"context"
	"os/exec"
	"strconv"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

// Handles reports whether the command belongs to the bridged controller
// grammar or the read-only rules contract. The interactive "tui" command is
// owned by the console, not by this backend.
func Handles(command []string) bool {
	if len(command) == 0 {
		return false
	}
	top := command[0]
	if len(command) == 1 {
		switch top {
		case "nodes", "groups", "connections", "traffic", "providers", "dns", "mode",
			"health-check", "manual", "override", "ui", "dashboard", "select", "latency":
			return true
		}
		return false
	}
	if len(command) != 2 {
		return false
	}
	switch top {
	case "controller":
		switch command[1] {
		case "status", "initialize", "setup", "token":
			return true
		}
	case "subscription":
		return command[1] == "preview" || command[1] == "apply"
	case "provider":
		return command[1] == "refresh"
	case "rules":
		return command[1] == "status" || command[1] == "check"
	}
	return false
}

// scopeLabel maps the scope flag to its public name.
func scopeLabel(system bool) string {
	if system {
		return "system"
	}
	return "user"
}

// bridgedEnvelope wraps a controller payload exactly like the original
// bridge: the legacy document travels under "legacy" with its own schema,
// command and overall, beside the exit code and legacy overall.
func bridgedEnvelope(command, scope, controllerCommand string, payload map[string]any) platform.Envelope {
	legacy := map[string]any{
		"schema":  ControllerSchema,
		"command": controllerCommand,
		"overall": "PASS",
	}
	for key, value := range payload {
		legacy[key] = value
	}
	data := map[string]any{"legacy": legacy, "exit": 0, "legacy_overall": "PASS"}
	return platform.Document(command, scope, data)
}

// failureEnvelope projects an error into the public envelope: control errors
// keep their code, exit class and explicitly safe detail.
func failureEnvelope(command, scope string, err error) platform.Envelope {
	envelope := platform.Document(command, scope, nil)
	doc := platform.ErrorDoc{Code: "controller-operation-unavailable"}
	switch typed := err.(type) {
	case *controlError:
		envelope.Overall = "UNVERIFIED"
		if typed.rc == exitFail {
			envelope.Overall = "FAIL"
		}
		doc.Code = typed.code
		doc.Detail = detailOf(typed)
	case *platform.Error:
		envelope.Overall = "UNVERIFIED"
		if typed.Exit == exitFail {
			envelope.Overall = "FAIL"
		}
		doc.Code = typed.Code
		doc.Detail = typed.Detail
	default:
		envelope.Overall = "UNVERIFIED"
	}
	envelope.Errors = append(envelope.Errors, doc)
	return envelope
}

// requiresMutation mirrors the bridge gating: routing write commands need the
// managed-scope identity (Linux, matching account) before anything runs.
func requiresMutation(command []string) bool {
	switch command[0] {
	case "select", "mode", "provider", "subscription", "manual", "override", "health-check":
		return true
	case "controller":
		return len(command) == 2 && (command[1] == "setup" || command[1] == "initialize" || command[1] == "token")
	}
	return false
}

// recoverBeforeSnapshot runs the shared recovery hooks — routing journals at
// order 10, the runtime journal after — before a mutating flow reads the
// configuration for the first time. The lock is taken and released here, so
// the flow's own later transaction locks stay sequential, never nested. A
// snapshot taken before recovery would be stale the moment recovery restores
// a crashed configuration, tripping the stale-before refusal on a perfectly
// valid edit; the in-transaction rechecks are untouched and still refuse a
// genuinely concurrent change. An already-cancelled request mutates nothing
// and snapshots nothing, so it skips straight to its own cancelled error.
func recoverBeforeSnapshot(ctx context.Context, scope platform.Scope) error {
	if ctx.Err() != nil {
		return nil
	}
	return platform.WithLock(ctx, scope, func() error { return nil })
}

// Run executes one bridged controller or rules command.
func Run(ctx context.Context, a platform.App, r platform.Request) (platform.Envelope, error) {
	command := r.Command
	scope := scopeLabel(a.Scope.System)
	name := command[0]
	if requiresMutation(command) {
		if err := a.Scope.RequireMutation(); err != nil {
			return failureEnvelope(name, scope, err), nil
		}
		// Recover every module's journals before the first configuration
		// read below: the snapshot must describe the recovered state, not
		// the crashed candidate a journal is about to roll back.
		if err := recoverBeforeSnapshot(ctx, a.Scope); err != nil {
			return failureEnvelope(name, scope, err), nil
		}
	}
	if command[0] == "rules" {
		return runRulesCommand(ctx, a, r, scope)
	}
	configPath, manager, err := resolveRoutingContext(a, r)
	if err != nil {
		return failureEnvelope(name, scope, err), nil
	}
	homeDir := r.Get("home-dir")
	payload, err := dispatch(ctx, a, r, manager, configPath, homeDir)
	if err != nil {
		return failureEnvelope(name, scope, err), nil
	}
	return bridgedEnvelope(name, scope, controllerCommandWord(command), payload), nil
}

// controllerCommandWord is the legacy document's command field: the top-level
// controller verb ("subscription", "provider", ...), not the subcommand.
func controllerCommandWord(command []string) string {
	return command[0]
}

// resolveRoutingContext resolves the core configuration path and the manager
// view, preferring explicit options exactly like the forwarded bridge argv.
// An installation with no manager document at all is UNINITIALIZED: the
// original refuses to bridge there (bridge.py synthesize_environment) and
// names the two supported ways forward instead of reporting a missing file.
func resolveRoutingContext(a platform.App, r platform.Request) (string, coreManager, error) {
	if explicit := r.Get("config"); explicit != "" {
		manager, err := loadCoreManager(a)
		if err != nil {
			if uninitializedInstallation(err) {
				return "", manager, bridgeUnavailable()
			}
			return "", manager, err
		}
		return explicit, manager, nil
	}
	path, err := a.CoreConfigPath()
	if err != nil {
		if uninitializedInstallation(err) {
			return "", coreManager{}, bridgeUnavailable()
		}
		return "", coreManager{}, err
	}
	manager, err := loadCoreManager(a)
	if err != nil {
		return "", manager, err
	}
	return path, manager, nil
}

// uninitializedInstallation reports whether the manager document itself is
// absent — nothing was ever initialized — as opposed to a present-but-broken
// manager or a missing managed configuration file.
func uninitializedInstallation(err error) bool {
	return platform.SafeError(err) == "config-missing"
}

// bridgeUnavailable is the original's refusal for an installation holding
// neither a V1 manager nor the 0.9.x legacy configuration: nothing can be
// bridged until one of the two supported states exists.
func bridgeUnavailable() error {
	return &controlError{
		code:       "bridge-unavailable",
		rc:         exitUnverify,
		safeDetail: "initialize V1 (mihomoctl init) or keep the 0.9.x configuration",
	}
}

// dispatch runs one controller command and returns its payload.
func dispatch(ctx context.Context, a platform.App, r platform.Request, m coreManager, configPath, homeDir string) (map[string]any, error) {
	command := r.Command
	switch command[0] {
	case "controller":
		switch command[1] {
		case "status":
			return controllerStatus(ctx, a, configPath)
		case "token":
			return controllerToken(ctx, a, r, configPath)
		case "initialize":
			requested, hasRequested := optionInt(r, "port")
			return initializeController(ctx, a, m, configPath, homeDir, requested, hasRequested)
		case "setup":
			archive := r.Get("archive")
			checksum := r.Get("sha256")
			if (archive != "") != (checksum != "") {
				return nil, control("dashboard-requires-archive-and-sha256", exitUnverify)
			}
			requested, hasRequested := optionInt(r, "port")
			return setupController(ctx, a, m, configPath, homeDir, archive, checksum, requested, hasRequested)
		}
	case "nodes", "groups", "connections", "traffic":
		c, err := verifiedClient(ctx, a, configPath)
		if err != nil {
			return nil, err
		}
		return snapshot(ctx, c, command[0], r.Has("details"))
	case "select":
		if len(r.Args) != 2 {
			return nil, control("invalid-options", exitUnverify)
		}
		c, err := verifiedClient(ctx, a, configPath)
		if err != nil {
			return nil, err
		}
		dir, err := nodeDirectory(ctx, c)
		if err != nil {
			return nil, err
		}
		return selectNode(ctx, c, dir, r.Arg(0), r.Arg(1), r.Has("allow-cross-level"))
	case "latency":
		if len(r.Args) != 1 {
			return nil, control("invalid-options", exitUnverify)
		}
		provider := r.Get("provider")
		globalNode := r.Has("global")
		if globalNode && provider != "" {
			return nil, control("global-option-requires-latency-without-provider", exitUnverify)
		}
		c, err := verifiedClient(ctx, a, configPath)
		if err != nil {
			return nil, err
		}
		var providerPtr *string
		if provider != "" {
			providerPtr = &provider
		}
		return latencyTarget(ctx, c, r.Arg(0), providerPtr, globalNode, nil)
	case "providers":
		c, err := verifiedClient(ctx, a, configPath)
		if err != nil {
			return nil, err
		}
		rows, err := providerRows(ctx, c)
		if err != nil {
			return nil, err
		}
		items := make([]any, 0, len(rows))
		for _, row := range rows {
			items = append(items, row)
		}
		return map[string]any{"providers": items}, nil
	case "provider":
		if len(r.Args) != 1 {
			return nil, control("invalid-options", exitUnverify)
		}
		c, err := verifiedClient(ctx, a, configPath)
		if err != nil {
			return nil, err
		}
		return providerRefresh(ctx, c, r.Arg(0))
	case "dns":
		if len(r.Args) < 1 || len(r.Args) > 2 {
			return nil, control("invalid-options", exitUnverify)
		}
		record := "A"
		if len(r.Args) == 2 {
			record = r.Arg(1)
		}
		c, err := verifiedClient(ctx, a, configPath)
		if err != nil {
			return nil, err
		}
		return dnsCommand(ctx, c, r.Arg(0), record)
	case "mode":
		if len(r.Args) != 1 {
			return nil, control("invalid-options", exitUnverify)
		}
		c, err := verifiedClient(ctx, a, configPath)
		if err != nil {
			return nil, err
		}
		return modeCommand(ctx, c, r.Arg(0))
	case "subscription":
		subs := newSubscriptions(a, m, configPath, homeDir, r.Input)
		if command[1] == "preview" {
			policy := r.Get("policy")
			if policy == "" {
				policy = "auto"
			}
			if r.Get("sha256") != "" {
				return nil, control("invalid-subscription-options", exitUnverify)
			}
			return subs.preview(ctx, r.Get("source-file"), r.Get("url-file"), r.Has("stdin"), policy)
		}
		if r.Get("sha256") == "" {
			return nil, control("invalid-subscription-options", exitUnverify)
		}
		if len(r.Args) != 1 {
			return nil, control("invalid-subscription-options", exitUnverify)
		}
		return subs.apply(ctx, r.Arg(0), r.Get("sha256"))
	case "health-check":
		if len(r.Args) != 2 {
			return nil, control("invalid-health-check-options", exitUnverify)
		}
		options := probeOptions{}
		for _, key := range probeFields {
			if value := r.Get(key); value != "" {
				options[key] = value
			}
		}
		if value := r.Get("preset"); value != "" {
			options["preset"] = value
		}
		text, data, err := readCoreConfig(configPath, a.Scope.System)
		if err != nil {
			return nil, err
		}
		updated, payload, err := healthCandidate(text, data, r.Arg(0), r.Arg(1), options)
		if err != nil {
			return nil, err
		}
		if r.Has("apply") {
			applied, err := applyPolicy(ctx, a, m, configPath, homeDir, text, updated, nil)
			if err != nil {
				return nil, err
			}
			for key, value := range applied {
				payload[key] = value
			}
		}
		return payload, nil
	case "manual":
		if len(r.Args) != 1 {
			return nil, control("invalid-options", exitUnverify)
		}
		text, updated, payload, err := policyCandidate(ctx, a, configPath, homeDir, "", r.Arg(0), false)
		if err != nil {
			return nil, err
		}
		if r.Has("apply") {
			applied, err := applyPolicy(ctx, a, m, configPath, homeDir, text, updated, nil)
			if err != nil {
				return nil, err
			}
			for key, value := range applied {
				payload[key] = value
			}
		}
		return payload, nil
	case "override":
		script := r.Get("script")
		if script == "" || len(r.Args) != 0 {
			return nil, control("invalid-options", exitUnverify)
		}
		text, updated, payload, err := policyCandidate(ctx, a, configPath, homeDir, script, "", r.Has("flclash-compat"))
		if err != nil {
			return nil, err
		}
		if r.Has("apply") {
			applied, err := applyPolicy(ctx, a, m, configPath, homeDir, text, updated, nil)
			if err != nil {
				return nil, err
			}
			for key, value := range applied {
				payload[key] = value
			}
		}
		return payload, nil
	case "ui", "dashboard":
		_, data, err := readCoreConfig(configPath, a.Scope.System)
		if err != nil {
			return nil, err
		}
		host, port, token, err := endpoint(data)
		if err != nil {
			return nil, err
		}
		c := newClient(host, port, token)
		c.runtime = newRuntimeOwner(a, managerDoc(a))
		if err := c.verify(ctx); err != nil {
			return nil, err
		}
		if platform.String(data["external-ui"]) == "" {
			return nil, control("dashboard-not-configured", exitFail)
		}
		return map[string]any{
			"url":           "http://127.0.0.1:" + strconv.Itoa(port) + "/ui/",
			"secret":        "use-mihomoctl-controller-token-in-private-terminal",
			"remote_access": "ssh -N -L LOCAL_PORT:127.0.0.1:" + strconv.Itoa(port) + " USER@SERVER",
			"remote_url":    "http://127.0.0.1:LOCAL_PORT/ui/",
		}, nil
	}
	return nil, control("invalid-options", exitUnverify)
}

// managerDoc loads the manager document or an empty substitute; used only to
// build the runtime ownership proof, which tolerates absence.
func managerDoc(a platform.App) map[string]any {
	doc, err := a.LoadManager()
	if err != nil {
		return map[string]any{}
	}
	return doc
}

// verifiedClient builds the controller client for read commands: the
// configuration is read, the endpoint contract enforced and the session
// verified (ownership, anonymous 401, authorized probe) before use.
func verifiedClient(ctx context.Context, a platform.App, configPath string) (*client, error) {
	_, data, err := readCoreConfig(configPath, a.Scope.System)
	if err != nil {
		return nil, err
	}
	host, port, token, err := endpoint(data)
	if err != nil {
		return nil, err
	}
	c := newClient(host, port, token)
	c.runtime = newRuntimeOwner(a, managerDoc(a))
	if err := c.verify(ctx); err != nil {
		return nil, err
	}
	return c, nil
}

// controllerStatus is the read-only controller self-report.
func controllerStatus(ctx context.Context, a platform.App, configPath string) (map[string]any, error) {
	c, err := verifiedClient(ctx, a, configPath)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"endpoint":       "127.0.0.1:" + strconv.Itoa(c.port),
		"authentication": "PASS",
		"listener":       "PASS",
	}, nil
}

// controllerToken reveals the controller secret only into a private terminal;
// it never travels inside a JSON envelope. A --json request is refused before
// any output is produced: the original's token-display-requires-terminal-
// without-json contract (the raw secret must never reach a tty through a
// machine-parsed document).
func controllerToken(ctx context.Context, a platform.App, r platform.Request, configPath string) (map[string]any, error) {
	if r.JSON || r.Has("json") {
		return nil, control("token-display-requires-terminal-without-json", exitUnverify)
	}
	_, data, err := readCoreConfig(configPath, a.Scope.System)
	if err != nil {
		return nil, err
	}
	_, _, token, err := endpoint(data)
	if err != nil {
		return nil, err
	}
	if !writerIsTerminal(r.Output) {
		return nil, control("token-display-requires-terminal-without-json", exitUnverify)
	}
	if _, err := r.Output.Write([]byte(token + "\n")); err != nil {
		return nil, control("token-display-requires-terminal-without-json", exitUnverify)
	}
	// The bridge JSON path replaces unstructured terminal output with a
	// placeholder; the secret itself never enters the envelope.
	return map[string]any{"output": "unstructured controller output omitted"}, nil
}

// runRulesCommand executes "rules status|check" through the checker contract.
func runRulesCommand(ctx context.Context, a platform.App, r platform.Request, scope string) (platform.Envelope, error) {
	action := r.Command[1]
	manager, err := a.LoadManager()
	if err != nil {
		return failureEnvelope(r.Command[0], scope, err), nil
	}
	core := platform.Map(manager["core"])
	binary := platform.String(core["binary"])
	if binary == "" {
		binary = findMihomoBinary()
		if binary == "" {
			return failureEnvelope(r.Command[0], scope, ruleFail("mihomo-binary-missing")), nil
		}
	}
	configPath := r.Get("config")
	if configPath == "" {
		configPath = platform.String(core["config"])
		if configPath == "" {
			return failureEnvelope(r.Command[0], scope, &platform.Error{
				Code:   "rules-unavailable",
				Detail: "run mihomoctl init first so the active core config path is known",
				Exit:   exitUnverify,
			}), nil
		}
	}
	homeDir := r.Get("home-dir")
	if homeDir == "" {
		homeDir = a.Scope.CoreHome()
	}
	asUID := 0
	if a.Scope.System {
		if uid := serviceAccountUID(); uid > 0 {
			asUID = uid
		}
	}
	data, overall, _ := runRules(ctx, a, binary, action, homeDir, configPath, asUID)
	envelope := platform.Document("rules-"+action, scope, data)
	envelope.Overall = overall
	return envelope, nil
}

// findMihomoBinary mirrors the checker's PATH fallback.
func findMihomoBinary() string {
	if path, err := exec.LookPath("mihomo"); err == nil {
		return path
	}
	return ""
}

// optionInt reads an integer option with presence.
func optionInt(r platform.Request, key string) (int, bool) {
	value := r.Get(key)
	if value == "" {
		return 0, false
	}
	n, err := strconv.Atoi(value)
	if err != nil {
		return 0, true
	}
	return n, true
}
