package routing

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/liuzq1103/mihomoctl/internal/platform"
	"gopkg.in/yaml.v3"
)

// policyKeys are the sections a routing policy may change.
var policyKeys = []string{"proxy-groups", "rules", "rule-providers"}

// overrideRunner is the exact trusted-JS harness the original shipped: the
// user's script runs in a new V8 context with a 3-second timeout and no I/O
// except a failing console.error; Node's vm is not a security sandbox and the
// script is explicitly trusted, as in the original.
const overrideRunner = `
const fs = require('fs'), vm = require('vm');
const config = JSON.parse(fs.readFileSync(0, 'utf8'));
let failed = false;
const context = vm.createContext({console: {log() {}, warn() {}, error() {failed = true;}}});
vm.runInContext(fs.readFileSync(process.argv[1], 'utf8'), context, {timeout: 3000});
context.input = config;
const result = vm.runInContext('main(input)', context, {timeout: 3000});
if (failed || !result || typeof result !== 'object' || Array.isArray(result)) process.exit(2);
process.stdout.write(JSON.stringify(result));
`

// flclashInput adapts a provider-based server config to the user's desktop
// script contract.
func flclashInput(data map[string]any, home string) (map[string]any, map[string][]string, error) {
	adapted := deepCopyMap(data)
	providers := anyMap(data["proxy-providers"])
	nodes := append([]any{}, anyList(adapted["proxies"])...)
	providerNodes := map[string][]string{}
	for providerName, provider := range providers {
		pm, ok := provider.(map[string]any)
		if !ok || platformString(pm["path"]) == "" {
			return nil, nil, control("flclash-provider-needs-local-cache", exitUnverify)
		}
		path := platformString(pm["path"])
		if !filepath.IsAbs(path) {
			path = filepath.Join(home, path)
		}
		if err := platform.CheckPath(path); err != nil {
			return nil, nil, controllerFileError(err)
		}
		st, err := os.Lstat(path)
		if err != nil {
			return nil, nil, controllerFileError(err)
		}
		if st.Size() > limit {
			return nil, nil, control("flclash-provider-cache-too-large", exitUnverify)
		}
		b, err := platform.ReadPrivate(path)
		if err != nil {
			return nil, nil, controllerFileError(err)
		}
		// The cache is core-managed data, not user policy input: it is parsed
		// leniently like the original yaml.safe_load.
		var cached map[string]any
		if yaml.Unmarshal(b, &cached) != nil {
			return nil, nil, control("flclash-provider-cache-invalid", exitUnverify)
		}
		entries := anyList(cached["proxies"])
		if entries == nil {
			return nil, nil, control("flclash-provider-cache-invalid", exitUnverify)
		}
		for _, entry := range entries {
			node, ok := entry.(map[string]any)
			if !ok {
				return nil, nil, control("flclash-provider-cache-invalid", exitUnverify)
			}
			nodeName, ok := node["name"].(string)
			if !ok {
				return nil, nil, control("flclash-provider-cache-invalid", exitUnverify)
			}
			providerNodes[nodeName] = append(providerNodes[nodeName], providerName)
		}
		nodes = append(nodes, entries...)
	}
	adapted["proxies"] = nodes
	groups := anyList(adapted["proxy-groups"])
	if groups == nil {
		groups = []any{}
		adapted["proxy-groups"] = groups
	}
	names := map[string]bool{}
	for _, g := range groups {
		if gm, ok := g.(map[string]any); ok {
			if n, ok := gm["name"].(string); ok {
				names[n] = true
			}
		}
	}
	for name, choices := range map[string][]string{"Ai+": {}, "漏网之鱼": {"DIRECT"}} {
		if !names[name] {
			groups = append(groups, map[string]any{"name": name, "type": "select", "proxies": toAnyList(choices)})
		}
	}
	adapted["proxy-groups"] = groups
	return adapted, providerNodes, nil
}

func toAnyList(src []string) []any {
	out := make([]any, len(src))
	for i, s := range src {
		out[i] = s
	}
	return out
}

var regexEscape = regexp.MustCompile(`([\\.^$|?*+()\[\]{}])`)

// policyCandidate computes a manual-group or trusted-script candidate.
// It returns the original text, updated text and the preview document.
func policyCandidate(ctx context.Context, a platform.App, configPath, homeDir, script string, group string, flclash bool) ([]byte, []byte, map[string]any, error) {
	text, data, err := readCoreConfig(configPath, a.Scope.System)
	if err != nil {
		return nil, nil, nil, err
	}
	var changes map[string]any
	if script != "" {
		if a.Scope.System {
			return nil, nil, nil, control("system-javascript-overrides-disabled", exitUnverify)
		}
		if err := platform.CheckPath(script); err != nil {
			return nil, nil, nil, controllerFileError(err)
		}
		st, err := os.Lstat(script)
		if err != nil {
			return nil, nil, nil, controllerFileError(err)
		}
		if st.Size() > limit {
			return nil, nil, nil, control("override-script-too-large", exitUnverify)
		}
		if _, err := platform.ReadPrivate(script); err != nil {
			return nil, nil, nil, controllerFileError(err)
		}
		node, err := exec.LookPath("node")
		if err != nil {
			return nil, nil, nil, control("override-requires-node", exitUnverify)
		}
		home := homeDir
		if home == "" {
			home = a.Scope.CoreHome()
		}
		inputData := data
		providerNodes := map[string][]string{}
		if flclash {
			inputData, providerNodes, err = flclashInput(data, home)
			if err != nil {
				return nil, nil, nil, err
			}
		}
		payload, err := json.Marshal(inputData)
		if err != nil {
			return nil, nil, nil, control("override-result-invalid", exitUnverify)
		}
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(cctx, node, "-e", overrideRunner, script)
		cmd.Stdin = bytes.NewReader(payload)
		cmd.Env = cleanChildEnvironment()
		var stdout bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = nil
		if err := cmd.Run(); err != nil {
			if cctx.Err() != nil {
				return nil, nil, nil, control("controller-operation-unavailable", exitUnverify)
			}
			return nil, nil, nil, control("override-failed-check-script-input-groups-and-inline-proxies", exitFail)
		}
		if stdout.Len() > limit {
			return nil, nil, nil, control("override-failed-check-script-input-groups-and-inline-proxies", exitFail)
		}
		var changed map[string]any
		if json.Unmarshal(stdout.Bytes(), &changed) != nil || changed == nil {
			return nil, nil, nil, control("override-result-invalid", exitUnverify)
		}
		// This desktop status marker is metadata, never core configuration.
		delete(changed, "__flclashRules")
		if flclash {
			if !sameValue(anyList(changed["proxies"]), anyList(inputData["proxies"])) {
				return nil, nil, nil, control("flclash-script-must-preserve-nodes", exitUnverify)
			}
			if _, ok := data["proxies"]; ok {
				changed["proxies"] = deepCopyList(anyList(data["proxies"]))
			} else {
				delete(changed, "proxies")
			}
			inlineNames := map[string]bool{}
			for _, n := range anyList(data["proxies"]) {
				if nm, ok := n.(map[string]any); ok {
					if s, ok := nm["name"].(string); ok {
						inlineNames[s] = true
					}
				}
			}
			for _, g := range anyList(changed["proxy-groups"]) {
				gm, ok := g.(map[string]any)
				if !ok {
					continue
				}
				choices := []string{}
				for _, c := range anyList(gm["proxies"]) {
					if s, ok := c.(string); ok {
						choices = append(choices, s)
					}
				}
				var cachedNames []string
				for _, n := range choices {
					if len(providerNodes[n]) > 0 && !inlineNames[n] {
						cachedNames = append(cachedNames, n)
					}
				}
				if len(cachedNames) > 0 {
					kept := []any{}
					for _, n := range choices {
						if !containsString(cachedNames, n) {
							kept = append(kept, n)
						}
					}
					gm["proxies"] = kept
					useSet := []any{}
					seenUse := map[string]bool{}
					for _, n := range cachedNames {
						for _, p := range providerNodes[n] {
							if !seenUse[p] {
								seenUse[p] = true
								useSet = append(useSet, p)
							}
						}
					}
					gm["use"] = useSet
					escaped := make([]string, len(cachedNames))
					for i, n := range cachedNames {
						escaped[i] = regexEscape.ReplaceAllString(n, `\$1`)

					}
					gm["filter"] = "^(?:" + strings.Join(escaped, "|") + ")$"
				}
				if n, _ := gm["name"].(string); n == "Ai+" {
					gm["type"] = "select"
					delete(gm, "use")
				}
			}
		}
		// Prevent a desktop script from replacing listeners/auth/TUN policy.
		keys := map[string]bool{}
		for k := range data {
			keys[k] = true
		}
		for k := range changed {
			keys[k] = true
		}
		for k := range keys {
			if memberString(policyKeys, k) || k == "__flclashRules" {
				continue
			}
			if !sameValue(data[k], changed[k]) {
				return nil, nil, nil, control("override-may-only-change-groups-rules-rule-providers", exitUnverify)
			}
		}
		changes = map[string]any{}
		for _, k := range policyKeys {
			v, inChanged := changed[k]
			if inChanged && !sameValue(data[k], v) {
				changes[k] = v
			}
		}
		for _, k := range policyKeys {
			if _, inData := data[k]; inData {
				if _, inChanged := changed[k]; !inChanged {
					return nil, nil, nil, control("override-cannot-remove-policy-sections", exitUnverify)
				}
			}
		}
	} else {
		groups := deepCopyList(anyList(data["proxy-groups"]))
		found := []map[string]any{}
		for _, g := range groups {
			gm, ok := g.(map[string]any)
			if !ok {
				continue
			}
			if n, _ := gm["name"].(string); n == group {
				found = append(found, gm)
			}
		}
		if len(found) != 1 {
			return nil, nil, nil, control("manual-requires-existing-policy-group", exitFail)
		}
		if t, _ := found[0]["type"].(string); t != "select" && t != "url-test" && t != "fallback" && t != "load-balance" {
			return nil, nil, nil, control("manual-requires-existing-policy-group", exitFail)
		}
		found[0]["type"] = "select"
		for _, key := range []string{"url", "interval", "tolerance", "lazy", "timeout", "max-failed-times", "expected-status", "strategy"} {
			delete(found[0], key)
		}
		if !sameValue(anyList(groups), anyList(data["proxy-groups"])) {
			changes = map[string]any{"proxy-groups": groups}
		} else {
			changes = map[string]any{}
		}
	}
	profile := anyMap(data["profile"])
	if rawProfile, exists := data["profile"]; exists {
		if _, isMap := rawProfile.(map[string]any); !isMap {
			return nil, nil, nil, control("config-profile-invalid", exitUnverify)
		}
	}
	if len(changes) > 0 && script == "" {
		withStore := deepCopyMap(profile)
		withStore["store-selected"] = true
		changes["profile"] = withStore
	}
	updated := text
	if len(changes) > 0 {
		updated, err = patchCoreConfig(text, changes)
		if err != nil {
			return nil, nil, nil, err
		}
	}
	if len(updated) > limit {
		return nil, nil, nil, control("config-too-large", exitUnverify)
	}
	state := "unchanged"
	if len(changes) > 0 {
		state = "preview"
	}
	// changed_sections keeps the POLICY_KEYS order, with the profile patch last.
	changedSections := []string{}
	for _, key := range policyKeys {
		if _, isChange := changes[key]; isChange {
			changedSections = append(changedSections, key)
		}
	}
	if _, isChange := changes["profile"]; isChange {
		changedSections = append(changedSections, "profile")
	}
	groupRows := []any{}
	for _, g := range anyList(changes["proxy-groups"]) {
		if gm, ok := g.(map[string]any); ok {
			name, err := label(gm["name"])
			if err != nil {
				return nil, nil, nil, err
			}
			gtype, err := label(gm["type"])
			if err != nil {
				return nil, nil, nil, err
			}
			groupRows = append(groupRows, map[string]any{"name": name, "type": gtype})
		}
	}
	ruleSource := anyList(data["rules"])
	if v, ok := changes["rules"]; ok {
		ruleSource = anyList(v)
	}
	summary := map[string]any{
		"changed_sections": changedSections,
		"state":            state,
		"groups":           groupRows,
		"rule_count":       len(ruleSource),
		"service":          "unchanged",
	}
	return text, updated, summary, nil
}

func sortedChangeKeys(changes map[string]any) []string {
	keys := make([]string, 0, len(changes))
	for k := range changes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

var _ = sortedChangeKeys

func memberString(values []string, v string) bool {
	for _, s := range values {
		if s == v {
			return true
		}
	}
	return false
}

func containsString(values []string, v string) bool { return memberString(values, v) }

// receiptPath is the restart receipt beside the core configuration.
func receiptPath(configPath string) string {
	return configPath + ".userctl-state.json"
}

// applyPolicy validates and commits a reviewed candidate inside a durable
// transaction: security envelope, isolated core -t validation, stale refusal,
// then journaled atomic writes of the configuration, the afterWrite hook's
// files and the restart receipt. Any failure — including one after the
// configuration was published — rolls every file back with its metadata; a
// failing rollback is reported as rollback-failed, never downgraded.
func applyPolicy(ctx context.Context, a platform.App, m coreManager, configPath, homeDir string, original, updated []byte, afterWrite func(*fileTransaction) error) (map[string]any, error) {
	if bytes.Equal(original, updated) && afterWrite == nil {
		return map[string]any{"state": "unchanged", "service": "unchanged"}, nil
	}
	if err := a.Scope.RequireMutation(); err != nil {
		return nil, control(platform.SafeError(err), exitUnverify)
	}
	system := a.Scope.System
	beforeDoc, err := platform.DecodeYAML(original)
	if err != nil {
		return nil, controllerFileError(err)
	}
	afterDoc, err := platform.DecodeYAML(updated)
	if err != nil {
		return nil, controllerFileError(err)
	}
	if err := assertSecurityEnvelope(beforeDoc, afterDoc); err != nil {
		return nil, err
	}
	var result map[string]any
	result, err = runFileTransaction(ctx, a.Scope, "policy-apply", system, func(tx *fileTransaction) (map[string]any, error) {
		if err := validateCandidateText(ctx, a, m, updated); err != nil {
			return nil, err
		}
		if err := platform.CheckPath(configPath); err != nil {
			return nil, controllerFileError(err)
		}
		current, err := readManagedText(configPath, system)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(current, original) {
			return nil, control("config-changed-during-policy-edit", exitUnverify)
		}
		mode := os.FileMode(0600)
		if system {
			mode = 0640
		}
		if err := tx.writeBytes(configPath, updated, mode); err != nil {
			return nil, err
		}
		if afterWrite != nil {
			if err := afterWrite(tx); err != nil {
				return nil, err
			}
		}
		receipt := map[string]any{"state": "restart-required", "service": "unchanged", "sha256": hashSHA256(updated)}
		raw, err := json.MarshalIndent(receipt, "", "  ")
		if err != nil {
			return nil, control("config-write-failed-original-restored", exitUnverify)
		}
		// A receipt failure rolls the whole operation back, exactly like the
		// original transaction; it is not a warning.
		if err := tx.writeBytes(receiptPath(configPath), append(raw, '\n'), 0600); err != nil {
			return nil, err
		}
		return map[string]any{"state": "restart-required", "service": "unchanged"}, nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// pendingState reads the restart receipt; an empty result means "not pending".
func pendingState(configPath string) (map[string]any, error) {
	path := receiptPath(configPath)
	if _, err := os.Lstat(path); err != nil {
		if os.IsNotExist(err) {
			return map[string]any{}, nil
		}
		return nil, controllerFileError(err)
	}
	st, err := os.Lstat(path)
	if err != nil {
		return nil, controllerFileError(err)
	}
	if st.Size() > 4096 {
		return nil, control("configuration-receipt-invalid", exitUnverify)
	}
	b, err := platform.ReadPrivate(path)
	if err != nil {
		return nil, controllerFileError(err)
	}
	var value map[string]any
	if json.Unmarshal(b, &value) != nil || value == nil {
		return nil, control("configuration-receipt-invalid", exitUnverify)
	}
	if err := platform.CheckPath(configPath); err != nil {
		return nil, controllerFileError(err)
	}
	current, err := platform.ReadPrivate(configPath)
	if err != nil {
		return nil, controllerFileError(err)
	}
	if hashSHA256(current) != platformString(value["sha256"]) {
		return map[string]any{}, nil
	}
	delete(value, "backup")
	delete(value, "backup_sha256")
	return value, nil
}
