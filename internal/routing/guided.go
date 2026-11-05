package routing

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/liuzq1103/mihomoctl/internal/platform"
	"github.com/liuzq1103/mihomoctl/internal/runtimecore"
	"gopkg.in/yaml.v3"
)

// guidedShape mirrors onboarding.guided_shape: only an untouched fresh
// configuration (no groups, MATCH,DIRECT) or our exact simple preset (one
// select group "Proxy" with only routing keys, MATCH,Proxy) qualifies for the
// guided onboarding flow.
func guidedShape(data map[string]any) bool {
	groups := anyList(data["proxy-groups"])
	rules := anyList(data["rules"])
	if len(groups) == 0 && len(rules) == 1 && rules[0] == "MATCH,DIRECT" {
		return true
	}
	if !(len(rules) == 1 && rules[0] == "MATCH,Proxy") {
		return false
	}
	if len(groups) != 1 {
		return false
	}
	group, ok := groups[0].(map[string]any)
	if !ok {
		return false
	}
	if group["name"] != "Proxy" || group["type"] != "select" {
		return false
	}
	for key := range group {
		if key != "name" && key != "type" && key != "proxies" && key != "use" {
			return false
		}
	}
	return true
}

// guidedPolicy mirrors onboarding.guided_policy: select the incoming
// nodes/providers without importing remote listener or host settings. The
// provider order preserves the subscription document's mapping order.
func guidedPolicy(incoming map[string]any, providerOrder []string) (map[string]any, error) {
	nodes := anyList(incoming["proxies"])
	providers := anyMap(incoming["proxy-providers"])
	if len(nodes) == 0 && len(providers) == 0 {
		return nil, control("subscription-node-list-invalid", exitFail)
	}
	for _, row := range nodes {
		node, ok := row.(map[string]any)
		if !ok {
			return nil, control("subscription-node-invalid", exitFail)
		}
		name, _ := node["name"].(string)
		if name == "Proxy" || name == "DIRECT" || name == "REJECT" {
			return nil, control("subscription-reserved-node-name-use-advanced", exitFail)
		}
	}
	members := make([]any, 0, len(nodes))
	for _, row := range nodes {
		node := row.(map[string]any)
		name, _ := node["name"].(string)
		members = append(members, name)
	}
	group := map[string]any{"name": "Proxy", "type": "select", "proxies": members}
	if len(providers) > 0 {
		use := []any{}
		if providerOrder != nil {
			for _, name := range providerOrder {
				if _, ok := providers[name]; ok {
					use = append(use, name)
				}
			}
		} else {
			names := make([]string, 0, len(providers))
			for name := range providers {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				use = append(use, name)
			}
		}
		group["use"] = use
	}
	changes := map[string]any{
		"proxies":         nodes,
		"proxy-providers": providers,
		"proxy-groups":    []any{group},
		"rules":           []any{"MATCH,Proxy"},
		"rule-providers":  map[string]any{},
	}
	return providerPolicy(changes)
}

// mappingKeyOrder extracts the key order of one top-level mapping from a
// strict YAML document, preserving how the source ordered its providers.
func mappingKeyOrder(content []byte, key string) []string {
	node, err := platform.StrictYAML(content)
	if err != nil || len(node.Content) == 0 {
		return nil
	}
	root := node.Content[0]
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value != key {
			continue
		}
		value := root.Content[i+1]
		if value.Kind != yaml.MappingNode {
			return nil
		}
		var order []string
		for j := 0; j+1 < len(value.Content); j += 2 {
			order = append(order, value.Content[j].Value)
		}
		return order
	}
	return nil
}

// expandSubscriptionPath mirrors Path.expanduser().absolute() for the guided
// file input: a leading ~ resolves against the home directory.
func expandSubscriptionPath(value string) string {
	if value == "~" || strings.HasPrefix(value, "~/") {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			return filepath.Join(home, strings.TrimPrefix(value, "~"))
		}
	}
	if absolute, err := filepath.Abs(value); err == nil {
		return absolute
	}
	return value
}

// VerifyController proves the controller endpoint before a caller opens
// direct API streams: the core configuration contract, the runtime ownership
// proof, the anonymous 401 refusal and the authorized probe — the identical
// verification every read command runs. It returns nil only when the session
// is proven; the error carries the stable control code (see ErrorCode).
func VerifyController(ctx context.Context, a platform.App) error {
	configPath, _, err := resolveRoutingContext(a, platform.Request{})
	if err != nil {
		return err
	}
	if _, err := verifiedClient(ctx, a, configPath); err != nil {
		return err
	}
	return nil
}

// ErrorCode exposes the stable control code of an error returned by this
// package, for callers that render diagnostics without the envelope bridge.
func ErrorCode(err error) string {
	switch typed := err.(type) {
	case *controlError:
		return typed.code
	case *platform.Error:
		return typed.Code
	}
	return ""
}

// ControllerConfig hands a proven caller everything needed for direct API
// streams: the loopback host, port, bearer token and the exact managed
// configuration path. The proof (scope-appropriate owner check — root-owned
// 0640 in system scope — plus the anonymous-401 refusal and authorized probe)
// always runs against the manager's recorded path, never a re-discovered
// file, so the token can never be minted from a mismatched configuration.
func ControllerConfig(ctx context.Context, a platform.App) (host string, port int, token, path string, err error) {
	configPath, _, err := resolveRoutingContext(a, platform.Request{})
	if err != nil {
		return "", 0, "", "", err
	}
	if _, err = verifiedClient(ctx, a, configPath); err != nil {
		return "", 0, "", "", err
	}
	text, err := readManagedText(configPath, a.Scope.System)
	if err != nil {
		return "", 0, "", "", err
	}
	data, err := platform.DecodeYAML(text)
	if err != nil {
		return "", 0, "", "", controllerFileError(err)
	}
	host, port, token, err = endpoint(data)
	if err != nil {
		return "", 0, "", "", err
	}
	return host, port, token, configPath, nil
}

// SubscriptionInput reproduces the controller_service.subscription_input
// onboarding entry used by the console and Textual front ends: the private
// URL or file value never reaches a subprocess or command line, the guided
// decision rewrites a fresh configuration to the single-"Proxy" preset while
// an existing routing setup is preserved through the nodes merge, exactly like
// the original. The returned envelope is the standard bridge document; the
// caller unwraps Data["legacy"].
func SubscriptionInput(ctx context.Context, a platform.App, value, kind, policy string) (platform.Envelope, error) {
	command, scope := "subscription", scopeLabel(a.Scope.System)
	if err := a.Scope.RequireMutation(); err != nil {
		return failureEnvelope(command, scope, err), nil
	}
	if kind == "" {
		kind = "url"
	}
	if policy == "" {
		policy = "simple"
	}
	configPath, manager, err := resolveRoutingContext(a, platform.Request{})
	if err != nil {
		return failureEnvelope(command, scope, err), nil
	}
	homeDir := a.Scope.CoreHome()
	var raw []byte
	if kind == "url" {
		if raw, err = download(ctx, strings.TrimSpace(value)); err != nil {
			return failureEnvelope(command, scope, err), nil
		}
	} else {
		path := expandSubscriptionPath(value)
		if err := platform.CheckPath(path); err != nil {
			return failureEnvelope(command, scope, controllerFileError(err)), nil
		}
		info, statErr := os.Lstat(path)
		if statErr != nil {
			return failureEnvelope(command, scope, controllerFileError(statErr)), nil
		}
		if info.Size() > limit {
			return failureEnvelope(command, scope, control("subscription-size-invalid", exitUnverify)), nil
		}
		if raw, err = platform.ReadPrivate(path); err != nil {
			return failureEnvelope(command, scope, controllerFileError(err)), nil
		}
	}
	// The guided decision reads the current configuration after the source is
	// already in hand, matching the original ordering (download errors first).
	simple := false
	if policy == "simple" {
		_, current, cfgErr := readCoreConfig(configPath, a.Scope.System)
		if cfgErr != nil {
			return failureEnvelope(command, scope, cfgErr), nil
		}
		simple = guidedShape(current)
	}
	effective := policy
	if policy == "simple" {
		if simple {
			effective = "provider"
		} else {
			effective = "nodes"
		}
	}
	subs := newSubscriptions(a, manager, configPath, homeDir, nil)
	payload, err := subs.previewRaw(ctx, raw, effective, effective, simple)
	if err != nil {
		return failureEnvelope(command, scope, err), nil
	}
	payload["guided"] = simple
	return bridgedEnvelope(command, scope, command, payload), nil
}

// SubscriptionDiscard reproduces controller_service.subscription_discard: the
// staged artifacts of one preview are dropped under the shared lock. The
// original returned no document; the explicit state row is the only addition.
func SubscriptionDiscard(ctx context.Context, a platform.App, identifier string) (platform.Envelope, error) {
	command, scope := "subscription", scopeLabel(a.Scope.System)
	if err := a.Scope.RequireMutation(); err != nil {
		return failureEnvelope(command, scope, err), nil
	}
	configPath, _, err := resolveRoutingContext(a, platform.Request{})
	if err != nil {
		return failureEnvelope(command, scope, err), nil
	}
	subs := newSubscriptions(a, coreManager{}, configPath, a.Scope.CoreHome(), nil)
	if err := subs.discard(ctx, identifier); err != nil {
		return failureEnvelope(command, scope, err), nil
	}
	return bridgedEnvelope(command, scope, command, map[string]any{"state": "discarded", "id": identifier}), nil
}

// SubscriptionSaveAndStart reproduces controller_service.subscription_save_and_start
// (subscription_apply with activate=True): the reviewed candidate is committed
// and the managed runtime is started and verified as one activation, not a
// save followed by a manual restart. The commit/start/verify/restore boundary
// is runtimecore.CommitAndStart — called sequentially here, never nested
// inside another held lock (the foundation flock is non-reentrant). On
// activation failure the original files and the original running/stopped
// state are restored by that boundary, and the staged plan stays on disk for
// retry, exactly like the original's transaction rollback. pending_restart is
// cleared: the receipt state is "ready", not "restart-required".
func SubscriptionSaveAndStart(ctx context.Context, a platform.App, identifier, digest string) (platform.Envelope, error) {
	command, scope := "subscription", scopeLabel(a.Scope.System)
	if err := a.Scope.RequireMutation(); err != nil {
		return failureEnvelope(command, scope, err), nil
	}
	configPath, manager, err := resolveRoutingContext(a, platform.Request{})
	if err != nil {
		return failureEnvelope(command, scope, err), nil
	}
	subs := newSubscriptions(a, manager, configPath, a.Scope.CoreHome(), nil)
	original, candidate, err := subs.validateStaged(ctx, identifier, digest)
	if err != nil {
		return failureEnvelope(command, scope, err), nil
	}
	activated, err := runtimecore.CommitAndStart(ctx, a, configPath, original, candidate)
	if err != nil {
		// The boundary restored the prior files and runtime state; the staged
		// plan is deliberately retained for a retry.
		return failureEnvelope(command, scope, err), nil
	}
	payload := map[string]any{}
	for key, value := range activated {
		payload[key] = value
	}
	payload["id"] = identifier
	payload["sha256"] = digest
	if applied, ok := payload["sha256"].(string); ok && applied != "" {
		payload["applied_sha256"] = applied
	}
	// Baseline receipt of a verified activation (controller_transaction
	// apply_policy activate=True): state "ready", activation verified.
	payload["state"] = "ready"
	payload["action"] = "start"
	payload["overall"] = "PASS"
	payload["config_state"] = "committed"
	payload["activation_state"] = "verified"
	payload["runtime_state"] = "running"
	payload["restart_required"] = false
	// Phase 3 (locked): drop the staged artifacts, reporting the activation
	// axes if the cleanup itself cannot complete.
	err = platform.WithLock(ctx, a.Scope, func() error {
		return subs.cleanup(identifier)
	})
	if err != nil {
		configState := "changed"
		if current, readErr := platform.ReadPrivate(configPath); readErr == nil && hashSHA256(current) == digest {
			configState = "committed"
		}
		return failureEnvelope(command, scope, &controlError{
			code:       "subscription-cleanup-incomplete",
			rc:         exitUnverify,
			safeDetail: fmt.Sprintf("phase=cleanup; config=%s; runtime=running; activation=verified", configState),
		}), nil
	}
	return bridgedEnvelope(command, scope, command, payload), nil
}
