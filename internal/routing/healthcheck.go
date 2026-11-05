package routing

import (
	"net"
	"regexp"
	"strconv"
	"strings"
)

// probeOption is one CLI probe option (health-check --url etc.).
type probeOptions map[string]string

var statusPattern = regexp.MustCompile(`^[1-5][0-9]{2}(-[1-5][0-9]{2})?(/[1-5][0-9]{2}(-[1-5][0-9]{2})?)*$`)

var publicHTTPSChar = regexp.MustCompile(`^[\x21-\x7e]+$`)

var credentialKVPattern = regexp.MustCompile(`(?i)(password|secret|token|uuid|key)\s*[:=]`)
var userinfoAtPattern = regexp.MustCompile(`[^\s:]+:[^\s@]+@`)

// publicHTTPSURL mirrors probes.public_https_url: a public HTTPS target
// without credentials, query or fragment.
func publicHTTPSURL(raw string) bool {
	if strings.ContainsAny(raw, "\x00") || raw == "" {
		return false
	}
	for _, r := range raw {
		if r < 33 || r == 127 {
			return false
		}
	}
	scheme, rest, ok := strings.Cut(raw, "://")
	if !ok || !strings.EqualFold(scheme, "https") {
		return false
	}
	authority, _, _ := strings.Cut(rest, "/")
	if strings.Contains(authority, "@") || userinfoAtPattern.MatchString(raw) || credentialKVPattern.MatchString(raw) {
		return false
	}
	if pathQuery, _, found := strings.Cut(rest, "?"); found {
		_ = pathQuery
		return false
	}
	if strings.Contains(rest, "#") {
		return false
	}
	hostname := authority
	if strings.HasPrefix(hostname, "[") {
		end := strings.Index(hostname, "]")
		if end < 0 {
			return false
		}
		if end+1 < len(hostname) && hostname[end+1] != ':' {
			return false
		}
		hostname = hostname[1:end]
	} else if i := strings.LastIndex(hostname, ":"); i >= 0 {
		if _, err := strconv.Atoi(hostname[i+1:]); err == nil {
			hostname = hostname[:i]
		}
	}
	port := 443
	if i := strings.LastIndex(authority, ":"); i >= 0 && !strings.Contains(authority[i:], "]") {
		if p, err := strconv.Atoi(authority[i+1:]); err == nil {
			port = p
		}
	}
	if port < 1 || port > 65535 {
		return false
	}
	hostname = strings.ToLower(strings.TrimSuffix(hostname, "."))
	if hostname == "" || hostname == "localhost" || strings.HasSuffix(hostname, ".localhost") || strings.HasSuffix(hostname, ".local") {
		return false
	}
	if !strings.Contains(hostname, ".") {
		return false
	}
	if ip := net.ParseIP(hostname); ip != nil {
		return ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsUnspecified()
	}
	for _, label := range strings.Split(hostname, ".") {
		if label == "" || len(label) > 63 || !validHostnameLabel(label) {
			return false
		}
	}
	_ = publicHTTPSChar
	return true
}

func validHostnameLabel(label string) bool {
	for i, r := range label {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case r == '-' && i > 0 && i < len(label)-1:
		default:
			return false
		}
	}
	return true
}

// validStatusRange validates an expected-status expression.
func validStatusRange(value string) bool {
	if !statusPattern.MatchString(value) {
		return false
	}
	for _, part := range strings.Split(value, "/") {
		bounds := strings.Split(part, "-")
		lo, _ := strconv.Atoi(bounds[0])
		hi := lo
		if len(bounds) == 2 {
			hi, _ = strconv.Atoi(bounds[1])
		}
		if lo > hi {
			return false
		}
	}
	return true
}

var probeFields = []string{"url", "expected-status", "interval", "timeout", "lazy", "tolerance"}

// settingsDTO projects probe settings safely: imported URLs may carry
// account-specific tokens.
func settingsDTO(value map[string]any) map[string]any {
	result := map[string]any{}
	for _, key := range append([]string{"enable"}, probeFields...) {
		item, ok := value[key]
		if !ok {
			continue
		}
		switch key {
		case "url":
			if s, ok := item.(string); ok && publicHTTPSURL(s) {
				result[key] = s
			} else {
				result[key] = "[redacted: non-public-or-credential-url]"
			}
		case "enable", "lazy":
			if b, ok := item.(bool); ok {
				result[key] = b
			} else {
				result[key] = "[invalid]"
			}
		case "expected-status":
			valid := false
			if n, ok := item.(int); ok && n >= 100 && n <= 599 {
				valid = true
			} else if s, ok := item.(string); ok && validStatusRange(s) {
				valid = true
			}
			if valid {
				result[key] = item
			} else {
				result[key] = "[invalid]"
			}
		default:
			if n, ok := item.(int); ok && n >= 0 && n <= 2147483647 {
				result[key] = n
			} else if f, ok := item.(float64); ok && f == float64(int(f)) && f >= 0 && f <= 2147483647 {
				result[key] = int(f)
			} else {
				result[key] = "[invalid]"
			}
		}
	}
	return result
}

// probeOverwrites reports routing probe settings an input would replace.
func probeOverwrites(before, after map[string]any) []map[string]any {
	result := []map[string]any{}
	oldGroups := map[string]map[string]any{}
	for _, g := range anyList(before["proxy-groups"]) {
		if gm, ok := g.(map[string]any); ok {
			if n, ok := gm["name"].(string); ok {
				oldGroups[n] = gm
			}
		}
	}
	newGroups := map[string]map[string]any{}
	for _, g := range anyList(after["proxy-groups"]) {
		if gm, ok := g.(map[string]any); ok {
			if n, ok := gm["name"].(string); ok {
				newGroups[n] = gm
			}
		}
	}
	for name, old := range oldGroups {
		new := newGroups[name]
		if new == nil {
			new = map[string]any{}
		}
		changed := false
		for _, f := range probeFields {
			ov, ohad := old[f]
			nv, nhad := new[f]
			if ohad != nhad || !sameValue(ov, nv) {
				changed = true
			}
		}
		if changed {
			result = append(result, map[string]any{
				"scope":  "group",
				"name":   name,
				"before": settingsDTO(old),
				"after":  settingsDTO(new),
			})
		}
	}
	for name, old := range anyMap(before["proxy-providers"]) {
		om, ok := old.(map[string]any)
		if !ok {
			continue
		}
		previous := anyMap(om["health-check"])
		var current map[string]any
		if afterProviders := anyMap(after["proxy-providers"]); afterProviders != nil {
			if nm, ok := afterProviders[name].(map[string]any); ok {
				current = anyMap(nm["health-check"])
			}
		}
		if current == nil {
			current = map[string]any{}
		}
		if !sameValue(previous, current) {
			result = append(result, map[string]any{
				"scope":  "provider",
				"name":   name,
				"before": settingsDTO(previous),
				"after":  settingsDTO(current),
			})
		}
	}
	return result
}

func anyList(v any) []any {
	if l, ok := v.([]any); ok {
		return l
	}
	return nil
}

func anyMap(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

// healthCandidate previews a group/provider probe-settings change. It
// returns the updated config text and the preview document.
func healthCandidate(text []byte, data map[string]any, scope, name string, options probeOptions) ([]byte, map[string]any, error) {
	if scope != "group" && scope != "provider" {
		return nil, nil, control("invalid-health-check-options", exitUnverify)
	}
	if _, err := label(name); err != nil {
		return nil, nil, err
	}
	groups := deepCopyList(anyList(data["proxy-groups"]))
	providers := deepCopyMap(anyMap(data["proxy-providers"]))
	var target map[string]any
	section := ""
	if scope == "group" {
		found := []map[string]any{}
		for _, g := range groups {
			gm, ok := g.(map[string]any)
			if !ok {
				continue
			}
			if n, _ := gm["name"].(string); n == name {
				found = append(found, gm)
			}
		}
		if len(found) != 1 {
			return nil, nil, control("health-check-requires-existing-automatic-group", exitFail)
		}
		if t, _ := found[0]["type"].(string); t != "url-test" && t != "fallback" {
			return nil, nil, control("health-check-requires-existing-automatic-group", exitFail)
		}
		target = found[0]
		section = "proxy-groups"
	} else {
		provider, ok := providers[name].(map[string]any)
		if !ok {
			return nil, nil, control("health-check-provider-missing", exitFail)
		}
		hc, exists := provider["health-check"].(map[string]any)
		if !exists {
			hc = map[string]any{}
			provider["health-check"] = hc
		} else if provider["health-check"] == nil {
			return nil, nil, control("health-check-provider-settings-invalid", exitUnverify)
		}
		target = hc
		section = "proxy-providers"
	}
	before := deepCopyMap(target)
	updates := map[string]any{}
	if preset, ok := options["preset"]; ok {
		if preset != "resilient" {
			return nil, nil, control("invalid-health-check-preset", exitUnverify)
		}
		updates = map[string]any{"url": testURL, "expected-status": "204", "interval": 120, "timeout": 5000, "lazy": false}
		if scope == "provider" {
			updates["enable"] = true
		} else if t, _ := target["type"].(string); t == "url-test" {
			updates["tolerance"] = 50
		}
	}
	optionError := func(key string) error { return control("invalid-health-check-"+key, exitFail) }
	for _, key := range probeFields {
		value, ok := options[key]
		if !ok {
			continue
		}
		switch key {
		case "url":
			if !publicHTTPSURL(value) {
				return nil, nil, control("health-check-requires-public-https-without-credentials-or-query", exitFail)
			}
			updates["url"] = value
		case "expected-status":
			if !validStatusRange(value) {
				return nil, nil, optionError(key)
			}
			updates["expected-status"] = value
		case "interval", "timeout", "tolerance":
			n, err := strconv.Atoi(value)
			if err != nil {
				return nil, nil, optionError(key)
			}
			low, high := 1, 2147483647
			if key == "tolerance" {
				low, high = 0, 65535
			}
			if n < low || n > high {
				return nil, nil, optionError(key)
			}
			updates[key] = n
		case "lazy":
			switch value {
			case "true":
				updates["lazy"] = true
			case "false":
				updates["lazy"] = false
			default:
				return nil, nil, optionError(key)
			}
		}
	}
	if _, ok := updates["tolerance"]; ok {
		if scope != "group" {
			return nil, nil, control("tolerance-requires-url-test-group", exitFail)
		}
		if t, _ := target["type"].(string); t != "url-test" {
			return nil, nil, control("tolerance-requires-url-test-group", exitFail)
		}
	}
	for k, v := range updates {
		target[k] = v
	}
	changed := !sameValue(before, target)
	updated := text
	var err error
	if changed {
		sectionValue := any(providers)
		if scope == "group" {
			sectionValue = any(groups)
		}
		updated, err = patchCoreConfig(text, map[string]any{section: sectionValue})
		if err != nil {
			return nil, nil, err
		}
		if len(updated) > limit {
			return nil, nil, control("config-too-large", exitUnverify)
		}
	}
	var references []string
	probeProviders := map[string]any{}
	if scope == "provider" {
		references = []string{}
		for _, g := range groups {
			gm, ok := g.(map[string]any)
			if !ok {
				continue
			}
			for _, u := range anyList(gm["use"]) {
				if s, ok := u.(string); ok && s == name {
					if n, ok := gm["name"].(string); ok {
						references = append(references, n)
					}
				}
			}
		}
	} else {
		for _, u := range anyList(target["use"]) {
			if s, ok := u.(string); ok {
				if pm, ok := providers[s].(map[string]any); ok {
					probeProviders[s] = settingsDTO(anyMap(pm["health-check"]))
				}
			}
		}
	}
	state := "unchanged"
	if changed {
		state = "preview"
	}
	warnings := []any{}
	if len(probeProviders) > 0 {
		warnings = append(warnings, "provider-scheduling-may-control-use-members")
	}
	beforeDTO := settingsDTO(before)
	afterDTO := settingsDTO(target)
	if scope == "provider" {
		if _, ok := beforeDTO["enable"]; !ok {
			beforeDTO["enable"] = false
		}
		if _, ok := afterDTO["enable"]; !ok {
			afterDTO["enable"] = false
		}
		warnings = append(warnings, "shared-provider-probes-affect-referencing-groups")
		if enable, _ := afterDTO["enable"].(bool); !enable && len(updates) > 0 {
			warnings = append(warnings, "provider-health-check-disabled-use-resilient-preset-to-enable")
		}
	}
	result := map[string]any{
		"kind":              "health-check",
		"scope":             scope,
		"name":              name,
		"state":             state,
		"service":           "unchanged",
		"before":            beforeDTO,
		"after":             afterDTO,
		"affected_groups":   references,
		"provider_settings": probeProviders,
		"warnings":          warnings,
	}
	return updated, result, nil
}

func deepCopyList(src []any) []any {
	out := make([]any, len(src))
	for i, v := range src {
		out[i] = deepCopyValue(v)
	}
	return out
}

func deepCopyMap(src map[string]any) map[string]any {
	out := make(map[string]any, len(src))
	for k, v := range src {
		out[k] = deepCopyValue(v)
	}
	return out
}

func deepCopyValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		return deepCopyMap(t)
	case []any:
		return deepCopyList(t)
	default:
		return v
	}
}
