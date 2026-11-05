package routing

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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

// The read-only custom-rule contract: three payload files under a private
// rules directory, referenced by fixed file providers and RULE-SET rules.
const rulesMaxFile = 4 * 1024 * 1024
const rulesMaxCount = 100000

var rulesFiles = []string{"custom-direct.yaml", "custom-proxy.yaml", "custom-reject.yaml"}

var rulesProviders = map[string]struct {
	file   string
	target string
}{
	"custom-direct": {"custom-direct.yaml", "DIRECT"},
	"custom-proxy":  {"custom-proxy.yaml", "Proxy"},
	"custom-reject": {"custom-reject.yaml", "REJECT"},
}

// ruleError mirrors the checker's own error type: usage and "unsupported"/
// "unverified" codes exit 2 (UNVERIFIED), everything else exits 1 (FAIL).
type ruleError struct {
	code  string
	usage bool
}

func (e *ruleError) Error() string { return e.code }

func ruleFail(code string) error  { return &ruleError{code: code} }
func ruleUsage(code string) error { return &ruleError{code: code, usage: true} }
func ruleErrorRC(err error) int {
	if e, ok := err.(*ruleError); ok {
		if e.usage || strings.Contains(e.code, "unsupported") || strings.Contains(e.code, "unverified") {
			return exitUnverify
		}
		return exitFail
	}
	return exitUnverify
}

var rulesControlChars = regexp.MustCompile("[\x00-\x1f\x7f]")
var rulesTopSection = regexp.MustCompile(`^(?:rule-providers|proxy-groups|rules):[ ]+\S`)
var rulesSectionKey = regexp.MustCompile(`^([A-Za-z0-9_-]+):$`)
var rulesProviderName = regexp.MustCompile(`^([^:]+):$`)
var rulesProviderProp = regexp.MustCompile(`^([A-Za-z0-9_-]+):[ ]+(.+)$`)
var rulesGroupName = regexp.MustCompile(`^-[ ]+name:[ ]+(.+)$`)
var rulesRuleLine = regexp.MustCompile(`^-[ ]+(.+)$`)
var rulesItem = regexp.MustCompile(`^ {0,8}-[ ]+[^#\s].*$`)

// safeAbsolute rejects relative, parent-escaping and control-character paths,
// then symlinked components.
func safeAbsolute(raw, name string) (string, error) {
	if !filepath.IsAbs(raw) || rulesControlChars.MatchString(raw) {
		return "", ruleUsage(name + "-must-be-safe-absolute-path")
	}
	for _, part := range strings.Split(filepath.ToSlash(filepath.Clean(raw)), "/") {
		if part == ".." {
			return "", ruleUsage(name + "-must-be-safe-absolute-path")
		}
	}
	for current := filepath.Clean(raw); ; {
		if st, err := os.Lstat(current); err == nil && st.Mode()&os.ModeSymlink != 0 {
			return "", ruleFail(name + "-symlink-not-supported")
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	return filepath.Clean(raw), nil
}

// inspectOwned checks a rules-tree path is the expected type, owned by the
// acting account with the exact expected mode (POSIX platforms).
func inspectOwned(path string, expectedMode os.FileMode, kind string, wantDir bool) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, ruleFail(kind + "-missing-or-unreadable")
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, ruleFail(kind + "-symlink-not-supported")
	}
	if info.IsDir() != wantDir {
		return nil, ruleFail(kind + "-wrong-type")
	}
	if !rulesOwnershipExact() {
		return info, nil
	}
	if err := rulesOwnerCheck(info, kind); err != nil {
		return nil, err
	}
	if info.Mode().Perm() != expectedMode {
		return nil, ruleFail(kind + "-mode-must-be-" + fmt.Sprintf("%o", expectedMode.Perm()))
	}
	return info, nil
}

// parseRuleFile validates one payload file and returns its status row.
func parseRuleFile(path string) (map[string]any, error) {
	info, err := inspectOwned(path, 0600, "rule-file", false)
	if err != nil {
		return nil, err
	}
	if info.Size() > rulesMaxFile {
		return nil, ruleFail("rule-file-size-limit-exceeded")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, ruleFail("rule-file-must-be-utf8")
	}
	if !utf8ValidBytes(data) {
		return nil, ruleFail("rule-file-must-be-utf8")
	}
	text := string(data)
	if strings.Contains(text, "\x00") || strings.Contains(text, "\t") {
		return nil, ruleFail("rule-file-unsupported-yaml")
	}
	payload := 0
	count := 0
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSuffix(line, "\r")
		stripped := strings.TrimSpace(line)
		if stripped == "" || strings.HasPrefix(stripped, "#") {
			continue
		}
		if line == "payload:" {
			payload++
			continue
		}
		if payload == 1 && rulesItem.MatchString(line) {
			item := strings.TrimLeft(strings.SplitN(line, "-", 2)[1], " \t")
			for _, prefix := range []string{"[", "{", "&", "*", "!", "<<:"} {
				if strings.HasPrefix(item, prefix) {
					return nil, ruleFail("rule-file-unsupported-yaml")
				}
			}
			count++
			if count > rulesMaxCount {
				return nil, ruleFail("rule-count-limit-exceeded")
			}
			continue
		}
		return nil, ruleFail("rule-file-unsupported-yaml")
	}
	if payload != 1 || count == 0 {
		return nil, ruleFail("rule-file-invalid-payload")
	}
	return map[string]any{
		"name":         filepath.Base(path),
		"exists":       true,
		"rules":        count,
		"sha256":       hashSHA256(data),
		"modified_utc": isoTimestamp(info.ModTime()),
		"mode":         "600",
		"status":       "PASS",
	}, nil
}

func utf8ValidBytes(data []byte) bool {
	for i := 0; i < len(data); {
		if data[i] < 0x80 {
			i++
			continue
		}
		r, size := decodeRune(data[i:])
		if r < 0 {
			return false
		}
		i += size
	}
	return true
}

// decodeRune decodes one UTF-8 rune without pulling in unicode/utf8 naming
// conflicts; returns -1 on invalid encoding.
func decodeRune(b []byte) (int, int) {
	if len(b) == 0 {
		return -1, 0
	}
	first := b[0]
	if first < 0x80 {
		return int(first), 1
	}
	var width int
	switch {
	case first&0xE0 == 0xC0:
		width = 2
	case first&0xF0 == 0xE0:
		width = 3
	case first&0xF8 == 0xF0:
		width = 4
	default:
		return -1, 0
	}
	if len(b) < width {
		return -1, 0
	}
	rune := int(first & (0x7F >> uint(width)))
	for i := 1; i < width; i++ {
		if b[i]&0xC0 != 0x80 {
			return -1, 0
		}
		rune = rune<<6 | int(b[i]&0x3F)
	}
	return rune, width
}

// isoTimestamp renders mtime like Python's UTC isoformat.
func isoTimestamp(t time.Time) string {
	t = t.UTC()
	text := t.Format("2006-01-02T15:04:05")
	if t.Nanosecond() != 0 {
		text += fmt.Sprintf(".%06d", t.Nanosecond()/1000)
	}
	return text + "+00:00"
}

// fileStatus maps a payload parse failure to its per-file row.
func fileStatus(path string) map[string]any {
	row, err := parseRuleFile(path)
	if err == nil {
		return row
	}
	code := err.(*ruleError).code
	exists := false
	if info, statErr := os.Lstat(path); statErr == nil && info.Mode()&os.ModeSymlink == 0 {
		exists = true
	}
	status := "FAIL"
	if strings.Contains(code, "unsupported") {
		status = "UNVERIFIED"
	}
	return map[string]any{
		"name":         filepath.Base(path),
		"exists":       exists,
		"rules":        nil,
		"sha256":       nil,
		"modified_utc": nil,
		"mode":         nil,
		"status":       status,
		"error":        code,
	}
}

// stripComment removes a trailing comment, honoring quotes.
func stripComment(line string) (string, error) {
	quote := rune(0)
	escaped := false
	var result []byte
	for index := 0; index < len(line); index++ {
		char := rune(line[index])
		if quote == '"' && char == '\\' && !escaped {
			escaped = true
			result = append(result, line[index])
			continue
		}
		if (char == '\'' || char == '"') && !escaped {
			switch {
			case quote == char:
				quote = 0
			case quote == 0:
				quote = char
			}
		}
		if char == '#' && quote == 0 && (index == 0 || isSpaceByte(line[index-1])) {
			break
		}
		result = append(result, line[index])
		escaped = false
	}
	if quote != 0 {
		return "", ruleFail("config-unsupported-yaml")
	}
	return strings.TrimRight(string(result), " \t\r\n"), nil
}

func isSpaceByte(b byte) bool {
	return b == ' ' || b == '\t' || b == '\r' || b == '\n' || b == '\v' || b == '\f'
}

// scalar validates a YAML scalar payload: no flow indicators or anchors.
func scalar(value string) (string, error) {
	value = strings.TrimSpace(value)
	if len(value) >= 2 && value[0] == value[len(value)-1] && (value[0] == '\'' || value[0] == '"') {
		value = value[1 : len(value)-1]
	}
	if value == "" || strings.ContainsAny(value, "{}[]&!\t\r\n") || strings.HasPrefix(value, "*") {
		return "", ruleFail("config-unsupported-yaml")
	}
	return value, nil
}

// parseConfig validates the rule-provider contract in the core config and
// reports whether the final MATCH fallback is missing.
func parseConfig(path string) (bool, error) {
	if _, err := inspectOwned(path, 0600, "config-file", false); err != nil {
		return false, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return false, ruleFail("config-must-be-utf8")
	}
	if info.Size() > rulesMaxFile {
		return false, ruleFail("config-size-limit-exceeded")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false, ruleFail("config-must-be-utf8")
	}
	if !utf8ValidBytes(data) {
		return false, ruleFail("config-must-be-utf8")
	}
	section := ""
	currentProvider := ""
	providers := map[string]map[string]string{}
	groups := map[string]bool{}
	type routedRule struct {
		name   string
		target string
		index  int
	}
	var routed []routedRule
	fallback := false
	for _, raw := range strings.Split(string(data), "\n") {
		raw = strings.TrimSuffix(raw, "\r")
		line, err := stripComment(raw)
		if err != nil {
			return false, err
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		if strings.Contains(line, "\t") {
			return false, ruleFail("config-unsupported-yaml")
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		content := strings.TrimSpace(line)
		if indent == 0 && rulesTopSection.MatchString(content) {
			return false, ruleFail("config-unsupported-yaml")
		}
		if indent == 0 {
			if match := rulesSectionKey.FindStringSubmatch(content); match != nil {
				section = match[1]
				currentProvider = ""
				continue
			}
		}
		switch section {
		case "rule-providers":
			if indent == 2 {
				if match := rulesProviderName.FindStringSubmatch(content); match != nil {
					name, err := scalar(match[1])
					if err != nil {
						return false, err
					}
					if _, dup := providers[name]; dup {
						return false, ruleFail("duplicate-rule-provider")
					}
					providers[name] = map[string]string{}
					currentProvider = name
					continue
				}
			}
			if indent == 4 && currentProvider != "" {
				if match := rulesProviderProp.FindStringSubmatch(content); match != nil {
					key := match[1]
					if _, dup := providers[currentProvider][key]; dup {
						return false, ruleFail("duplicate-provider-property")
					}
					value, err := scalar(match[2])
					if err != nil {
						return false, err
					}
					providers[currentProvider][key] = value
					continue
				}
			}
			if _, isRequired := rulesProviders[currentProvider]; isRequired {
				return false, ruleFail("config-unsupported-yaml")
			}
		case "proxy-groups":
			if match := rulesGroupName.FindStringSubmatch(content); match != nil {
				name, err := scalar(match[1])
				if err != nil {
					return false, err
				}
				groups[name] = true
			}
		case "rules":
			match := rulesRuleLine.FindStringSubmatch(content)
			if match == nil {
				return false, ruleFail("config-unsupported-yaml")
			}
			rule, err := scalar(match[1])
			if err != nil {
				return false, err
			}
			parts := strings.Split(rule, ",")
			for i, part := range parts {
				parts[i] = strings.TrimSpace(part)
			}
			if parts[0] == "RULE-SET" && len(parts) >= 3 {
				if _, known := rulesProviders[parts[1]]; known {
					routed = append(routed, routedRule{parts[1], parts[2], len(routed)})
				}
			}
			if parts[0] == "MATCH" {
				fallback = true
				target := ""
				if len(parts) > 1 {
					target = parts[1]
				}
				routed = append(routed, routedRule{"MATCH", target, len(routed)})
			}
		}
	}
	names := make([]string, 0, len(rulesProviders))
	for name := range rulesProviders {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		expected := rulesProviders[name]
		row, ok := providers[name]
		if !ok {
			return false, ruleFail("required-provider-missing")
		}
		if row["type"] != "file" || row["behavior"] != "classical" || row["format"] != "yaml" ||
			row["path"] != "./rules/"+expected.file {
			return false, ruleFail("provider-contract-mismatch")
		}
	}
	matchIndex := -1
	for _, rule := range routed {
		if rule.name == "MATCH" {
			matchIndex = rule.index
			break
		}
	}
	seen := map[string]int{}
	for _, rule := range routed {
		if rule.name == "MATCH" {
			continue
		}
		if _, dup := seen[rule.name]; dup {
			return false, ruleFail("duplicate-provider-rule")
		}
		seen[rule.name] = rule.index
		expectedTarget := rulesProviders[rule.name].target
		if rule.target != expectedTarget {
			if !groups[rule.target] && rule.target != "DIRECT" && rule.target != "REJECT" {
				return false, ruleFail("unknown-rule-target")
			}
			return false, ruleFail("provider-target-mismatch")
		}
		if matchIndex >= 0 && rule.index > matchIndex {
			return false, ruleFail("custom-rule-after-match")
		}
	}
	if len(seen) != len(rulesProviders) {
		return false, ruleFail("provider-rule-reference-missing")
	}
	if !groups["Proxy"] {
		return false, ruleFail("required-proxy-group-missing")
	}
	return !fallback, nil
}

// rulesConfigTest validates a private copy: the core may write caches and
// geodata while parsing, so the HomeDir is copied into staging first.
func rulesConfigTest(ctx context.Context, binary, home, configPath string, asUID int) error {
	staged, err := os.MkdirTemp("", "mihomoctl-go-rules-check-")
	if err != nil {
		return ruleFail("mihomo-config-test-unverified")
	}
	defer os.RemoveAll(staged)
	failure := ruleFail("mihomo-config-test-unverified")
	if err := copyRulesHome(home, filepath.Join(staged, "home")); err != nil {
		return err
	}
	configRaw, err := os.ReadFile(configPath)
	if err != nil {
		return failure
	}
	node, err := platform.StrictYAML(configRaw)
	if err != nil {
		return failure
	}
	providerRoot, err := os.MkdirTemp(filepath.Join(staged, "home"), ".validation-providers-")
	if err != nil {
		return failure
	}
	if err := rewriteProviderPaths(node, home, providerRoot); err != nil {
		return err
	}
	text, err := yaml.Marshal(node)
	if err != nil {
		return failure
	}
	candidate := filepath.Join(staged, "config.yaml")
	if err := platform.AtomicWrite(candidate, text, 0600); err != nil {
		return failure
	}
	if asUID > 0 {
		if err := chownTree(staged, asUID, asUID); err != nil {
			return failure
		}
	}
	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	cmd := execCommandContext(cctx, binary, "-t", "-d", filepath.Join(staged, "home"), "-f", candidate)
	cmd.Env = cleanChildEnvironment()
	validationIdentity(cmd, asUID)
	if err := cmd.Run(); err != nil {
		if cctx.Err() != nil {
			return failure
		}
		return ruleFail("mihomo-config-test-failed")
	}
	return nil
}

// execCommandContext builds the core validation command.
func execCommandContext(ctx context.Context, name string, args ...string) *execCmd {
	return exec.CommandContext(ctx, name, args...)
}

// copyRulesHome refuses symlinked or oversized trees and copies the rest.
func copyRulesHome(home, target string) error {
	var total int64
	err := filepath.Walk(home, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
			return ruleFail("rules-home-unsafe")
		}
		if info.Mode().IsRegular() {
			total += info.Size()
			if total > 256*1024*1024 {
				return ruleFail("rules-home-size-unverified")
			}
		}
		return nil
	})
	if err != nil {
		if _, isRule := err.(*ruleError); isRule {
			return err
		}
		return ruleFail("rules-home-unsafe")
	}
	return copyTree(home, target)
}

func copyTree(source, target string) error {
	return filepath.Walk(source, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		destination := filepath.Join(target, relative)
		if info.IsDir() {
			return os.MkdirAll(destination, 0700)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return platform.AtomicWrite(destination, data, 0600)
	})
}

// rewriteProviderPaths redirects every provider cache/file path into the
// private staging area, refusing paths that would escape it.
func rewriteProviderPaths(node *yaml.Node, home, providerRoot string) error {
	root := node.Content[0]
	for _, section := range []string{"proxy-providers", "rule-providers"} {
		sectionNode := mappingFind(root, section)
		if sectionNode == nil || sectionNode.Kind != yaml.MappingNode {
			continue
		}
		index := 0
		for i := 0; i+1 < len(sectionNode.Content); i += 2 {
			entry := sectionNode.Content[i+1]
			if entry.Kind != yaml.MappingNode {
				continue
			}
			pathNode := mappingFind(entry, "path")
			if pathNode == nil || pathNode.Tag != "!!str" {
				continue
			}
			original := pathNode.Value
			if original == "" || !filepath.IsAbs(original) {
				original = filepath.Join(home, original)
			}
			absolute, err := safeAbsolute(original, "provider-path")
			if err != nil {
				return err
			}
			target := filepath.Join(providerRoot, fmt.Sprintf("%d", index))
			index++
			if info, statErr := os.Lstat(absolute); statErr == nil {
				if !info.Mode().IsRegular() || info.Size() > 256*1024*1024 {
					return ruleFail("provider-file-size-or-type-unverified")
				}
				data, readErr := os.ReadFile(absolute)
				if readErr != nil {
					return ruleFail("mihomo-config-test-unverified")
				}
				if writeErr := platform.AtomicWrite(target, data, 0600); writeErr != nil {
					return ruleFail("mihomo-config-test-unverified")
				}
			}
			pathNode.Value = target
			pathNode.Tag = "!!str"
			pathNode.Style = yaml.DoubleQuotedStyle
		}
	}
	return nil
}

func mappingFind(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key && node.Content[i].Tag == "!!str" {
			return node.Content[i+1]
		}
	}
	return nil
}

// rulesDocument is the report shape the original checker printed.
func rulesDocument(command, overall string, payload map[string]any, errorCode string) map[string]any {
	document := map[string]any{
		"schema":  RulesSchema,
		"command": command,
		"overall": overall,
	}
	for key, value := range payload {
		document[key] = value
	}
	if errorCode != "" {
		document["error"] = map[string]any{"code": errorCode}
	}
	return document
}

// runRules executes "rules status|check" and returns the bridge data block.
func runRules(ctx context.Context, a platform.App, binary, action, homeDir, configPath string, asUID int) (map[string]any, string, int) {
	command := "rules-" + action
	var document map[string]any
	rc := 0
	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				document = rulesDocument(command, "UNVERIFIED", nil, "rules-operation-unavailable")
				rc = exitUnverify
			}
		}()
		home, err := safeAbsolute(homeDir, "home-dir")
		if err != nil {
			document, rc = rulesErrorDocument(command, err)
			return
		}
		config, err := safeAbsolute(configPath, "config")
		if err != nil {
			document, rc = rulesErrorDocument(command, err)
			return
		}
		if _, err := inspectOwned(filepath.Join(home, "rules"), 0700, "rules-directory", true); err != nil {
			document, rc = rulesErrorDocument(command, err)
			return
		}
		files := make([]any, 0, len(rulesFiles))
		for _, name := range rulesFiles {
			files = append(files, fileStatus(filepath.Join(home, "rules", name)))
		}
		if action == "status" {
			document, rc = rulesStatusDocument("rules-status", files)
			return
		}
		allPass := true
		for _, row := range files {
			if row.(map[string]any)["status"] != "PASS" {
				allPass = false
				break
			}
		}
		if !allPass {
			document, rc = rulesStatusDocument("rules-status", files)
			return
		}
		warning, err := parseConfig(config)
		if err != nil {
			document, rc = rulesErrorDocument(command, err)
			return
		}
		if err := rulesConfigTest(ctx, binary, home, config, asUID); err != nil {
			document, rc = rulesErrorDocument(command, err)
			return
		}
		document = rulesDocument("rules-check", "PASS", map[string]any{
			"read_only": true, "files": files, "fallback_warning": warning,
		}, "")
		rc = 0
	}()
	output, _ := json.Marshal(sortedJSON(document))
	data := map[string]any{"check": action, "exit": rc, "output": string(output) + "\n", "rules": document}
	overall := "PASS"
	if rc == 1 {
		overall = "FAIL"
	} else if rc == 2 {
		overall = "UNVERIFIED"
	}
	return data, overall, rc
}

func rulesErrorDocument(command string, err error) (map[string]any, int) {
	rc := ruleErrorRC(err)
	overall := "FAIL"
	if rc == exitUnverify {
		overall = "UNVERIFIED"
	}
	code := "rules-operation-unavailable"
	if ruleErr, ok := err.(*ruleError); ok {
		code = ruleErr.code
	}
	return rulesDocument(command, overall, nil, code), rc
}

func rulesStatusDocument(command string, files []any) (map[string]any, int) {
	overall := "PASS"
	for _, row := range files {
		switch row.(map[string]any)["status"] {
		case "FAIL":
			overall = "FAIL"
		case "UNVERIFIED":
			if overall == "PASS" {
				overall = "UNVERIFIED"
			}
		}
	}
	rc := 0
	switch overall {
	case "FAIL":
		rc = exitFail
	case "UNVERIFIED":
		rc = exitUnverify
	}
	return rulesDocument(command, overall, map[string]any{"files": files}, ""), rc
}

// sortedJSON renders a document deterministically like the original emitter.
func sortedJSON(value any) []byte {
	var buf bytes.Buffer
	writeSortedJSON(&buf, value)
	return buf.Bytes()
}

func writeSortedJSON(buf *bytes.Buffer, value any) {
	switch typed := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			encoded, _ := json.Marshal(key)
			buf.Write(encoded)
			buf.WriteByte(':')
			writeSortedJSON(buf, typed[key])
		}
		buf.WriteByte('}')
	case []any:
		buf.WriteByte('[')
		for i, item := range typed {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeSortedJSON(buf, item)
		}
		buf.WriteByte(']')
	default:
		encoded, _ := json.Marshal(typed)
		buf.Write(encoded)
	}
}
