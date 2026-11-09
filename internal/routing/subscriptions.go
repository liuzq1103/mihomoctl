package routing

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

// dialer15 bounds the subscription TCP connection setup like the original
// HTTPSConnection(timeout=15).
type dialer15 struct{}

func (d *dialer15) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	var dialer net.Dialer
	dialer.Timeout = 15 * time.Second
	return dialer.DialContext(ctx, network, address)
}

// policyField describes one routing-policy field the subscription contract
// recognizes, with the shape it must have.
type policyField struct {
	name   string
	isDict bool
}

var policyFields = []policyField{
	{"proxies", false},
	{"proxy-providers", true},
	{"proxy-groups", false},
	{"rules", false},
	{"rule-providers", true},
}

var routingFields = map[string]bool{
	"proxy-providers": true, "proxy-groups": true, "rules": true, "rule-providers": true,
}

var overlayFields = map[string]bool{
	"proxy-groups": true, "rules": true, "rule-providers": true,
}

var subscriptionNamePattern = regexp.MustCompile(`^[a-f0-9]{32}\.(raw\.yaml|candidate\.yaml|json)$`)
var subscriptionIDPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)
var subscriptionHashPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

// providerTreeRoots are the only first-level trees under the core home where
// downloaded provider caches may live.
var providerTreeRoots = map[string]bool{
	"providers": true, "proxy-providers": true, "proxy_provider": true, "proxy_providers": true,
	"rules": true, "rule-providers": true, "rule_provider": true, "rule_providers": true,
}

// policyOverlay validates the "policy" overlay input: only routing sections,
// validated against the complete merged result.
func policyOverlay(incoming map[string]any, current map[string]any) (map[string]any, error) {
	if len(incoming) == 0 {
		return nil, control("subscription-policy-overlay-fields-only", exitFail)
	}
	for key := range incoming {
		if !overlayFields[key] {
			return nil, control("subscription-policy-overlay-fields-only", exitFail)
		}
	}
	merged := make(map[string]any, len(current)+len(incoming))
	for key, value := range current {
		merged[key] = value
	}
	for key, value := range incoming {
		merged[key] = value
	}
	if _, err := providerPolicy(merged); err != nil {
		return nil, err
	}
	return incoming, nil
}

// providerPolicy validates a full provider-mode policy document, defaulting
// absent fields to empty and checking every reference. It returns the complete
// five-field change set.
func providerPolicy(incoming map[string]any) (map[string]any, error) {
	known := false
	for _, field := range policyFields {
		if _, ok := incoming[field.name]; ok {
			known = true
		}
	}
	if !known {
		return nil, control("subscription-routing-policy-missing", exitFail)
	}
	changes := map[string]any{}
	for _, field := range policyFields {
		value, ok := incoming[field.name]
		if !ok {
			if field.isDict {
				changes[field.name] = map[string]any{}
			} else {
				changes[field.name] = []any{}
			}
			continue
		}
		if field.isDict {
			if _, valid := value.(map[string]any); !valid {
				return nil, control("subscription-policy-shape-invalid", exitFail)
			}
		} else if _, valid := value.([]any); !valid {
			return nil, control("subscription-policy-shape-invalid", exitFail)
		}
		changes[field.name] = value
	}
	names := map[string]bool{"DIRECT": true, "REJECT": true, "REJECT-DROP": true, "PASS": true, "COMPATIBLE": true}
	for _, section := range []string{"proxies", "proxy-groups"} {
		for _, row := range anyList(changes[section]) {
			entry, ok := row.(map[string]any)
			if !ok {
				return nil, control("subscription-policy-entry-invalid", exitFail)
			}
			if _, ok := entry["type"].(string); !ok {
				return nil, control("subscription-policy-entry-invalid", exitFail)
			}
			name, err := label(entry["name"])
			if err != nil {
				return nil, err
			}
			if name == "" || names[name] {
				return nil, control("subscription-policy-name-invalid", exitFail)
			}
			names[name] = true
		}
	}
	// Mihomo permits replacing its implicit GLOBAL group with an explicit one.
	names["GLOBAL"] = true
	for _, section := range []string{"proxy-providers", "rule-providers"} {
		for name, row := range anyMap(changes[section]) {
			if _, err := label(name); err != nil {
				return nil, err
			}
			entry, ok := row.(map[string]any)
			if !ok {
				return nil, control("subscription-provider-invalid", exitFail)
			}
			path, hasPath := entry["path"]
			if hasPath && path != nil {
				text, ok := path.(string)
				if !ok || text == "" || strings.Contains(text, "\\") || strings.Contains(text, ":") ||
					strings.HasPrefix(text, "/") || providerPathHasParent(text) {
					return nil, control("subscription-provider-path-unsafe", exitFail)
				}
			}
			if fileProviderWithoutPath(entry, hasPath, path) {
				return nil, control("subscription-provider-path-required", exitFail)
			}
		}
	}
	providerNames := map[string]bool{}
	for name := range anyMap(changes["proxy-providers"]) {
		providerNames[name] = true
	}
	for _, row := range anyList(changes["proxy-groups"]) {
		group, ok := row.(map[string]any)
		if !ok {
			continue
		}
		if raw, exists := group["proxies"]; exists {
			if _, isList := raw.([]any); !isList {
				return nil, control("subscription-group-references-invalid", exitFail)
			}
		}
		if raw, exists := group["use"]; exists {
			uses, isList := raw.([]any)
			if !isList {
				return nil, control("subscription-group-references-invalid", exitFail)
			}
			for _, use := range uses {
				name, ok := use.(string)
				if !ok || !providerNames[name] {
					return nil, control("subscription-provider-reference-missing", exitFail)
				}
			}
		}
		for _, member := range anyList(group["proxies"]) {
			name, ok := member.(string)
			if !ok || !names[name] {
				return nil, control("subscription-group-reference-missing", exitFail)
			}
		}
	}
	for _, rule := range anyList(changes["rules"]) {
		text, ok := rule.(string)
		if !ok {
			return nil, control("subscription-rule-invalid", exitFail)
		}
		parts := strings.Split(text, ",")
		for i, part := range parts {
			parts[i] = strings.TrimSpace(part)
		}
		if len(parts) < 2 {
			return nil, control("subscription-rule-invalid", exitFail)
		}
		// Logical rules may contain nested commas; their policy remains last.
		target := parts[len(parts)-1]
		if target == "no-resolve" {
			target = parts[len(parts)-2]
		}
		if !names[target] {
			return nil, control("subscription-rule-target-missing", exitFail)
		}
		if parts[0] == "RULE-SET" {
			ruleProviders := map[string]bool{}
			for name := range anyMap(changes["rule-providers"]) {
				ruleProviders[name] = true
			}
			if len(parts) < 3 || !ruleProviders[parts[1]] {
				return nil, control("subscription-rule-provider-missing", exitFail)
			}
		}
	}
	return changes, nil
}

func fileProviderWithoutPath(entry map[string]any, hasPath bool, path any) bool {
	if entry["type"] != "file" {
		return false
	}
	if !hasPath || path == nil {
		return true
	}
	text, ok := path.(string)
	return !ok || text == ""
}

// providerPathHasParent rejects ".." components in a POSIX provider path.
func providerPathHasParent(path string) bool {
	for _, part := range strings.Split(path, "/") {
		if part == ".." {
			return true
		}
	}
	return false
}

// downloadDeadline bounds the entire subscription exchange — connect,
// headers and body — so a server that flushes headers and then stalls can
// never pin the reader. It is a variable only so tests can shorten it.
var downloadDeadline = 15 * time.Second

// downloadTLSConfig is nil in production (default certificate verification);
// tests pin a private CA to exercise the full verified-TLS path locally.
var downloadTLSConfig *tls.Config

// download fetches a subscription over verified TLS with a direct transport,
// no redirects and no error-body disclosure.
func download(ctx context.Context, url string) ([]byte, error) {
	for _, r := range url {
		if r < 33 || r == 127 {
			return nil, control("subscription-requires-https-url-without-userinfo", exitFail)
		}
	}
	parts, err := parseSubscriptionURL(url)
	if err != nil || parts.scheme != "https" || parts.hostname == "" || parts.hasUserinfo || parts.fragment {
		return nil, control("subscription-requires-https-url-without-userinfo", exitFail)
	}
	// The context deadline covers the whole request plus body: the per-read
	// loop below can block indefinitely inside the kernel, so only a hard
	// deadline (context and client timeout together) bounds a stalled body.
	dctx, cancel := context.WithTimeout(ctx, downloadDeadline)
	defer cancel()
	transport := &http.Transport{
		Proxy:                 nil,
		TLSClientConfig:       downloadTLSConfig,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		DisableKeepAlives:     true,
		DialContext:           (&dialer15{}).DialContext,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   downloadDeadline,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	request, err := http.NewRequestWithContext(dctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, control("subscription-download-failed", exitFail)
	}
	request.Header.Set("Accept", "application/yaml, text/yaml, text/plain")
	response, err := client.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return nil, control("subscription-download-cancelled", exitUnverify)
		}
		if dctx.Err() != nil || isNetTimeout(err) {
			return nil, control("subscription-download-timeout", exitFail)
		}
		return nil, control("subscription-download-failed", exitFail)
	}
	defer response.Body.Close()
	if encoding := response.Header.Get("Content-Encoding"); encoding != "" && encoding != "identity" {
		return nil, control("subscription-download-rejected", exitFail)
	}
	if response.StatusCode != http.StatusOK {
		return nil, control("subscription-download-rejected", exitFail)
	}
	reader := bufio.NewReader(response.Body)
	var chunks []byte
	for len(chunks) <= limit {
		if ctx.Err() != nil {
			return nil, control("subscription-download-cancelled", exitUnverify)
		}
		if dctx.Err() != nil {
			return nil, control("subscription-download-timeout", exitFail)
		}
		want := 65536
		if remaining := limit + 1 - len(chunks); remaining < want {
			want = remaining
		}
		chunk := make([]byte, want)
		n, readErr := reader.Read(chunk)
		if n > 0 {
			chunks = append(chunks, chunk[:n]...)
		}
		if readErr != nil {
			if readErr == io.EOF {
				break
			}
			if ctx.Err() != nil {
				return nil, control("subscription-download-cancelled", exitUnverify)
			}
			if dctx.Err() != nil || isNetTimeout(readErr) {
				return nil, control("subscription-download-timeout", exitFail)
			}
			return nil, control("subscription-download-failed", exitFail)
		}
	}
	if len(chunks) == 0 || len(chunks) > limit {
		return nil, control("subscription-size-invalid", exitFail)
	}
	return chunks, nil
}

// isNetTimeout reports whether the transport surfaced a timeout-class error
// (the client hard deadline fires independently of the context).
func isNetTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

type subscriptionURL struct {
	scheme      string
	hostname    string
	hasUserinfo bool
	fragment    bool
}

func parseSubscriptionURL(raw string) (subscriptionURL, error) {
	var parts subscriptionURL
	scheme, rest, ok := strings.Cut(raw, "://")
	if !ok {
		return parts, fmt.Errorf("no scheme")
	}
	parts.scheme = strings.ToLower(scheme)
	if idx := strings.IndexByte(rest, '#'); idx >= 0 {
		parts.fragment = true
		rest = rest[:idx]
	}
	authority := rest
	if idx := strings.IndexByte(authority, '/'); idx >= 0 {
		authority = authority[:idx]
	}
	if strings.Contains(authority, "@") {
		parts.hasUserinfo = true
	}
	host := authority
	if idx := strings.LastIndexByte(host, ':'); idx >= 0 && !strings.Contains(host[idx:], "]") {
		host = host[:idx]
	}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	parts.hostname = strings.ToLower(host)
	return parts, nil
}

// subscriptions is the private staging store under the state root.
type subscriptions struct {
	a       platform.App
	m       coreManager
	config  string
	homeDir string
	input   io.Reader
}

func newSubscriptions(a platform.App, m coreManager, config, homeDir string, input io.Reader) *subscriptions {
	if homeDir == "" {
		homeDir = a.Scope.CoreHome()
	}
	return &subscriptions{a: a, m: m, config: config, homeDir: homeDir, input: input}
}

func (s *subscriptions) root() string {
	return filepath.Join(s.a.Scope.StateRoot, "subscriptions")
}

// directory ensures the private staging root exists and drops material older
// than 24 hours. Foreign or drifted files are never cleanup targets.
func (s *subscriptions) directory(ctx context.Context) error {
	return s.stageDirectory(ctx, false)
}

// stageDirectory prepares the private staging root. A preview takes the scope
// lock without replaying recovery journals: the cleanup touches the private
// staging area only, and a preview must not change the live configuration.
// The staging root is prepared before the lock, exactly as before.
func (s *subscriptions) stageDirectory(ctx context.Context, preview bool) error {
	if err := platform.PrivateDir(s.root()); err != nil {
		return controllerFileError(err)
	}
	lock := platform.WithLock
	if preview {
		lock = platform.WithPreviewLock
	}
	return lock(ctx, s.a.Scope, func() error {
		entries, err := os.ReadDir(s.root())
		if err != nil {
			return controllerFileError(err)
		}
		now := time.Now()
		for _, entry := range entries {
			name := entry.Name()
			if !subscriptionNamePattern.MatchString(name) {
				continue
			}
			path := filepath.Join(s.root(), name)
			info, err := os.Lstat(path)
			if err != nil || !info.Mode().IsRegular() || !fileOwnedPrivate(info) {
				continue
			}
			if now.Sub(info.ModTime()) > 24*time.Hour {
				_ = os.Remove(path)
			}
		}
		return nil
	})
}

// discard drops every staged artifact of one preview.
func (s *subscriptions) discard(ctx context.Context, identifier string) error {
	if !subscriptionIDPattern.MatchString(identifier) {
		return control("subscription-plan-invalid", exitUnverify)
	}
	if err := s.directory(ctx); err != nil {
		return err
	}
	return platform.WithLock(ctx, s.a.Scope, func() error {
		for _, suffix := range []string{".json", ".candidate.yaml", ".raw.yaml"} {
			path := filepath.Join(s.root(), identifier+suffix)
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				return controllerFileError(err)
			}
		}
		return nil
	})
}

// checkProviderPaths keeps downloaded provider caches inside dedicated trees,
// away from configuration and core state.
func (s *subscriptions) checkProviderPaths(changes map[string]any) error {
	home := s.homeDir
	if s.a.Scope.System {
		owner := serviceAccountUID()
		if owner <= 0 {
			return control("subscription-provider-path-unsafe", exitUnverify)
		}
		if err := checkAncestorsOwned(filepath.Join(home, "provider"), owner); err != nil {
			return err
		}
		if resolvePath(home) != resolvePath(s.a.Scope.CoreHome()) {
			return control("subscription-provider-path-unsafe", exitUnverify)
		}
		info, err := os.Stat(home)
		if err != nil || !pathOwnedBy(info, 0, owner) {
			return control("subscription-provider-path-unsafe", exitUnverify)
		}
	} else if err := platform.PrivateDir(home); err != nil {
		return controllerFileError(err)
	}
	resolvedHome := resolvePath(home)
	resolvedConfig := resolvePath(s.config)
	configName := filepath.Base(s.config)
	used := map[string]bool{}
	for _, section := range []string{"proxy-providers", "rule-providers"} {
		for _, row := range anyMap(changes[section]) {
			entry, ok := row.(map[string]any)
			if !ok {
				continue
			}
			path, _ := entry["path"].(string)
			if entry["type"] == "http" && path == "" {
				return control("subscription-provider-cache-path-required", exitFail)
			}
			if path == "" {
				continue
			}
			target := filepath.Join(home, filepath.FromSlash(path))
			if err := platform.CheckPath(target); err != nil {
				return control("subscription-provider-path-unsafe", exitFail)
			}
			if s.a.Scope.System {
				if info, err := os.Lstat(target); err == nil && info.Mode()&os.ModeSymlink != 0 {
					return control("subscription-provider-path-unsafe", exitFail)
				}
				if err := checkAncestorsOwned(target, serviceAccountUID()); err != nil {
					return err
				}
			}
			resolved := resolvePath(target)
			if !pathWithin(resolvedHome, resolved) {
				return control("subscription-provider-path-unsafe", exitFail)
			}
			relative, err := filepath.Rel(resolvedHome, resolved)
			if err != nil {
				return control("subscription-provider-path-unsafe", exitFail)
			}
			parts := strings.Split(filepath.ToSlash(relative), "/")
			if len(parts) < 2 || !providerTreeRoots[parts[0]] || resolved == resolvedConfig ||
				strings.HasPrefix(filepath.Base(resolved), configName+".") || used[resolved] {
				return control("subscription-provider-cache-path-unsafe", exitFail)
			}
			used[resolved] = true
		}
	}
	return nil
}

// pathWithin reports whether candidate is strictly below root.
func pathWithin(root, candidate string) bool {
	rel, err := filepath.Rel(root, candidate)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != "." && rel != ""
}

// resolvePath resolves symlinks of every existing component; the lexical
// remainder is kept, mirroring pathlib resolve() without strict mode.
func resolvePath(path string) string {
	absolute, err := filepath.Abs(path)
	if err != nil {
		absolute = path
	}
	absolute = filepath.Clean(absolute)
	volume := filepath.VolumeName(absolute)
	rest := strings.TrimPrefix(absolute, volume)
	resolved := volume
	for rest != "" {
		rest = strings.TrimPrefix(rest, string(os.PathSeparator))
		if rest == "" {
			break
		}
		var child string
		if idx := strings.IndexByte(rest, os.PathSeparator); idx >= 0 {
			child, rest = rest[:idx], rest[idx+1:]
		} else {
			child, rest = rest, ""
		}
		resolved = filepath.Join(resolved, child)
		if st, err := os.Lstat(resolved); err == nil && st.Mode()&os.ModeSymlink != 0 {
			if link, err := filepath.EvalSymlinks(resolved); err == nil {
				resolved = link
			}
		}
	}
	if resolved == "" {
		resolved = string(os.PathSeparator)
	}
	return filepath.Clean(resolved)
}

// preview stages a reviewed subscription candidate and returns its summary.
func (s *subscriptions) preview(ctx context.Context, sourceFile, urlFile string, stdin bool, policy string) (map[string]any, error) {
	if policy != "auto" && policy != "nodes" && policy != "provider" && policy != "policy" {
		return nil, control("subscription-policy-invalid", exitFail)
	}
	sources := 0
	for _, present := range []bool{sourceFile != "", urlFile != "", stdin} {
		if present {
			sources++
		}
	}
	if sources != 1 {
		return nil, control("choose-one-private-subscription-source", exitUnverify)
	}
	var raw []byte
	var err error
	if stdin {
		if s.input == nil {
			return nil, control("choose-one-private-subscription-source", exitUnverify)
		}
		raw, err = io.ReadAll(io.LimitReader(s.input, limit+1))
		if err != nil {
			return nil, control("subscription-size-invalid", exitFail)
		}
	} else {
		path := urlFile
		if path == "" {
			path = sourceFile
		}
		if absolute, absErr := filepath.Abs(path); absErr == nil {
			path = absolute
		}
		if err := platform.CheckPath(path); err != nil {
			return nil, controllerFileError(err)
		}
		info, statErr := os.Lstat(path)
		if statErr != nil {
			return nil, controllerFileError(statErr)
		}
		if info.Size() > limit {
			return nil, control("subscription-size-invalid", exitFail)
		}
		raw, err = platform.ReadPrivate(path)
		if err != nil {
			return nil, controllerFileError(err)
		}
		if urlFile != "" {
			if !utf8.Valid(raw) {
				return nil, control("subscription-url-invalid", exitFail)
			}
			raw, err = download(ctx, strings.TrimSpace(string(raw)))
			if err != nil {
				return nil, err
			}
		}
	}
	if len(raw) == 0 || len(raw) > limit {
		return nil, control("subscription-size-invalid", exitFail)
	}
	return s.previewRaw(ctx, raw, policy, policy, false)
}

// previewRaw stages an already-private raw subscription document. It is the
// shared locked half behind the CLI sources and the TUI subscription input.
// It is a preview: it never changes the live configuration and never replays
// a recovery journal. A pending recovery is refused, leaving the journal for
// the next authorized mutation.
func (s *subscriptions) previewRaw(ctx context.Context, raw []byte, policy, requestedPolicy string, guided bool) (map[string]any, error) {
	if policy != "auto" && policy != "nodes" && policy != "provider" && policy != "policy" {
		return nil, control("subscription-policy-invalid", exitFail)
	}
	if len(raw) == 0 || len(raw) > limit {
		return nil, control("subscription-size-invalid", exitFail)
	}
	if err := s.stageDirectory(ctx, true); err != nil {
		return nil, err
	}
	identifierBytes := make([]byte, 16)
	if _, err := rand.Read(identifierBytes); err != nil {
		return nil, control("controller-operation-unavailable", exitUnverify)
	}
	identifier := hex.EncodeToString(identifierBytes)
	var payload map[string]any
	err := platform.WithPreviewLock(ctx, s.a.Scope, func() error {
		var stageErr error
		payload, stageErr = s.stage(ctx, raw, policy, requestedPolicy, identifier, guided)
		if stageErr != nil {
			for _, suffix := range []string{".json", ".candidate.yaml"} {
				_ = os.Remove(filepath.Join(s.root(), identifier+suffix))
			}
			return stageErr
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return payload, nil
}

// stage performs the locked half of preview: parse, validate, write plan.
func (s *subscriptions) stage(ctx context.Context, raw []byte, policy, requestedPolicy, identifier string, guided bool) (map[string]any, error) {
	order, incoming, err := readOrderedYAML(raw)
	if err != nil {
		return nil, controllerFileError(err)
	}
	for _, key := range order {
		if _, err := label(key); err != nil {
			return nil, err
		}
	}
	if policy == "auto" {
		policy = "nodes"
		for _, key := range order {
			if routingFields[key] {
				policy = "provider"
				break
			}
		}
	}
	if policy == "nodes" {
		if len(incoming) != 1 {
			return nil, control("subscription-only-node-list-supported", exitFail)
		}
		if _, ok := incoming["proxies"]; !ok {
			return nil, control("subscription-only-node-list-supported", exitFail)
		}
	}
	rawNodes, nodesPresent := incoming["proxies"]
	if nodesPresent {
		if _, isList := rawNodes.([]any); !isList {
			return nil, control("subscription-node-list-invalid", exitFail)
		}
	}
	nodes := anyList(rawNodes)
	if nodes == nil {
		nodes = []any{}
	}
	if (len(nodes) == 0 && policy == "nodes") || len(nodes) > 10000 {
		return nil, control("subscription-node-list-invalid", exitFail)
	}
	names := map[string]bool{}
	for _, row := range nodes {
		node, ok := row.(map[string]any)
		if !ok {
			return nil, control("subscription-node-invalid", exitFail)
		}
		if _, ok := node["type"].(string); !ok {
			return nil, control("subscription-node-invalid", exitFail)
		}
		if _, err := label(node["type"]); err != nil {
			return nil, err
		}
		name, err := label(node["name"])
		if err != nil {
			return nil, err
		}
		if name == "" || names[name] {
			return nil, control("subscription-node-name-invalid", exitFail)
		}
		names[name] = true
	}
	original, data, err := readCoreConfig(s.config, s.a.Scope.System)
	if err != nil {
		return nil, err
	}
	if rawCurrent, exists := data["proxies"]; exists {
		if _, isList := rawCurrent.([]any); !isList {
			return nil, control("existing-node-list-invalid", exitUnverify)
		}
	}
	current := anyList(data["proxies"])
	if current == nil {
		current = []any{}
	}
	merged := make([]any, 0, len(current)+len(nodes))
	index := map[string]int{}
	for position, row := range current {
		node, ok := row.(map[string]any)
		if !ok {
			return nil, control("existing-node-list-invalid", exitUnverify)
		}
		name, ok := node["name"].(string)
		if !ok {
			return nil, control("existing-node-list-invalid", exitUnverify)
		}
		if _, dup := index[name]; dup {
			return nil, control("existing-node-names-not-unique", exitUnverify)
		}
		index[name] = position
		merged = append(merged, node)
	}
	existingNames := map[string]bool{}
	for name := range index {
		existingNames[name] = true
	}
	replaced := 0
	for name := range names {
		if existingNames[name] {
			replaced++
		}
	}
	for _, row := range nodes {
		node := row.(map[string]any)
		name := node["name"].(string)
		if position, ok := index[name]; ok {
			merged[position] = node
		} else {
			index[name] = len(merged)
			merged = append(merged, node)
		}
	}
	var changes map[string]any
	var fields []string
	if guided {
		// Guided onboarding: only an untouched configuration or our exact
		// simple preset may be rewritten; anything else preserves routing.
		if !guidedShape(data) {
			return nil, control("existing-routing-preserved-use-advanced", exitUnverify)
		}
		changes, err = guidedPolicy(incoming, mappingKeyOrder(raw, "proxy-providers"))
		if err != nil {
			return nil, err
		}
		for _, field := range policyFields {
			fields = append(fields, field.name)
		}
	} else {
		switch policy {
		case "policy":
			overlay := map[string]any{}
			for _, key := range order {
				if overlayFields[key] {
					overlay[key] = incoming[key]
				}
			}
			changes, err = policyOverlay(overlay, data)
			if err != nil {
				return nil, err
			}
			fields = append(fields, order...)
		case "provider":
			changes, err = providerPolicy(incoming)
			if err != nil {
				return nil, err
			}
			for _, field := range policyFields {
				fields = append(fields, field.name)
			}
		default:
			changes = map[string]any{"proxies": merged}
			fields = []string{"proxies"}
		}
	}
	if policy == "provider" || policy == "policy" {
		combined := map[string]any{}
		for key, value := range data {
			combined[key] = value
		}
		for key, value := range changes {
			combined[key] = value
		}
		complete, err := providerPolicy(combined)
		if err != nil {
			return nil, err
		}
		if err := s.checkProviderPaths(complete); err != nil {
			return nil, err
		}
		patched, err := patchCoreConfig(original, changes)
		if err != nil {
			return nil, err
		}
		if err := validateCandidateText(ctx, s.a, s.m, patched); err != nil {
			return nil, err
		}
	}
	candidate, err := patchCoreConfig(original, changes)
	if err != nil {
		return nil, err
	}
	candidateHash := hashSHA256(candidate)
	configAbsolute := s.config
	if absolute, absErr := filepath.Abs(s.config); absErr == nil {
		configAbsolute = absolute
	}
	plan := map[string]any{
		"schema":           1,
		"id":               identifier,
		"config":           configAbsolute,
		"original_sha256":  hashSHA256(original),
		"candidate_sha256": candidateHash,
		"nodes":            len(nodes),
		"replaced":         replaced,
		"policy":           policy,
	}
	if err := platform.AtomicWrite(filepath.Join(s.root(), identifier+".candidate.yaml"), candidate, 0600); err != nil {
		return nil, controllerFileError(err)
	}
	if err := platform.WriteJSON(filepath.Join(s.root(), identifier+".json"), plan); err != nil {
		return nil, controllerFileError(err)
	}
	changeRows := []any{}
	for _, row := range nodes {
		node := row.(map[string]any)
		nodeType, err := label(node["type"])
		if err != nil {
			return nil, err
		}
		action := "add"
		if existingNames[node["name"].(string)] {
			action = "replace"
		}
		changeRows = append(changeRows, map[string]any{
			"name": node["name"], "type": nodeType, "action": action,
		})
	}
	probeRows := []any{}
	if policy == "provider" {
		for _, row := range probeOverwrites(data, changes) {
			probeRows = append(probeRows, row)
		}
	}
	ignored := []string{}
	for _, key := range order {
		if _, isChange := changes[key]; !isChange {
			ignored = append(ignored, key)
		}
	}
	sort.Strings(ignored)
	payload := map[string]any{
		"state":            "preview",
		"id":               identifier,
		"sha256":           candidateHash,
		"nodes":            len(nodes),
		"added":            len(nodes) - replaced,
		"replaced":         replaced,
		"changes":          changeRows,
		"policy":           policy,
		"requested_policy": requestedPolicy,
		"fields":           fields,
		"probe_overwrites": probeRows,
		"ignored_fields":   ignored,
		"removed":          0,
		"removed_groups":   0,
		"removed_rules":    0,
		"group_changes":    []any{},
		"groups":           0,
		"rules":            0,
		"service":          "unchanged",
	}
	if policy == "provider" {
		removed := 0
		for name := range existingNames {
			if !names[name] {
				removed++
			}
		}
		payload["removed"] = removed
		groupNames := map[string]bool{}
		for _, row := range anyList(data["proxy-groups"]) {
			if group, ok := row.(map[string]any); ok {
				if name, ok := group["name"].(string); ok {
					groupNames[name] = true
				}
			}
		}
		keptGroups := map[string]bool{}
		groupChangeRows := []any{}
		for _, row := range anyList(changes["proxy-groups"]) {
			group, ok := row.(map[string]any)
			if !ok {
				continue
			}
			name, _ := group["name"].(string)
			keptGroups[name] = true
			groupType, err := label(group["type"])
			if err != nil {
				return nil, err
			}
			groupChangeRows = append(groupChangeRows, map[string]any{"name": name, "type": groupType})
		}
		removedGroups := 0
		for name := range groupNames {
			if !keptGroups[name] {
				removedGroups++
			}
		}
		newRules := anyList(changes["rules"])
		removedRules := 0
		for _, rule := range anyList(data["rules"]) {
			if !containsAnyValue(newRules, rule) {
				removedRules++
			}
		}
		payload["removed_groups"] = removedGroups
		payload["removed_rules"] = removedRules
		payload["group_changes"] = groupChangeRows
		payload["groups"] = len(anyList(changes["proxy-groups"]))
		payload["rules"] = len(newRules)
	}
	return payload, nil
}

func containsAnyValue(values []any, wanted any) bool {
	for _, value := range values {
		if sameValue(value, wanted) {
			return true
		}
	}
	return false
}

// apply commits a staged candidate after digest and boundary validation.
// validateStaged is the locked phase-1 proof of a staged plan: the plan and
// candidate are read privately, the digests still match the live
// configuration, and the write boundary holds even if a plan file was edited.
func (s *subscriptions) validateStaged(ctx context.Context, identifier, expectedHash string) ([]byte, []byte, error) {
	if !subscriptionIDPattern.MatchString(identifier) || !subscriptionHashPattern.MatchString(expectedHash) {
		return nil, nil, control("subscription-plan-invalid", exitFail)
	}
	if err := s.directory(ctx); err != nil {
		return nil, nil, err
	}
	// The foundation exposes one non-reentrant operation lock, so every phase
	// takes and releases it; the commit phases re-prove the bytes inside their
	// own transaction lock.
	var original, candidate []byte
	err := platform.WithLock(ctx, s.a.Scope, func() error {
		planPath := filepath.Join(s.root(), identifier+".json")
		candidatePath := filepath.Join(s.root(), identifier+".candidate.yaml")
		planRaw, err := platform.ReadPrivate(planPath)
		if err != nil {
			return controllerFileError(err)
		}
		candidate, err = platform.ReadPrivate(candidatePath)
		if err != nil {
			return controllerFileError(err)
		}
		if len(planRaw) > limit || len(candidate) > limit {
			return control("subscription-size-invalid", exitFail)
		}
		var plan map[string]any
		if json.Unmarshal(planRaw, &plan) != nil || plan == nil {
			return control("subscription-plan-invalid", exitFail)
		}
		original, err = readCoreConfigText(s.config, s.a.Scope.System)
		if err != nil {
			return err
		}
		configAbsolute := s.config
		if absolute, absErr := filepath.Abs(s.config); absErr == nil {
			configAbsolute = absolute
		}
		if !planNumberIs(plan["schema"], 1) || planString(plan["id"]) != identifier ||
			planString(plan["config"]) != configAbsolute ||
			planString(plan["candidate_sha256"]) != expectedHash || hashSHA256(candidate) != expectedHash {
			return control("subscription-candidate-changed", exitFail)
		}
		if hashSHA256(original) != planString(plan["original_sha256"]) {
			return control("subscription-config-changed", exitFail)
		}
		// Re-parse both sides and enforce the write boundary even if a plan
		// file was edited.
		before, err := platform.DecodeYAML(original)
		if err != nil {
			return controllerFileError(err)
		}
		after, err := platform.DecodeYAML(candidate)
		if err != nil {
			return controllerFileError(err)
		}
		policy := planString(plan["policy"])
		if policy == "" {
			policy = "nodes"
		}
		var allowed map[string]bool
		switch policy {
		case "nodes":
			allowed = map[string]bool{"proxies": true}
		case "provider":
			allowed = map[string]bool{}
			for _, field := range policyFields {
				allowed[field.name] = true
			}
		case "policy":
			allowed = overlayFields
		default:
			return control("subscription-plan-invalid", exitFail)
		}
		if policy == "provider" || policy == "policy" {
			complete, err := providerPolicy(after)
			if err != nil {
				return err
			}
			if err := s.checkProviderPaths(complete); err != nil {
				return err
			}
		}
		if !outsideBoundaryEqual(before, after, allowed) {
			if policy == "provider" {
				return control("subscription-may-only-change-routing-policy", exitFail)
			}
			return control("subscription-may-only-change-proxies", exitFail)
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return original, candidate, nil
}

func (s *subscriptions) apply(ctx context.Context, identifier, expectedHash string) (map[string]any, error) {
	original, candidate, err := s.validateStaged(ctx, identifier, expectedHash)
	if err != nil {
		return nil, err
	}
	// Phase 2: the durable transaction (its own lock) validates the candidate
	// again and commits or rolls everything back.
	applied, err := applyPolicy(ctx, s.a, s.m, s.config, s.homeDir, original, candidate, nil)
	if err != nil {
		return nil, err
	}
	// Phase 3 (locked): drop the staged artifacts.
	err = platform.WithLock(ctx, s.a.Scope, func() error {
		return s.cleanup(identifier)
	})
	if err != nil {
		state := "changed"
		if current, readErr := platform.ReadPrivate(s.config); readErr == nil {
			digest := expectedHash
			if appliedDigest, ok := applied["applied_sha256"].(string); ok {
				digest = appliedDigest
			}
			if hashSHA256(current) == digest {
				state = "committed"
			}
		}
		return nil, &controlError{
			code:       "subscription-cleanup-incomplete",
			rc:         exitUnverify,
			safeDetail: fmt.Sprintf("phase=cleanup; config=%s; runtime=unverified; activation=not-requested", state),
		}
	}
	outcome := map[string]any{"id": identifier, "sha256": expectedHash}
	for key, value := range applied {
		outcome[key] = value
	}
	return outcome, nil
}

func (s *subscriptions) cleanup(identifier string) error {
	for _, suffix := range []string{".json", ".candidate.yaml", ".raw.yaml"} {
		path := filepath.Join(s.root(), identifier+suffix)
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func readCoreConfigText(path string, system bool) ([]byte, error) {
	text, _, err := readCoreConfig(path, system)
	return text, err
}

func planString(value any) string {
	text, _ := value.(string)
	return text
}

func planNumberIs(value any, wanted int) bool {
	switch n := value.(type) {
	case float64:
		return n == float64(wanted)
	case int:
		return n == wanted
	}
	return false
}

// outsideBoundaryEqual compares every key outside the allowed boundary,
// distinguishing an absent key from an explicit null.
func outsideBoundaryEqual(before, after map[string]any, allowed map[string]bool) bool {
	keys := map[string]bool{}
	for key := range before {
		keys[key] = true
	}
	for key := range after {
		keys[key] = true
	}
	for key := range keys {
		if allowed[key] {
			continue
		}
		beforeValue, beforeHas := before[key]
		afterValue, afterHas := after[key]
		if beforeHas != afterHas || !sameValue(beforeValue, afterValue) {
			return false
		}
	}
	return true
}

// readOrderedYAML strict-decodes a document and reports its top-level key
// order, which the preview payload preserves.
func readOrderedYAML(content []byte) ([]string, map[string]any, error) {
	node, err := platform.StrictYAML(content)
	if err != nil {
		return nil, nil, err
	}
	root := node.Content[0]
	var order []string
	for i := 0; i+1 < len(root.Content); i += 2 {
		order = append(order, root.Content[i].Value)
	}
	var value map[string]any
	if err := node.Decode(&value); err != nil {
		return nil, nil, platform.Usage("config-invalid")
	}
	return order, value, nil
}
