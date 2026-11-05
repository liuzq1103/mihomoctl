package routing

import (
	"fmt"
	"io"
	"net"
	"reflect"
	"regexp"
	"strings"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

var (
	controllerPattern = regexp.MustCompile(`^(?:127\.0\.0\.1|\[::1\]|localhost):([0-9]{1,5})$`)
	secretPatternCtl  = regexp.MustCompile(`^[A-Za-z0-9_-]{32,256}$`)
)

// controllerFileError maps platform private-file/YAML failures onto the
// original controller error codes so diagnostics keep their contract.
func controllerFileError(err error) error {
	code := platform.SafeError(err)
	switch code {
	case "config-missing":
		return control("config-missing", exitUnverify)
	case "config-too-large", "file-too-large", "input-too-large":
		return control("config-too-large", exitUnverify)
	case "yaml-alias-disabled":
		return control("config-anchors-or-document-end-not-supported", exitUnverify)
	case "yaml-duplicate-or-invalid-key":
		return control("config-duplicate-or-complex-key", exitUnverify)
	case "config-must-be-mapping", "config-invalid", "config-multiple-documents", "config-too-complex":
		return control(code, exitUnverify)
	case "owner-mismatch", "private-permissions-required":
		return control("controller-path-must-be-private-owned-regular", exitUnverify)
	case "symlink-refused", "path-unavailable", "unsafe-path", "unsafe-file":
		return control("controller-path-must-be-private-owned-regular", exitUnverify)
	}
	return control(code, exitUnverify)
}

// readCoreConfig loads the managed core configuration, strictly. System
// scope accepts the root-owned 0640 configuration the original mandate
// prescribes; user scope keeps the strictly-private 0600 contract.
func readCoreConfig(path string, system bool) ([]byte, map[string]any, error) {
	b, err := readManagedText(path, system)
	if err != nil {
		return nil, nil, err
	}
	if len(b) > limit {
		return nil, nil, control("config-too-large", exitUnverify)
	}
	data, err := platform.DecodeYAML(b)
	if err != nil {
		return nil, nil, controllerFileError(err)
	}
	return b, data, nil
}

// readManagedText reads a managed private file with the scope-appropriate
// ownership/permission policy. Opening goes through platform.OpenRegular
// (O_NOFOLLOW|O_NONBLOCK with a regular-file proof): opening a FIFO or device
// can never block or hang the controller, and the open is re-verified against
// a swap after the handle exists.
func readManagedText(path string, system bool) ([]byte, error) {
	if err := platform.CheckPath(path); err != nil {
		return nil, controllerFileError(err)
	}
	handle, err := platform.OpenRegular(path)
	if err != nil {
		return nil, controllerFileError(err)
	}
	defer handle.Close()
	info, err := handle.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, control("controller-path-must-be-private-owned-regular", exitUnverify)
	}
	if !managedFileAcceptable(info, system) {
		return nil, control("controller-path-must-be-private-owned-regular", exitUnverify)
	}
	if info.Size() > limit {
		return nil, control("config-too-large", exitUnverify)
	}
	b, err := io.ReadAll(io.LimitReader(handle, limit+1))
	if err != nil {
		return nil, controllerFileError(err)
	}
	return b, nil
}

// parseCoreConfig applies the same strict parser to in-memory content (a
// downloaded subscription or a computed candidate).
func parseCoreConfig(content []byte) (map[string]any, error) {
	data, err := platform.DecodeYAML(content)
	if err != nil {
		return nil, controllerFileError(err)
	}
	return data, nil
}

// endpoint validates the controller address/secret contract: an authenticated
// loopback external-controller with a strong URL-safe secret and no extra
// controller listeners. Returns the dial host, port and token.
func endpoint(data map[string]any) (string, int, string, error) {
	match := controllerPattern.FindStringSubmatch(platform.String(data["external-controller"]))
	if match == nil {
		return "", 0, "", control("controller-not-configured-as-loopback", exitUnverify)
	}
	port := 0
	for _, c := range match[1] {
		port = port*10 + int(c-'0')
	}
	if port < 1024 || port > 65535 {
		return "", 0, "", control("controller-not-configured-as-loopback", exitUnverify)
	}
	token := platform.String(data["secret"])
	if !secretPatternCtl.MatchString(token) {
		return "", 0, "", control("controller-secret-must-be-32-to-256-url-safe-characters", exitUnverify)
	}
	for _, k := range []string{"external-controller-tls", "external-controller-unix", "external-controller-pipe", "external-doh-server"} {
		if v, ok := data[k]; ok && v != nil && v != false && platform.String(v) != "" {
			return "", 0, "", control("additional-controller-listeners-not-supported", exitUnverify)
		}
	}
	host := "127.0.0.1"
	if strings.HasPrefix(platform.String(data["external-controller"]), "[::1]") {
		host = "::1"
	}
	return host, port, token, nil
}

// patchCoreConfig patches top-level keys in place, preserving the untouched
// document, and proves the semantics did not drift before returning it.
func patchCoreConfig(text []byte, changes map[string]any) ([]byte, error) {
	patched, err := platform.PatchYAML(text, changes)
	if err != nil {
		return nil, controllerFileError(err)
	}
	before, err := platform.DecodeYAML(text)
	if err != nil {
		return nil, controllerFileError(err)
	}
	after, err := parseCoreConfig(patched)
	if err != nil {
		return nil, err
	}
	expected := map[string]any{}
	for k, v := range before {
		expected[k] = v
	}
	for k, v := range changes {
		expected[k] = v
	}
	if !sameConfig(after, expected) {
		return nil, control("config-patch-semantics-changed", exitUnverify)
	}
	return patched, nil
}

// sameConfig is the deep-equality check the original ran before a candidate
// could reach disk.
func sameConfig(a, b map[string]any) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		w, ok := b[k]
		if !ok || !sameValue(v, w) {
			return false
		}
	}
	return true
}

func sameValue(a, b any) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	switch av := a.(type) {
	case map[string]any:
		bm, ok := b.(map[string]any)
		return ok && sameConfig(av, bm)
	case []any:
		bv, ok := b.([]any)
		if !ok || len(av) != len(bv) {
			return false
		}
		for i := range av {
			if !sameValue(av[i], bv[i]) {
				return false
			}
		}
		return true
	}
	// YAML decodes integers as int and JSON as float64; compare numerically
	// so a value round-tripped through a script stays equal to itself.
	if na, ok := numericValue(a); ok {
		if nb, ok := numericValue(b); ok {
			return na == nb
		}
		return false
	}
	if reflect.TypeOf(a) != reflect.TypeOf(b) {
		return false
	}
	return reflect.DeepEqual(a, b)
}

// numericValue reports a whole numeric value as float64 when it is a YAML or
// JSON number.
func numericValue(v any) (float64, bool) {
	switch n := v.(type) {
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case float64:
		return n, true
	}
	return 0, false
}

// The design-reference 10.2 security envelope: keys that policy and
// subscription input can never touch.
var envelopeForbidden = []string{
	"port", "socks-port", "mixed-port", "redir-port", "tproxy-port",
	"bind-address", "allow-lan", "lan-allowed-ips", "lan-disallowed-ips",
	"authentication", "skip-auth-prefixes",
	"external-controller", "external-controller-tls", "external-controller-unix",
	"external-controller-cors", "external-doh-server", "secret",
	"tun", "listeners",
}

var envelopeExistenceProtected = map[string]bool{
	"external-controller": true, "external-controller-tls": true,
	"external-controller-unix": true, "external-controller-cors": true,
	"external-doh-server": true, "secret": true,
}

// assertSecurityEnvelope rejects any change to listener/auth/controller/TUN/
// DNS-listening keys between two configuration documents.
func assertSecurityEnvelope(before, after map[string]any) error {
	for _, key := range envelopeForbidden {
		old, hadOld := before[key]
		new, hadNew := after[key]
		if envelopeExistenceProtected[key] {
			if hadOld != hadNew || !sameValue(old, new) {
				return control("policy-envelope-violation", exitUnverify)
			}
			continue
		}
		if hadOld != hadNew || !sameValue(old, new) {
			return control("policy-envelope-violation", exitUnverify)
		}
	}
	return nil
}

var loopbackNames = map[string]bool{"127.0.0.1": true, "::1": true, "localhost": true}

// validateEndpointEnvelope normalizes every listening surface of a candidate
// configuration and enforces the managed security model, the equivalent of
// the original parse_endpoints check during candidate validation.
func validateEndpointEnvelope(cfg map[string]any, systemScope bool, allowed []string) error {
	invalid := func() error { return control("config-invalid", exitUnverify) }
	allowedSet := map[string]bool{}
	for _, a := range allowed {
		allowedSet[strings.ToLower(strings.Trim(strings.TrimSpace(platform.String(a)), "[]"))] = true
	}
	tun := platform.Map(cfg["tun"])
	if v, ok := cfg["tun"]; ok && v != nil {
		if _, ok := v.(map[string]any); !ok {
			return invalid()
		}
	}
	if !systemScope && (platform.Bool(tun["enable"]) || platform.Int(cfg["redir-port"]) != 0 || platform.Int(cfg["tproxy-port"]) != 0) {
		return invalid()
	}
	if !systemScope && platform.Bool(cfg["allow-lan"]) {
		return invalid()
	}
	dns := platform.Map(cfg["dns"])
	if v, ok := cfg["dns"]; ok && v != nil {
		if _, ok := v.(map[string]any); !ok {
			return invalid()
		}
	}
	if dns["listen"] != nil && platform.String(dns["listen"]) != "" {
		return invalid()
	}
	if cfg["skip-auth-prefixes"] != nil || cfg["external-doh-server"] != nil {
		return invalid()
	}
	normalize := func(raw string) (string, error) {
		address := strings.ToLower(strings.Trim(strings.TrimSpace(raw), "[]"))
		if address == "localhost" {
			address = "127.0.0.1"
		}
		ip := net.ParseIP(address)
		if ip == nil {
			return "", invalid()
		}
		address = ip.String()
		if ip.IsUnspecified() {
			return "", invalid()
		}
		if loopbackNames[address] {
			return address, nil
		}
		if !systemScope || !allowedSet[address] {
			return "", invalid()
		}
		return address, nil
	}
	seen := map[string]bool{}
	binds := map[string]bool{}
	add := func(name, rawAddress string, port int) error {
		address, err := normalize(rawAddress)
		if err != nil {
			return err
		}
		if !loopbackNames[address] && !allowedSet[address] {
			return invalid()
		}
		if seen[name] {
			return invalid()
		}
		key := fmt.Sprintf("%s|%d", address, port)
		if binds[key] {
			return invalid()
		}
		seen[name] = true
		binds[key] = true
		return nil
	}
	if v, ok := cfg["listeners"]; ok && v != nil {
		rows, ok := v.([]any)
		if !ok {
			return invalid()
		}
		for _, row := range rows {
			m, ok := row.(map[string]any)
			if !ok {
				return invalid()
			}
			for k := range m {
				if k != "name" && k != "type" && k != "listen" && k != "port" && k != "users" {
					return invalid()
				}
			}
			name := platform.String(m["name"])
			etype := platform.String(m["type"])
			if name == "" || len(name) > 64 || strings.ContainsFunc(name, func(r rune) bool { return r == ' ' || r == '\t' }) {
				return invalid()
			}
			if etype != "http" && etype != "socks" && etype != "mixed" && etype != "redir" && etype != "tproxy" {
				return invalid()
			}
			authenticated := false
			if users, ok := m["users"]; ok && users != nil {
				rows, ok := users.([]any)
				if !ok || len(rows) == 0 {
					return invalid()
				}
				for _, u := range rows {
					um, ok := u.(map[string]any)
					if !ok || len(um) != 2 || platform.String(um["username"]) == "" {
						return invalid()
					}
				}
				authenticated = true
			}
			if (etype == "redir" || etype == "tproxy") && !systemScope {
				return invalid()
			}
			if (etype == "http" || etype == "socks" || etype == "mixed") && !authenticated {
				return invalid()
			}
			port := platform.Int(m["port"])
			if port < 1024 || port > 65535 {
				return invalid()
			}
			address := platform.String(m["listen"])
			if address == "" {
				address = "127.0.0.1"
			}
			if err := add(name, address, port); err != nil {
				return err
			}
		}
	}
	legacyAuth := false
	if v, ok := cfg["authentication"]; ok && v != nil {
		rows, ok := v.([]any)
		if !ok || len(rows) == 0 {
			return invalid()
		}
		for _, r := range rows {
			s, ok := r.(string)
			if !ok || !strings.Contains(s, ":") || s == ":" {
				return invalid()
			}
		}
		legacyAuth = true
	}
	legacyAddress := "127.0.0.1"
	if platform.Bool(cfg["allow-lan"]) {
		legacyAddress = "0.0.0.0"
	}
	if v, ok := cfg["bind-address"]; ok && v != nil {
		legacyAddress = platform.String(v)
	}
	for _, row := range []struct{ k, t string }{{"port", "http"}, {"socks-port", "socks"}, {"mixed-port", "mixed"}, {"redir-port", "redir"}, {"tproxy-port", "tproxy"}} {
		v, ok := cfg[row.k]
		if !ok || v == nil {
			continue
		}
		switch v.(type) {
		case int, int64, float64:
		default:
			return invalid()
		}
		n := platform.Int(v)
		if n == 0 {
			continue
		}
		if row.t == "http" || row.t == "socks" || row.t == "mixed" {
			if !legacyAuth {
				return invalid()
			}
		}
		if n < 1024 || n > 65535 {
			return invalid()
		}
		if err := add(row.k, legacyAddress, n); err != nil {
			return err
		}
	}
	if v, ok := cfg["external-controller"]; ok && v != nil && platform.String(v) != "" {
		host, port, _, err := endpoint(cfg)
		if err != nil {
			return err
		}
		if binds[fmt.Sprintf("%s|%d", host, port)] {
			return invalid()
		}
	}
	return nil
}
