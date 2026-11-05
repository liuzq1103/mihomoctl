// Package runtimecore implements the native, independently scoped Mihomo runtime.
package runtimecore

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/liuzq1103/mihomoctl/internal/platform"
	"gopkg.in/yaml.v3"
)

type coreSettings struct {
	Binary  string `yaml:"binary"`
	Config  string `yaml:"config"`
	Backend string `yaml:"backend"`
	Adopted bool   `yaml:"adopted,omitempty"`
}
type profile struct {
	HTTP        string   `yaml:"http_listener,omitempty"`
	SOCKS       string   `yaml:"socks_listener,omitempty"`
	Credentials string   `yaml:"credentials_file,omitempty"`
	NoProxy     []string `yaml:"no_proxy,omitempty"`
	Health      struct {
		Timeout int `yaml:"timeout,omitempty"`
	} `yaml:"health,omitempty"`
}
type binding struct {
	Profile     string `yaml:"profile"`
	Adapter     string `yaml:"adapter"`
	Target      string `yaml:"target,omitempty"`
	ConnectHost string `yaml:"connect_host,omitempty"`
}
type tunSettings struct {
	Enabled bool   `yaml:"enabled"`
	Device  string `yaml:"device"`
}
type manager struct {
	Version  int                `yaml:"version"`
	Core     coreSettings       `yaml:"core"`
	Default  string             `yaml:"default_profile"`
	Profiles map[string]profile `yaml:"profiles"`
	Bindings map[string]binding `yaml:"bindings,omitempty"`
	Tun      tunSettings        `yaml:"tun,omitempty"`
	Allow    []string           `yaml:"allow_non_loopback,omitempty"`
}
type credentials struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}
type endpoint struct {
	Name          string        `json:"name"`
	Source        string        `json:"source"`
	Type          string        `json:"type"`
	Address       string        `json:"address"`
	Port          int           `json:"port"`
	Authenticated bool          `json:"authenticated"`
	Users         []credentials `json:"-"`
}

func (e endpoint) address() string { return net.JoinHostPort(e.Address, fmt.Sprint(e.Port)) }
func (e endpoint) http() bool      { return e.Type == "mixed" || e.Type == "http" }
func (e endpoint) socks() bool     { return e.Type == "mixed" || e.Type == "socks" }

type resolved struct {
	Manager     manager
	Config      map[string]any
	Text        []byte
	Endpoints   []endpoint
	Controller  *endpoint
	Profile     profile
	Name        string
	Credentials credentials
}

var namePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
var unitPattern = regexp.MustCompile(`^[A-Za-z0-9_.@:\\-]+\.service$`)
var devicePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,15}$`)
var secretPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{32,256}$`)
var digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var noProxyPattern = regexp.MustCompile(`^[A-Za-z0-9*.:_\[\]-]+$`)

func invalid() error { return platform.Usage("config-invalid") }
func cleanString(s string) bool {
	return s != "" && !strings.ContainsFunc(s, func(r rune) bool { return unicode.IsControl(r) })
}
func absolute(s string) bool { return cleanString(s) && filepath.IsAbs(s) && filepath.Clean(s) == s }
func decode(b []byte, v any) error {
	if _, e := platform.StrictYAML(b); e != nil {
		return e
	}
	d := yaml.NewDecoder(bytes.NewReader(b))
	d.KnownFields(true)
	if d.Decode(v) != nil {
		return invalid()
	}
	return nil
}
func loadManager(a platform.App) (manager, error) {
	m := manager{Core: coreSettings{Backend: "process"}, Default: "default", Tun: tunSettings{Device: "mihomo0"}}
	b, e := platform.ReadPrivate(a.Scope.ManagerPath())
	if e != nil {
		return m, e
	}
	if e = decode(b, &m); e != nil {
		return m, e
	}
	// yaml.v3 permits some scalar coercions; the public manager schema does not.
	raw, e := platform.DecodeYAML(b)
	if e != nil {
		return m, e
	}
	if _, ok := raw["version"].(int); !ok {
		return m, invalid()
	}
	if v, ok := raw["default_profile"]; ok {
		if _, ok = v.(string); !ok {
			return m, invalid()
		}
	}
	for _, v := range platform.Map(raw["core"]) {
		switch v.(type) {
		case string, bool:
		default:
			return m, invalid()
		}
	}
	for _, v := range platform.Map(raw["profiles"]) {
		p := platform.Map(v)
		for _, k := range []string{"http_listener", "socks_listener", "credentials_file"} {
			if v, ok := p[k]; ok && v != nil {
				if _, ok = v.(string); !ok {
					return m, invalid()
				}
			}
		}
		if v, ok := p["health"]; ok && v != nil {
			h, ok := v.(map[string]any)
			if !ok {
				return m, invalid()
			}
			if n, ok := h["timeout"]; ok {
				value, ok := n.(int)
				if !ok || value < 1 || value > 120 {
					return m, invalid()
				}
			}
		}
		if v, ok := p["no_proxy"]; ok && v != nil {
			rows, ok := v.([]any)
			if !ok || len(rows) == 0 {
				return m, invalid()
			}
			for _, item := range rows {
				if _, ok := item.(string); !ok {
					return m, invalid()
				}
			}
		}
	}
	if t, ok := raw["tun"].(map[string]any); ok {
		if v, ok := t["enabled"]; ok {
			if _, ok = v.(bool); !ok {
				return m, invalid()
			}
		}
	}
	return m, validateManager(a, m)
}
func validateManager(a platform.App, m manager) error {
	if m.Version != 1 || !absolute(m.Core.Binary) || !absolute(m.Core.Config) || !a.Scope.Contains(m.Core.Config) || len(m.Profiles) == 0 {
		return invalid()
	}
	if m.Core.Backend != "process" && m.Core.Backend != "systemd" {
		return invalid()
	}
	if a.Scope.System && m.Core.Backend != "systemd" {
		return invalid()
	}
	if _, ok := m.Profiles[m.Default]; !ok {
		return invalid()
	}
	if m.Tun.Enabled && !a.Scope.System || m.Tun.Device != "" && !devicePattern.MatchString(m.Tun.Device) {
		return invalid()
	}
	if len(m.Allow) > 0 && !a.Scope.System {
		return invalid()
	}
	for _, s := range m.Allow {
		ip := net.ParseIP(s)
		if ip == nil || ip.IsUnspecified() {
			return invalid()
		}
	}
	for n, p := range m.Profiles {
		if !namePattern.MatchString(n) || (p.HTTP == "" && p.SOCKS == "") {
			return invalid()
		}
		for _, v := range []string{p.HTTP, p.SOCKS} {
			if v != "" && (!cleanString(v) || len(v) > 64 || strings.ContainsFunc(v, unicode.IsSpace)) {
				return invalid()
			}
		}
		if p.Credentials != "" && (!absolute(p.Credentials) || !a.Scope.Contains(p.Credentials)) {
			return platform.Usage("credentials-outside-scope")
		}
		if a.Scope.System && p.Credentials != "" && !within(a.Scope.ConfigRoot, p.Credentials) {
			return invalid()
		}
		if p.Health.Timeout < 0 || p.Health.Timeout > 120 {
			return invalid()
		}
		if len(p.NoProxy) > 128 {
			return invalid()
		}
		for _, s := range p.NoProxy {
			if len(s) > 253 || !noProxyPattern.MatchString(s) {
				return invalid()
			}
		}
	}
	for n, b := range m.Bindings {
		if !namePattern.MatchString(n) || !namePattern.MatchString(b.Adapter) {
			return invalid()
		}
		if _, ok := m.Profiles[b.Profile]; !ok {
			return invalid()
		}
		if b.Adapter == "systemd" && !unitPattern.MatchString(b.Target) {
			return invalid()
		}
		if b.Target != "" && !cleanString(b.Target) {
			return invalid()
		}
		if b.ConnectHost != "" && !validHost(b.ConnectHost) {
			return invalid()
		}
	}
	return nil
}
func within(root, p string) bool {
	r, e := filepath.Rel(root, p)
	return e == nil && r != ".." && !strings.HasPrefix(r, ".."+string(filepath.Separator))
}
func validHost(s string) bool {
	s = strings.Trim(s, "[]")
	if ip := net.ParseIP(s); ip != nil {
		return !ip.IsUnspecified()
	}
	return regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$`).MatchString(s)
}
func defaults(p profile) profile {
	if p.Health.Timeout == 0 {
		p.Health.Timeout = 10
	}
	if len(p.NoProxy) == 0 {
		p.NoProxy = []string{"localhost", "127.0.0.1", "::1"}
	}
	return p
}
func validateCredentials(c credentials) error {
	if !cleanString(c.Username) || !cleanString(c.Password) || len(c.Username) > 255 || len(c.Password) > 255 || strings.ContainsAny(c.Username, ": \t\r\n") {
		return platform.Usage("credentials-invalid")
	}
	return nil
}
func loadCredentials(p profile) (credentials, error) {
	var c credentials
	if p.Credentials == "" {
		return c, platform.Usage("credentials-required")
	}
	b, e := platform.ReadPrivate(p.Credentials)
	if e != nil {
		return c, e
	}
	if e = decode(b, &c); e != nil {
		return c, e
	}
	raw, e := platform.DecodeYAML(b)
	if e != nil {
		return c, e
	}
	if _, ok := raw["username"].(string); !ok {
		return c, platform.Usage("credentials-invalid")
	}
	if _, ok := raw["password"].(string); !ok {
		return c, platform.Usage("credentials-invalid")
	}
	return c, validateCredentials(c)
}
func resolve(a platform.App, name string) (resolved, error) {
	var x resolved
	var e error
	x.Manager, e = loadManager(a)
	if e != nil {
		return x, e
	}
	if name == "" {
		name = x.Manager.Default
	}
	p, ok := x.Manager.Profiles[name]
	if !ok {
		return x, platform.Usage("profile-unknown")
	}
	x.Name = name
	x.Profile = defaults(p)
	x.Text, e = readManagedFile(a, x.Manager.Core.Config)
	if e != nil {
		return x, e
	}
	x.Config, e = platform.DecodeYAML(x.Text)
	if e != nil {
		return x, e
	}
	x.Endpoints, x.Controller, e = parseEndpoints(x.Config, a.Scope.System, x.Manager.Allow)
	if e != nil {
		return x, e
	}
	if platform.Bool(platform.Map(x.Config["tun"])["enable"]) != x.Manager.Tun.Enabled {
		return x, platform.Usage("tun-authorization-mismatch")
	}
	if x.Manager.Tun.Enabled {
		b, e := platform.ReadPrivate(tunReceiptPath(a))
		if e != nil {
			return x, e
		}
		var rec tunReceipt
		if json.Unmarshal(b, &rec) != nil || rec.Device != tunDevice(x.Manager) || rec.UID != 0 {
			return x, platform.Usage("tun-authorization-mismatch")
		}
	}
	for _, role := range []struct {
		name string
		http bool
	}{{p.HTTP, true}, {p.SOCKS, false}} {
		if role.name == "" {
			continue
		}
		found := false
		for _, ep := range x.Endpoints {
			if ep.Name == role.name && ((role.http && ep.http()) || (!role.http && ep.socks())) {
				found = true
			}
		}
		if !found {
			return x, platform.Usage("profile-listener-invalid")
		}
	}
	x.Credentials, e = loadCredentials(p)
	if e != nil {
		return x, e
	}
	for _, ep := range x.Endpoints {
		if ep.Name == p.HTTP || ep.Name == p.SOCKS {
			if !hasCredential(ep, x.Credentials) {
				return x, platform.Usage("credentials-mismatch")
			}
		}
	}
	return x, nil
}
func readManagedFile(a platform.App, p string) ([]byte, error) {
	if a.Scope.System {
		if c, e := loadCompound(a); e == nil && c != nil && (p == c.Before.Core.Config || p == c.Next.Core.Config) {
			return readSystemConfig(p)
		}
		config := filepath.Join(a.Scope.ConfigRoot, "mihomo", "config.yaml")
		if m, e := loadManager(a); e == nil {
			config = m.Core.Config
		}
		if p == config {
			return readSystemConfig(p)
		}
	}
	return platform.ReadPrivate(p)
}
func hasCredential(ep endpoint, c credentials) bool {
	for _, v := range ep.Users {
		if v == c {
			return true
		}
	}
	return false
}
func parseEndpoints(cfg map[string]any, system bool, allowed []string) ([]endpoint, *endpoint, error) {
	out := []endpoint{}
	var controller *endpoint
	for _, k := range []string{"allow-lan"} {
		if v, ok := cfg[k]; ok {
			if _, ok = v.(bool); !ok {
				return nil, nil, invalid()
			}
		}
	}
	if v, ok := cfg["tun"]; ok {
		if _, ok = v.(map[string]any); !ok {
			return nil, nil, invalid()
		}
		if enabled, ok := platform.Map(v)["enable"]; ok {
			if _, ok = enabled.(bool); !ok {
				return nil, nil, invalid()
			}
		}
	}
	if !system && (platform.Bool(platform.Map(cfg["tun"])["enable"]) || platform.Bool(cfg["allow-lan"])) {
		return nil, nil, invalid()
	}
	if v, ok := cfg["dns"]; ok {
		if _, ok = v.(map[string]any); !ok {
			return nil, nil, invalid()
		}
	}
	for _, k := range []string{"skip-auth-prefixes", "external-doh-server", "external-controller-tls", "external-controller-unix", "external-controller-pipe"} {
		if v, ok := cfg[k]; ok && v != nil {
			return nil, nil, invalid()
		}
	}
	if platform.Map(cfg["dns"])["listen"] != nil {
		return nil, nil, invalid()
	}
	address := func(raw string) (string, error) {
		if raw == "localhost" {
			raw = "127.0.0.1"
		}
		ip := net.ParseIP(strings.Trim(raw, "[]"))
		if ip == nil || ip.IsUnspecified() {
			return "", invalid()
		}
		s := ip.String()
		if !ip.IsLoopback() {
			ok := false
			for _, v := range allowed {
				if s == v && system {
					ok = true
				}
			}
			if !ok {
				return "", invalid()
			}
		}
		return s, nil
	}
	add := func(ep endpoint) error {
		var e error
		ep.Address, e = address(ep.Address)
		if e != nil {
			return e
		}
		if ep.Port < 1024 || ep.Port > 65535 || !cleanString(ep.Name) || len(ep.Name) > 64 || strings.ContainsFunc(ep.Name, unicode.IsSpace) {
			return invalid()
		}
		if ep.Type != "mixed" && ep.Type != "http" && ep.Type != "socks" && ep.Type != "redir" && ep.Type != "tproxy" {
			return invalid()
		}
		if !ep.http() && !ep.socks() && !system {
			return invalid()
		}
		if (ep.http() || ep.socks()) && len(ep.Users) == 0 {
			return platform.Usage("listener-auth-required")
		}
		ep.Authenticated = len(ep.Users) > 0
		for _, old := range out {
			if old.Name == ep.Name || old.address() == ep.address() {
				return invalid()
			}
		}
		out = append(out, ep)
		return nil
	}
	if v, ok := cfg["listeners"]; ok {
		rows, ok := v.([]any)
		if !ok {
			return nil, nil, invalid()
		}
		for _, row := range rows {
			m, ok := row.(map[string]any)
			if !ok {
				return nil, nil, invalid()
			}
			for k := range m {
				if k != "name" && k != "type" && k != "listen" && k != "port" && k != "users" {
					return nil, nil, invalid()
				}
			}
			port, ok := m["port"].(int)
			if !ok {
				return nil, nil, invalid()
			}
			ep := endpoint{Name: platform.String(m["name"]), Source: "listeners", Type: platform.String(m["type"]), Address: "127.0.0.1", Port: port}
			if v, ok := m["listen"]; ok {
				ep.Address = platform.String(v)
			}
			if v, ok := m["users"]; ok {
				users, ok := v.([]any)
				if !ok || len(users) == 0 {
					return nil, nil, invalid()
				}
				for _, u := range users {
					um, ok := u.(map[string]any)
					if !ok || len(um) != 2 {
						return nil, nil, invalid()
					}
					c := credentials{platform.String(um["username"]), platform.String(um["password"])}
					if e := validateCredentials(c); e != nil {
						return nil, nil, e
					}
					ep.Users = append(ep.Users, c)
				}
			}
			if e := add(ep); e != nil {
				return nil, nil, e
			}
		}
	}
	users := []credentials{}
	if v, ok := cfg["authentication"]; ok {
		rows, ok := v.([]any)
		if !ok {
			return nil, nil, invalid()
		}
		for _, v := range rows {
			s, ok := v.(string)
			pair := strings.SplitN(s, ":", 2)
			if !ok || len(pair) != 2 {
				return nil, nil, invalid()
			}
			c := credentials{pair[0], pair[1]}
			if e := validateCredentials(c); e != nil {
				return nil, nil, e
			}
			users = append(users, c)
		}
	}
	for _, row := range []struct{ k, t string }{{"port", "http"}, {"socks-port", "socks"}, {"mixed-port", "mixed"}, {"redir-port", "redir"}, {"tproxy-port", "tproxy"}} {
		if v, ok := cfg[row.k]; ok {
			n, ok := v.(int)
			if !ok {
				return nil, nil, invalid()
			}
			if n == 0 {
				continue
			}
			addr := "127.0.0.1"
			if v, ok := cfg["bind-address"]; ok {
				addr = platform.String(v)
			} else if platform.Bool(cfg["allow-lan"]) {
				addr = "*"
			}
			if e := add(endpoint{Name: row.k, Source: row.k, Type: row.t, Address: addr, Port: n, Users: users}); e != nil {
				return nil, nil, e
			}
		}
	}
	if v, ok := cfg["external-controller"]; ok {
		host, port, e := net.SplitHostPort(platform.String(v))
		if e != nil {
			return nil, nil, invalid()
		}
		if host == "localhost" {
			host = "127.0.0.1"
		}
		ip := net.ParseIP(host)
		var n int
		_, e = fmt.Sscanf(port, "%d", &n)
		if e != nil || fmt.Sprint(n) != port || n < 1024 || n > 65535 || ip == nil || !ip.IsLoopback() || !secretPattern.MatchString(platform.String(cfg["secret"])) {
			return nil, nil, invalid()
		}
		controller = &endpoint{Name: "controller", Source: "external-controller", Type: "controller", Address: ip.String(), Port: n, Authenticated: true}
		for _, ep := range out {
			if ep.address() == controller.address() {
				return nil, nil, invalid()
			}
		}
	}
	return out, controller, nil
}
func sortedKeys[T any](m map[string]T) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
func profileDoc(n string, p profile) map[string]any {
	p = defaults(p)
	present := false
	if p.Credentials != "" {
		_, e := platform.ReadPrivate(p.Credentials)
		present = e == nil
	}
	return map[string]any{"name": n, "http_listener": p.HTTP, "socks_listener": p.SOCKS, "credentials_file": p.Credentials, "credentials_present": present, "no_proxy": p.NoProxy, "health_timeout": p.Health.Timeout}
}
func bindingDoc(n string, b binding) map[string]any {
	return map[string]any{"name": n, "profile": b.Profile, "adapter": b.Adapter, "target": b.Target, "connect_host": b.ConnectHost}
}
