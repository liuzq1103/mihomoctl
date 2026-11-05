package runtimecore

import (
	"bytes"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

type adapter struct {
	Format   int    `yaml:"format"`
	Kind     string `yaml:"kind"`
	Template string `yaml:"template"`
}

var placeholderPattern = regexp.MustCompile(`\{([A-Za-z_][A-Za-z0-9_-]*)\}`)
var placeholderNames = []string{"http_url", "https_url", "socks_url", "no_proxy", "profile", "binding", "connect_host"}

func builtinAdapter(name string) bool {
	return member(name, "exec", "systemd", "docker", "kubernetes", "supervisor", "pm2", "ci")
}
func loadAdapter(a platform.App, name string) (adapter, error) {
	if builtinAdapter(name) {
		return adapter{Format: 1, Kind: name}, nil
	}
	if !namePattern.MatchString(name) {
		return adapter{}, platform.Usage("adapter-invalid")
	}
	path := filepath.Join(a.Scope.ConfigRoot, "adapters", name+".json")
	if e := platform.CheckPath(path); e != nil {
		return adapter{}, e
	}
	if _, e := os.Lstat(path); os.IsNotExist(e) {
		return adapter{}, platform.Usage("adapter-unknown")
	}
	b, e := platform.ReadPrivate(path)
	if e != nil {
		return adapter{}, e
	}
	raw, e := platform.DecodeYAML(b)
	if e != nil {
		return adapter{}, platform.Usage("adapter-invalid")
	}
	format, ok := raw["format"].(int)
	kind, kindOK := raw["kind"].(string)
	template, templateOK := raw["template"].(string)
	if len(raw) != 3 || !ok || format != 1 || !kindOK || !member(kind, "docker", "kubernetes", "supervisor", "pm2", "ci") || !templateOK || utf8.RuneCountInString(template) > 65536 {
		return adapter{}, platform.Usage("adapter-invalid")
	}
	for _, match := range placeholderPattern.FindAllStringSubmatch(template, -1) {
		if !member(match[1], placeholderNames...) {
			return adapter{}, platform.Usage("adapter-invalid")
		}
	}
	return adapter{format, kind, template}, nil
}

// asciiJSON follows Python's json.dumps(ensure_ascii=True) literal escaping;
// values are inserted once, never rescanned as template input or evaluated.
func asciiJSON(s string) string {
	var buf bytes.Buffer
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"', '\\':
			buf.WriteByte('\\')
			buf.WriteRune(r)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 32 || r >= 127 {
				if r > 0xffff {
					a, b := utf16.EncodeRune(r)
					fmt.Fprintf(&buf, `\u%04x\u%04x`, a, b)
				} else {
					fmt.Fprintf(&buf, `\u%04x`, r)
				}
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
	return buf.String()
}
func renderTemplate(template string, values map[string]string, kind string) (string, error) {
	if !member(kind, "docker", "kubernetes", "supervisor", "pm2", "ci") {
		return "", platform.Usage("adapter-invalid")
	}
	// Match v1.5.1's malformed-placeholder rule, including literal ordinary
	// braces (JavaScript object syntax is not itself a placeholder).
	for _, name := range placeholderNames {
		needle := "{" + name
		for offset := 0; offset < len(template); {
			i := strings.Index(template[offset:], needle)
			if i < 0 {
				break
			}
			end := offset + i + len(needle)
			if end == len(template) || !((template[end] >= 'A' && template[end] <= 'Z') || (template[end] >= 'a' && template[end] <= 'z') || (template[end] >= '0' && template[end] <= '9') || template[end] == '_' || template[end] == '}') {
				return "", platform.Usage("adapter-invalid")
			}
			offset = end
		}
	}
	var out strings.Builder
	last := 0
	for _, indices := range placeholderPattern.FindAllStringSubmatchIndex(template, -1) {
		start, end := indices[0], indices[1]
		key := template[indices[2]:indices[3]]
		if !member(key, placeholderNames...) {
			return "", platform.Usage("adapter-invalid")
		}
		value, ok := values[key]
		if !ok {
			return "", platform.Usage("adapter-incomplete")
		}
		if strings.ContainsFunc(value, func(r rune) bool { return r < 32 || r == 127 }) {
			return "", platform.Usage("adapter-invalid")
		}
		if kind != "docker" && ((start > 0 && strings.ContainsRune(`'"`, rune(template[start-1]))) || (end < len(template) && strings.ContainsRune(`'"`, rune(template[end])))) {
			return "", platform.Usage("adapter-invalid")
		}
		out.WriteString(template[last:start])
		switch kind {
		case "kubernetes", "pm2", "ci":
			out.WriteString(asciiJSON(value))
		case "supervisor":
			value = strings.ReplaceAll(value, "%", "%%")
			out.WriteString(quoteEnvironment(value))
		default:
			out.WriteString(value)
		}
		last = end
	}
	out.WriteString(template[last:])
	return out.String(), nil
}
func rehostEnvironment(vars map[string]string, host string) (map[string]string, error) {
	out := map[string]string{}
	for k, v := range vars {
		if member(strings.ToLower(k), "http_proxy", "https_proxy", "all_proxy") {
			u, e := urlParseProxy(v, host)
			if e != nil {
				return nil, e
			}
			out[k] = u
		} else {
			out[k] = v
		}
	}
	return out, nil
}
func customExport(a platform.App, n string, b binding, vars map[string]string) (map[string]string, error) {
	custom, e := loadAdapter(a, b.Adapter)
	if e != nil {
		return nil, e
	}
	if builtinAdapter(b.Adapter) {
		return nil, nil
	}
	if custom.Template == "" {
		return nil, platform.Usage("adapter-unknown")
	}
	if member(custom.Kind, "docker", "kubernetes") {
		if b.ConnectHost == "" {
			return nil, platform.Usage("export-requires-connect-host")
		}
		vars, e = rehostEnvironment(vars, b.ConnectHost)
		if e != nil {
			return nil, e
		}
	}
	host := b.ConnectHost
	if host == "" {
		host = "127.0.0.1"
	}
	values := map[string]string{"http_url": vars["HTTP_PROXY"], "https_url": vars["HTTPS_PROXY"], "socks_url": vars["ALL_PROXY"], "no_proxy": vars["NO_PROXY"], "profile": b.Profile, "binding": n, "connect_host": host}
	text, e := renderTemplate(custom.Template, values, custom.Kind)
	if e != nil {
		return nil, e
	}
	return map[string]string{"custom." + custom.Kind: text}, nil
}

func urlParseProxy(value, host string) (string, error) {
	u, e := url.Parse(value)
	if e != nil || u.Hostname() == "" || u.Port() == "" || !validHost(host) {
		return "", platform.Usage("adapter-invalid")
	}
	u.Host = net.JoinHostPort(strings.Trim(host, "[]"), u.Port())
	return u.String(), nil
}
func redactProxyVariables(vars map[string]string) (map[string]string, error) {
	out := map[string]string{}
	for k, v := range vars {
		if member(strings.ToLower(k), "http_proxy", "https_proxy", "all_proxy") {
			u, e := url.Parse(v)
			if e != nil {
				return nil, platform.Usage("adapter-invalid")
			}
			u.User = url.UserPassword("REDACTED", "REDACTED")
			out[k] = u.String()
		} else {
			out[k] = v
		}
	}
	return out, nil
}
func expandOutputPath(path string) (string, error) {
	if path == "~" || strings.HasPrefix(path, "~/") || strings.HasPrefix(path, "~\\") {
		home, e := os.UserHomeDir()
		if e != nil {
			return "", e
		}
		if len(path) == 1 {
			path = home
		} else {
			path = filepath.Join(home, path[2:])
		}
	}
	if !cleanString(path) {
		return "", platform.Usage("output-path-invalid")
	}
	return filepath.Abs(path)
}
