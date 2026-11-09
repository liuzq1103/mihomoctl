// Package platform contains the shared CLI/TUI contracts and private filesystem primitives.
package platform

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const Version = "0.2.0"
const Schema = "mihomoctl/v1"
const Limit = 16 << 20

type Check struct {
	Name     string `json:"name"`
	Status   string `json:"status"`
	Evidence string `json:"evidence"`
	Detail   string `json:"detail,omitempty"`
}
type ErrorDoc struct {
	Code        string `json:"code"`
	Detail      string `json:"detail,omitempty"`
	Remediation string `json:"remediation,omitempty"`
}
type Envelope struct {
	Schema  string         `json:"schema"`
	Command string         `json:"command"`
	Scope   string         `json:"scope"`
	Overall string         `json:"overall"`
	Data    map[string]any `json:"data"`
	Checks  []Check        `json:"checks"`
	Errors  []ErrorDoc     `json:"errors"`
}
type Error struct {
	Code, Detail string
	Remediation  string
	Exit         int
}

func (e *Error) Error() string { return e.Code }
func Fail(code string) error   { return &Error{Code: code, Exit: 1} }
func Usage(code string) error  { return &Error{Code: code, Exit: 2} }

// UsageDetail carries the human-readable diagnostic and the remediation hint
// of a usage or permission refusal. The baseline publishes both fields, so
// the JSON envelope keeps them as well.
func UsageDetail(code, detail, remediation string) error {
	return &Error{Code: code, Detail: detail, Remediation: remediation, Exit: 2}
}

// FailDetail reports an observed failure with its diagnostic text.
func FailDetail(code, detail string) error {
	return &Error{Code: code, Detail: detail, Exit: 1}
}
func Document(command, scope string, data map[string]any) Envelope {
	if data == nil {
		data = map[string]any{}
	}
	return Envelope{Schema, command, scope, "PASS", data, []Check{}, []ErrorDoc{}}
}
func Failure(command, scope string, err error) Envelope {
	e := Document(command, scope, nil)
	e.Overall = "UNVERIFIED"
	d := ErrorDoc{Code: "operation-unavailable"}
	var p *Error
	if errors.As(err, &p) {
		d.Code = p.Code
		d.Detail = p.Detail
		d.Remediation = p.Remediation
		if p.Exit == 1 {
			e.Overall = "FAIL"
		}
	}
	e.Errors = append(e.Errors, d)
	return e
}
func (e Envelope) ExitCode() int {
	if e.Overall == "PASS" {
		return 0
	}
	if e.Overall == "FAIL" {
		return 1
	}
	return 2
}

type Request struct {
	JSON           bool
	Command        []string
	Options        map[string][]string
	Args           []string
	Input          io.Reader
	Output, Stderr io.Writer
	Child          []string
}

func (r Request) Get(k string) string {
	v := r.Options[k]
	if len(v) == 0 {
		return ""
	}
	return v[len(v)-1]
}
func (r Request) Has(k string) bool { _, ok := r.Options[k]; return ok }
func (r Request) Name() string      { return strings.Join(r.Command, "-") }

// TopLevel is the requested command word, as the original reports it in a
// failure envelope: a refusal for "profile list" is reported under
// "profile", while a successful result keeps the leaf name.
func (r Request) TopLevel() string {
	if len(r.Command) == 0 {
		return ""
	}
	return r.Command[0]
}
func (r Request) Arg(n int) string {
	if n < len(r.Args) {
		return r.Args[n]
	}
	return ""
}

type Scope struct {
	System                                                        bool
	Name, ConfigRoot, DataRoot, StateRoot, CacheRoot, RuntimeRoot string
}

func NewScope(system bool) (Scope, error) {
	s := Scope{System: system, Name: "user"}
	if system {
		s.Name = "system"
		s.ConfigRoot = "/etc/mihomoctl-go"
		s.DataRoot = "/var/lib/mihomoctl-go"
		s.StateRoot = s.DataRoot
		s.CacheRoot = "/var/cache/mihomoctl-go"
		s.RuntimeRoot = "/run/mihomoctl-go"
		return s, nil
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return s, Usage("home-unavailable")
	}
	roots := []struct {
		env, def string
		dst      *string
	}{{"XDG_CONFIG_HOME", ".config", &s.ConfigRoot}, {"XDG_DATA_HOME", ".local/share", &s.DataRoot}, {"XDG_STATE_HOME", ".local/state", &s.StateRoot}, {"XDG_CACHE_HOME", ".cache", &s.CacheRoot}}
	for _, r := range roots {
		v := os.Getenv(r.env)
		if v == "" {
			v = filepath.Join(h, r.def)
		}
		if !filepath.IsAbs(v) {
			return s, Usage("config-invalid")
		}
		*r.dst = filepath.Join(v, "mihomoctl-go")
	}
	s.RuntimeRoot = filepath.Join(s.StateRoot, "runtime")
	if v := os.Getenv("XDG_RUNTIME_DIR"); filepath.IsAbs(v) {
		s.RuntimeRoot = filepath.Join(v, "mihomoctl-go")
	}
	return s, nil
}
func (s Scope) ManagerPath() string  { return filepath.Join(s.ConfigRoot, "manager.yaml") }
func (s Scope) CoreHome() string     { return filepath.Join(s.DataRoot, "core-home") }
func (s Scope) RuntimeState() string { return filepath.Join(s.StateRoot, "runtime.json") }
func (s Scope) RequireMutation() error {
	if runtime.GOOS != "linux" {
		return Usage("linux-required")
	}
	if s.System && os.Geteuid() != 0 {
		return Usage("system-requires-root")
	}
	if !s.System && os.Geteuid() == 0 {
		return Usage("root-requires-system")
	}
	return nil
}
func (s Scope) Contains(path string) bool {
	p, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	for _, root := range []string{s.ConfigRoot, s.DataRoot, s.StateRoot, s.CacheRoot, s.RuntimeRoot} {
		r, e := filepath.Rel(root, p)
		if e == nil && r != ".." && !strings.HasPrefix(r, ".."+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}

type App struct{ Scope Scope }

func (a App) LoadManager() (map[string]any, error) { return ReadYAML(a.Scope.ManagerPath(), true) }
func (a App) CoreConfigPath() (string, error) {
	m, e := a.LoadManager()
	if e != nil {
		return "", e
	}
	c := Map(m["core"])
	p := String(c["config"])
	if p == "" {
		return "", Usage("config-invalid")
	}
	if !a.Scope.Contains(p) {
		return "", Usage("config-outside-scope")
	}
	return p, nil
}
func Map(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}
func String(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
func Int(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	}
	return 0
}
func Bool(v any) bool      { b, _ := v.(bool); return b }
func Hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func Token() (string, error) {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		return "", e
	}
	return hex.EncodeToString(b), nil
}

// CheckPath rejects symlinks in every existing component, not just the leaf.
func CheckPath(path string) error {
	p, e := filepath.Abs(path)
	if e != nil {
		return Usage("unsafe-path")
	}
	for {
		st, err := os.Lstat(p)
		if err == nil {
			if st.Mode()&os.ModeSymlink != 0 {
				return Usage("symlink-refused")
			}
		} else if !os.IsNotExist(err) {
			return Usage("path-unavailable")
		}
		q := filepath.Dir(p)
		if q == p {
			break
		}
		p = q
	}
	return nil
}
func ReadPrivate(path string) ([]byte, error) {
	if e := CheckPath(path); e != nil {
		return nil, e
	}
	f, e := OpenRegular(path)
	if e != nil {
		return nil, Usage("config-missing")
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() {
		return nil, Usage("unsafe-file")
	}
	if e = checkOwner(st, true); e != nil {
		return nil, e
	}
	b, e := io.ReadAll(io.LimitReader(f, Limit+1))
	if e != nil {
		return nil, e
	}
	if len(b) > Limit {
		return nil, Usage("file-too-large")
	}
	return b, nil
}
func PrivateDir(path string) error {
	if e := CheckPath(path); e != nil {
		return e
	}
	if e := os.MkdirAll(path, 0700); e != nil {
		return e
	}
	st, e := os.Stat(path)
	if e != nil {
		return e
	}
	return checkOwner(st, true)
}
func AtomicWrite(path string, b []byte, mode os.FileMode) error {
	if e := CheckPath(path); e != nil {
		return e
	}
	if e := PrivateDir(filepath.Dir(path)); e != nil {
		return e
	}
	if st, e := os.Stat(path); e == nil {
		if e = checkOwner(st, true); e != nil {
			return e
		}
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".write-*")
	if e != nil {
		return e
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if e = f.Chmod(mode); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e == nil {
		e = closeErr
	}
	if e != nil {
		return e
	}
	if e = os.Rename(tmp, path); e != nil {
		return e
	}
	// A rename is only durable once the directory entry itself is flushed.
	// The failure is reported: a publication that cannot confirm its
	// durability must not be reported as a success.
	return SyncDirectory(filepath.Dir(path))
}
func WriteJSON(path string, v any) error {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	return AtomicWrite(path, append(b, '\n'), 0600)
}
func WriteYAML(path string, v any) error {
	b, e := yaml.Marshal(v)
	if e != nil {
		return e
	}
	return AtomicWrite(path, b, 0600)
}
func StrictYAML(b []byte) (*yaml.Node, error) {
	if len(b) > Limit {
		return nil, Usage("config-too-large")
	}
	var root yaml.Node
	dec := yaml.NewDecoder(bytes.NewReader(b))
	if e := dec.Decode(&root); e != nil {
		if e == io.EOF {
			return nil, UsageDetail("config-invalid", "expected exactly one YAML document", "")
		}
		return nil, UsageDetail("config-invalid", yamlSyntaxDiagnostic(b, e), "")
	}
	var extra yaml.Node
	if dec.Decode(&extra) != io.EOF {
		return nil, UsageDetail("config-multiple-documents", "expected exactly one YAML document", "")
	}
	count := 0
	var walk func(*yaml.Node, int) error
	walk = func(n *yaml.Node, d int) error {
		count++
		if d > 100 || count > 200000 {
			return Usage("config-too-complex")
		}
		if n.Kind == yaml.AliasNode || n.Anchor != "" {
			return UsageDetail("yaml-alias-disabled", fmt.Sprintf("YAML anchors/aliases are not allowed (line %d column %d)", n.Line, n.Column), "")
		}
		if n.Kind == yaml.MappingNode {
			seen := map[string]bool{}
			for i := 0; i < len(n.Content); i += 2 {
				k := n.Content[i]
				if k.Kind != yaml.ScalarNode || k.Tag != "!!str" {
					return UsageDetail("yaml-duplicate-or-invalid-key", fmt.Sprintf("unhashable YAML key at line %d", k.Line), "")
				}
				if seen[k.Value] {
					return UsageDetail("yaml-duplicate-or-invalid-key", fmt.Sprintf("duplicate YAML key at line %d column %d", k.Line, k.Column), "")
				}
				seen[k.Value] = true
			}
		}
		for _, c := range n.Content {
			if e := walk(c, d+1); e != nil {
				return e
			}
		}
		return nil
	}
	if e := walk(&root, 0); e != nil {
		return nil, e
	}
	if len(root.Content) != 1 || root.Content[0].Kind != yaml.MappingNode {
		return nil, UsageDetail("config-must-be-mapping", "core configuration must be a YAML mapping", "")
	}
	return &root, nil
}

var yamlErrorLine = regexp.MustCompile(`(?:^| )line ([0-9]+):`)

// yamlSyntaxDiagnostic reports source coordinates without echoing YAML values.
// yaml.v3 reports the last token's line for an unfinished flow collection;
// the actual error position in that case is the end of the input.
func yamlSyntaxDiagnostic(input []byte, problem error) string {
	line, column := 1, 1
	message := problem.Error()
	if match := yamlErrorLine.FindStringSubmatch(message); len(match) == 2 {
		line, _ = strconv.Atoi(match[1])
	}
	if strings.Contains(message, "expected node content") || strings.Contains(message, "unexpected end of stream") {
		line = bytes.Count(input, []byte{'\n'}) + 1
		if last := bytes.LastIndexByte(input, '\n'); last >= 0 {
			column = len(input) - last
		} else {
			column = len(input) + 1
		}
	}
	return fmt.Sprintf("YAML error (line %d column %d)", line, column)
}

// ConfigDiagnostic projects strict parser refusals onto the public baseline
// config-invalid code while preserving the primitive's safe source position.
// Internal callers can still distinguish the original safety error codes.
func ConfigDiagnostic(err error) error {
	var problem *Error
	if !errors.As(err, &problem) {
		return err
	}
	switch problem.Code {
	case "config-invalid", "config-multiple-documents", "config-must-be-mapping", "yaml-duplicate-or-invalid-key", "yaml-alias-disabled":
		return UsageDetail("config-invalid", problem.Detail, problem.Remediation)
	}
	return err
}
func DecodeYAML(b []byte) (map[string]any, error) {
	n, e := StrictYAML(b)
	if e != nil {
		return nil, e
	}
	var m map[string]any
	if e = n.Decode(&m); e != nil {
		return nil, Usage("config-invalid")
	}
	return m, nil
}
func ReadYAML(path string, private bool) (map[string]any, error) {
	var b []byte
	var e error
	if private {
		b, e = ReadPrivate(path)
	} else {
		if e = CheckPath(path); e == nil {
			b, e = os.ReadFile(path)
		}
	}
	if e != nil {
		return nil, e
	}
	return DecodeYAML(b)
}
func PatchYAML(b []byte, changes map[string]any) ([]byte, error) {
	n, e := StrictYAML(b)
	if e != nil {
		return nil, e
	}
	root := n.Content[0]
	for k, v := range changes {
		var value yaml.Node
		if e = value.Encode(v); e != nil {
			return nil, e
		}
		found := false
		for i := 0; i < len(root.Content); i += 2 {
			if root.Content[i].Value == k {
				value.HeadComment = root.Content[i+1].HeadComment
				value.LineComment = root.Content[i+1].LineComment
				root.Content[i+1] = &value
				found = true
				break
			}
		}
		if !found {
			root.Content = append(root.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: k}, &value)
		}
	}
	return yaml.Marshal(n)
}
func WithLock(ctx context.Context, s Scope, fn func() error) error {
	if e := s.RequireMutation(); e != nil {
		return e
	}
	if e := PrivateDir(s.RuntimeRoot); e != nil {
		return e
	}
	return withLock(ctx, filepath.Join(s.RuntimeRoot, "manager.lock"), func() error {
		if e := recoverAll(ctx, s); e != nil {
			return e
		}
		return fn()
	})
}

// WithPreviewLock takes the same scope lock as WithLock but never replays a
// recovery journal. A preview must not change the live configuration: a
// pending recovery is refused instead of replayed, so the journal survives
// the preview and the next explicitly authorized mutation finishes it. The
// lock is still taken, so a preview never observes state another mutation is
// halfway through publishing.
func WithPreviewLock(ctx context.Context, s Scope, fn func() error) error {
	if e := s.RequireMutation(); e != nil {
		return e
	}
	if e := PrivateDir(s.RuntimeRoot); e != nil {
		return e
	}
	return withLock(ctx, filepath.Join(s.RuntimeRoot, "manager.lock"), func() error {
		if e := CheckPending(s); e != nil {
			return e
		}
		return fn()
	})
}
func ReadLimited(r io.Reader) ([]byte, error) {
	if r == nil {
		return nil, Usage("stdin-required")
	}
	b, e := io.ReadAll(io.LimitReader(r, Limit+1))
	if e != nil {
		return nil, e
	}
	if len(b) > Limit {
		return nil, Usage("input-too-large")
	}
	return b, nil
}
func SafeError(err error) string {
	var p *Error
	if errors.As(err, &p) {
		return p.Code
	}
	return fmt.Sprintf("operation-unavailable (%T)", err)
}

var _ = time.Second
