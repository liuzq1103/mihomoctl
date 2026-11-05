package routing

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

// fixtureToken mirrors the original controller test credential.
var fixtureToken = "fixture-" + strings.Repeat("a", 40)

var fixtureRows = map[string]any{
	"Proxy / 中文": map[string]any{"type": "Selector", "now": "Node A", "all": []any{"Node A", "Node B"}},
	"Auto":       map[string]any{"type": "URLTest", "now": "Node A", "all": []any{"Node A"}},
	"Node A":     map[string]any{"type": "SS", "password": "DO-NOT-PRINT"},
	"Node B":     map[string]any{"type": "SS"},
}

// fixtureServer reproduces the original tests' loopback controller: bearer
// auth, ordered proxy table, streaming traffic, and the redirect default.
type fixtureServer struct {
	server *httptest.Server
	mu     sync.Mutex
	rows   map[string]any
	puts   int
	patch  map[string]any
	mode   string
}

func newFixtureServer(t *testing.T) *fixtureServer {
	t.Helper()
	f := &fixtureServer{rows: deepCopyMap(fixtureRows), mode: "rule"}
	mux := http.NewServeMux()
	authenticated := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer "+fixtureToken {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			next(w, r)
		}
	}
	mux.HandleFunc("/version", authenticated(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, `{"version": "fixture"}`)
	}))
	mux.HandleFunc("/proxies", authenticated(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		payload, _ := json.Marshal(map[string]any{"proxies": f.rows})
		w.Write(append(payload, '\n'))
	}))
	mux.HandleFunc("/connections", authenticated(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, `{"connections": [{"metadata": {"host": "PRIVATE-HOST"}, "chains": ["Node B", "Proxy"], "rule": "Match"}]}`)
	}))
	mux.HandleFunc("/traffic", authenticated(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, `{"up": 10, "down": 20}`)
	}))
	mux.HandleFunc("/configs", authenticated(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.Method == http.MethodPatch {
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			f.patch = body
			if m, ok := body["mode"].(string); ok {
				f.mode = m
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		fmt.Fprintf(w, "{\"mode\": %q, \"secret\": %q}\n", f.mode, fixtureToken)
	}))
	mux.HandleFunc("/dns/query", authenticated(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, `{"Answer": [{"name": "example.com", "type": 1, "TTL": 60, "data": "192.0.2.1"}]}`)
	}))
	mux.HandleFunc("/providers/proxies", authenticated(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, `{"providers": {"provider / fixture": {"vehicleType": "HTTP", "updatedAt": "now", "proxies": [{"name": "provider node", "type": "Shadowsocks", "password": "DO-NOT-PRINT"}], "url": "PRIVATE-URL"}}}`)
	}))
	mux.HandleFunc("/", authenticated(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/unsupported":
			w.WriteHeader(http.StatusNotFound)
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/providers/proxies/"):
			f.mu.Lock()
			f.puts++
			f.mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/proxies/"):
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			f.mu.Lock()
			f.puts++
			f.rows["Proxy / 中文"].(map[string]any)["now"] = body["name"]
			f.mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		case strings.Contains(r.URL.Path, "/delay"):
			fmt.Fprintln(w, `{"delay": 32}`)
		default:
			w.Header().Set("Location", "http://example.com/")
			w.WriteHeader(http.StatusFound)
		}
	}))
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

func (f *fixtureServer) port() int {
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(f.server.URL, "http://"))
	n := 0
	for _, c := range port {
		n = n*10 + int(c-'0')
	}
	return n
}

// privateTempDir is t.TempDir tightened to 0700: the platform foundation
// refuses to write private documents under group/other-readable parents.
func privateTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

// fixtureScope builds a private scope rooted at a temp directory with the
// manager and core configuration pointing at the fixture controller.
func fixtureScope(t *testing.T, f *fixtureServer) (platform.App, string) {
	t.Helper()
	root := privateTempDir(t)
	scope := platform.Scope{
		Name:        "user",
		ConfigRoot:  filepath.Join(root, "config"),
		DataRoot:    filepath.Join(root, "data"),
		StateRoot:   filepath.Join(root, "state"),
		CacheRoot:   filepath.Join(root, "cache"),
		RuntimeRoot: filepath.Join(root, "state", "runtime"),
	}
	configPath := filepath.Join(scope.ConfigRoot, "mihomo", "config.yaml")
	config := "external-controller: 127.0.0.1:" + fmt.Sprint(f.port()) + "\n" +
		"secret: " + fixtureToken + "\n" +
		"proxies: [{name: test, type: ss, password: PRIVATE-LOG-CREDENTIAL}]\n"
	if err := platform.AtomicWrite(configPath, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	app := platform.App{Scope: scope}
	binary := fixtureRuntimeBinary(t, app, configPath)
	manager := "version: 1\ncore:\n  binary: " + binary + "\n  config: " + configPath + "\n  backend: process\n"
	if err := platform.AtomicWrite(scope.ManagerPath(), []byte(manager), 0600); err != nil {
		t.Fatal(err)
	}
	return app, configPath
}

func runRequest(t *testing.T, a platform.App, command []string, args ...string) platform.Envelope {
	t.Helper()
	return RunRequest(t, a, command, nil, args...)
}

// RunRequest builds a Request around explicit option/argument splits. Output
// and Stderr are pipes, never terminals, so terminal-only behaviors are
// deterministic under `go test`.
func RunRequest(t *testing.T, a platform.App, command []string, options map[string]string, args ...string) platform.Envelope {
	t.Helper()
	request := platform.Request{
		Command: command,
		Options: map[string][]string{},
		Args:    args,
		Input:   strings.NewReader(""),
		Output:  &bytes.Buffer{},
		Stderr:  &bytes.Buffer{},
	}
	for key, value := range options {
		request.Options[key] = []string{value}
	}
	envelope, err := Run(context.Background(), a, request)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	return envelope
}

// runMutationRequest covers a mutating command through the full Run path on
// Linux, where the foundation mutation gate is active. Elsewhere the gate
// refuses non-Linux runs before dispatch, so the dispatch layer is exercised
// directly to keep the handler contract tested everywhere.
func runMutationRequest(t *testing.T, a platform.App, command []string, args ...string) platform.Envelope {
	t.Helper()
	if runtime.GOOS == "linux" {
		return runRequest(t, a, command, args...)
	}
	request := platform.Request{
		Command: command,
		Options: map[string][]string{},
		Args:    args,
		Input:   strings.NewReader(""),
		Output:  &bytes.Buffer{},
		Stderr:  &bytes.Buffer{},
	}
	configPath, manager, err := resolveRoutingContext(a, request)
	if err != nil {
		t.Fatalf("resolveRoutingContext: %v", err)
	}
	payload, err := dispatch(context.Background(), a, request, manager, configPath, "")
	if err != nil {
		return failureEnvelope(command[0], scopeLabel(a.Scope.System), err)
	}
	return bridgedEnvelope(command[0], scopeLabel(a.Scope.System), controllerCommandWord(command), payload)
}

func dataLegacy(t *testing.T, envelope platform.Envelope) map[string]any {
	t.Helper()
	if envelope.Schema != platform.Schema {
		t.Fatalf("envelope schema = %q", envelope.Schema)
	}
	legacy, ok := envelope.Data["legacy"].(map[string]any)
	if !ok {
		t.Fatalf("missing legacy payload: %v", envelope.Data)
	}
	return legacy
}

func mustEqual(t *testing.T, what string, got, want any) {
	t.Helper()
	gotJSON, _ := json.Marshal(normalizeForCompare(got))
	wantJSON, _ := json.Marshal(normalizeForCompare(want))
	if string(gotJSON) != string(wantJSON) {
		t.Fatalf("%s = %s, want %s", what, gotJSON, wantJSON)
	}
}

func normalizeForCompare(v any) any {
	switch typed := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, item := range typed {
			out[k] = normalizeForCompare(item)
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for i, item := range typed {
			out[i] = normalizeForCompare(item)
		}
		return out
	default:
		return v
	}
}
