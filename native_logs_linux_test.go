//go:build linux

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

// This is a runtimecore-format identity, obtained from the kernel rather than
// a mocked owner proof. The test process really owns the httptest listener.
func nativeLogsRecordOwner(t *testing.T, f *rootRegressionFixture, stale bool) {
	t.Helper()
	stat, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		t.Fatal(err)
	}
	end := strings.LastIndexByte(string(stat), ')')
	if end < 0 {
		t.Fatal("invalid /proc/self/stat")
	}
	fields := strings.Fields(string(stat)[end+1:])
	if len(fields) < 20 {
		t.Fatal("missing process start time")
	}
	info, err := os.Stat("/proc/self")
	if err != nil {
		t.Fatal(err)
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(owner.Uid) != os.Geteuid() {
		t.Fatal("test process UID is not proven")
	}
	exe, err := os.Readlink("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	argv, err := os.ReadFile("/proc/self/cmdline")
	if err != nil {
		t.Fatal(err)
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	start := fields[19]
	if stale {
		start = "0"
	}
	state := map[string]any{
		"version": 1, "namespace": "mihomoctl-go", "scope": "user",
		"config": f.ConfigPath, "home": f.App.Scope.CoreHome(),
		"identity": map[string]any{
			"pid": os.Getpid(), "uid": int(owner.Uid), "start_time": start,
			"boot_id": strings.TrimSpace(string(boot)), "exe": exe,
			"argv": strings.Split(strings.TrimSuffix(string(argv), "\x00"), "\x00"),
		},
	}
	if err := platform.WriteJSON(f.App.Scope.RuntimeState(), state); err != nil {
		t.Fatal(err)
	}
}

type nativeLogsHTTPFixture struct {
	server     *httptest.Server
	anonymous  atomic.Int32
	authorized atomic.Int32
	logs       atomic.Int32
	wrongLevel atomic.Bool
	wrongAuth  atomic.Bool
}

func nativeLogsController(t *testing.T, token, payload string) *nativeLogsHTTPFixture {
	t.Helper()
	f := &nativeLogsHTTPFixture{}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if r.URL.Path == "/version" {
			if auth == "" {
				f.anonymous.Add(1)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if auth != "Bearer "+token {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			f.authorized.Add(1)
			fmt.Fprintln(w, `{"version":"native-log-fixture"}`)
			return
		}
		if r.URL.Path != "/logs" {
			http.NotFound(w, r)
			return
		}
		f.logs.Add(1)
		if auth != "Bearer "+token {
			f.wrongAuth.Store(true)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Query().Get("level") != "debug" {
			f.wrongLevel.Store(true)
		}
		w.Header().Set("Content-Type", "application/x-ndjson")
		for _, line := range []LogLine{{Type: "warning", Payload: payload}, {Type: "info", Payload: "harmless-tail"}} {
			if err := json.NewEncoder(w).Encode(line); err != nil {
				return
			}
			w.(http.Flusher).Flush()
		}
		// Keep a real stream open so cancellation must close the native channel.
		<-r.Context().Done()
	}))
	t.Cleanup(f.server.Close)
	return f
}

func nativeLogsPort(t *testing.T, server *httptest.Server) int {
	t.Helper()
	addr, ok := server.Listener.Addr().(*net.TCPAddr)
	if !ok || !addr.IP.IsLoopback() || addr.Port < 1024 {
		t.Fatal("controller fixture must be an unprivileged loopback listener")
	}
	return addr.Port
}

func TestNativeLogsRedactOwnedControllerStream(t *testing.T) {
	rootRegressionNonRoot(t)
	const privateURL = "https://subscription.invalid/private-path?token=provider-secret"
	const secondPassword = "unused-profile-private-password"
	const querySecret = "unconfigured-query-secret"
	const userinfo = "private-url-password"
	payload := "visible-prefix " + rootRegressionToken + " " + rootRegressionPassword + " " + secondPassword +
		" " + privateURL + " https://probe.invalid/?token=" + querySecret +
		" https://user:" + userinfo + "@probe.invalid/path visible-suffix\x1b[31m"
	server := nativeLogsController(t, rootRegressionToken, payload)
	f := newRootRegressionFixture(t, nativeLogsPort(t, server.server))
	f.Config["proxy-providers"] = map[string]any{"private": map[string]any{"type": "http", "url": privateURL}}
	f.writeConfig(t)
	otherCredentials := filepath.Join(f.App.Scope.ConfigRoot, "credentials", "secondary.yaml")
	if err := platform.WriteYAML(otherCredentials, map[string]any{"username": "secondary", "password": secondPassword}); err != nil {
		t.Fatal(err)
	}
	platform.Map(f.Manager["profiles"])["secondary"] = map[string]any{
		"http_listener": "proxy", "socks_listener": "proxy", "credentials_file": otherCredentials,
	}
	f.writeManager(t)
	nativeLogsRecordOwner(t, f, false)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	source := &nativeSource{cli: &realCli{}}
	logs, err := source.StartLogsAt(ctx, "debug")
	if err != nil {
		t.Fatal("opening the proven native stream:", err)
	}
	for i, wantType := range []string{"warning", "info"} {
		select {
		case line, ok := <-logs:
			if !ok || line.Type != wantType {
				t.Fatalf("log %d missing or metadata changed (open=%v type=%q)", i, ok, line.Type)
			}
			raw, err := json.Marshal(line)
			if err != nil {
				t.Fatal(err)
			}
			for name, secret := range map[string]string{
				"controller token": rootRegressionToken, "profile password": rootRegressionPassword,
				"secondary password": secondPassword, "private URL": privateURL,
				"provider query": "provider-secret", "unconfigured query": querySecret, "URL userinfo": userinfo,
			} {
				if strings.Contains(string(raw), secret) {
					t.Fatalf("%s reached the native log channel", name)
				}
			}
			if i == 0 && (!strings.Contains(line.Payload, "visible-prefix") || !strings.Contains(line.Payload, "visible-suffix") || !strings.Contains(line.Payload, "[redacted]") || strings.ContainsRune(line.Payload, '\x1b')) {
				t.Fatal("native redaction discarded useful content or retained terminal escapes")
			}
			if i == 1 && line.Payload != "harmless-tail" {
				t.Fatal("native redaction changed a harmless log entry")
			}
		case <-ctx.Done():
			t.Fatal("native log delivery timed out")
		}
	}
	if server.anonymous.Load() == 0 || server.authorized.Load() == 0 || server.logs.Load() != 1 || server.wrongAuth.Load() || server.wrongLevel.Load() {
		t.Fatal("stream did not pass the real anonymous/authenticated controller and log-level contract")
	}
	cancel()
	select {
	case _, ok := <-logs:
		if ok {
			t.Fatal("native stream emitted an unexpected entry after cancellation")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("native stream did not close after cancellation")
	}
}

func TestNativeLogsFailClosedBeforeStreaming(t *testing.T) {
	rootRegressionNonRoot(t)
	for _, problem := range []string{"stale-owner", "wrong-token", "public-credentials"} {
		t.Run(problem, func(t *testing.T) {
			accepted := rootRegressionToken
			if problem == "wrong-token" {
				accepted = strings.Repeat("z", 64)
			}
			server := nativeLogsController(t, accepted, "must-never-reach-channel "+rootRegressionPassword)
			f := newRootRegressionFixture(t, nativeLogsPort(t, server.server))
			nativeLogsRecordOwner(t, f, problem == "stale-owner")
			if problem == "public-credentials" {
				if err := os.Chmod(f.CredentialsPath, 0644); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			logs, err := (&nativeSource{cli: &realCli{}}).StartLogsAt(ctx, "debug")
			if err == nil || logs != nil {
				t.Fatal("unproven configuration/identity returned a native log stream")
			}
			if server.logs.Load() != 0 {
				t.Fatal("refusal occurred after the private log endpoint was opened")
			}
		})
	}
}
