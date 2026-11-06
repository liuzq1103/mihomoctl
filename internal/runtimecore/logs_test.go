package runtimecore

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

func secretLogFixture(t *testing.T) (platform.App, manager, string) {
	t.Helper()
	a, m := fixture(t)
	cfg, e := platform.ReadYAML(m.Core.Config, true)
	if e != nil {
		t.Fatal(e)
	}
	cfg["proxy-providers"] = map[string]any{"private": map[string]any{"url": "https://configured.invalid/sub?token=configured-token", "path": "providers/data.yaml"}}
	cfg["proxies"] = []any{map[string]any{"name": "secret-node", "uuid": "node-uuid-private", "private-key": "node-private-key"}}
	if e = platform.WriteYAML(m.Core.Config, cfg); e != nil {
		t.Fatal(e)
	}
	raw := "controller=" + strings.Repeat("a", 64) + " password=unit-secret uuid=node-uuid-private key=node-private-key url=https://configured.invalid/sub?token=configured-token other=https://userinfo-user:userinfo-password@remote.invalid/path?ToKeN=query-token&KEY=query-key&secret=query-secret&password=query-password&auth=query-auth ok\t\x1b\x00\x7f\n"
	return a, m, raw
}
func assertRedactedLog(t *testing.T, text string) {
	t.Helper()
	for _, secret := range []string{strings.Repeat("a", 64), "unit-secret", "node-uuid-private", "node-private-key", "configured-token", "userinfo-user", "userinfo-password", "query-token", "query-key", "query-secret", "query-password", "query-auth"} {
		if strings.Contains(text, secret) {
			t.Fatalf("log leaked configured/URL credential (%d bytes)", len(secret))
		}
	}
	for _, r := range text {
		if r != '\n' && unicode.IsControl(r) {
			t.Fatalf("log retained control rune U+%04X", r)
		}
	}
	if !strings.Contains(text, "[redacted]") {
		t.Fatal("fixture was not redacted")
	}
}
func TestProcessLogSnapshotRedactionAndEntriesContract(t *testing.T) {
	a, _, raw := secretLogFixture(t)
	path := filepath.Join(a.Scope.StateRoot, "logs", "mihomo.log")
	if e := platform.AtomicWrite(path, []byte(raw), 0600); e != nil {
		t.Fatal(e)
	}
	doc, e := Run(context.Background(), a, platform.Request{Command: []string{"logs"}, JSON: true})
	if e != nil {
		t.Fatal(e)
	}
	entries, ok := doc.Data["entries"].([]string)
	if !ok || len(entries) != 1 {
		t.Fatal("baseline entries contract missing", doc)
	}
	if _, ok = doc.Data["logs"]; ok {
		t.Fatal("raw text logs field remains public")
	}
	assertRedactedLog(t, entries[0])
	encoded, e := json.Marshal(doc)
	if e != nil {
		t.Fatal(e)
	}
	assertRedactedLog(t, string(encoded))
}
func TestLogJSONFollowRejectedBeforeOutputAndConfigAccess(t *testing.T) {
	var out bytes.Buffer
	doc, e := Run(context.Background(), testApp(t), platform.Request{Command: []string{"logs"}, JSON: true, Options: map[string][]string{"follow": {}}, Output: &out, Stderr: &out})
	requireCode(t, e, "logs-follow-json")
	if out.Len() != 0 || doc.Overall == "PASS" {
		t.Fatal("JSON-follow emitted output before refusal")
	}
}
func TestRedactedStreamProtectsEveryChunkBoundary(t *testing.T) {
	_, _, raw := secretLogFixture(t)
	cfg := map[string]any{"secret": strings.Repeat("a", 64), "password": "unit-secret", "uuid": "node-uuid-private", "private-key": "node-private-key", "url": "https://configured.invalid/sub?token=configured-token"}
	redactor := makeLogRedactor(cfg)
	for split := 0; split <= len(raw); split++ {
		var out bytes.Buffer
		stream := redactedLogStream{Writer: &out, Redactor: redactor}
		if _, e := stream.Write([]byte(raw[:split])); e != nil {
			t.Fatal(e)
		}
		if split < len(raw) && out.Len() != 0 {
			t.Fatal("partial line escaped stream")
		}
		if _, e := stream.Write([]byte(raw[split:])); e != nil {
			t.Fatal(e)
		}
		if e := stream.Flush(); e != nil {
			t.Fatal(e)
		}
		assertRedactedLog(t, out.String())
	}
	var out bytes.Buffer
	stream := redactedLogStream{Writer: &out, Redactor: redactor}
	stream.Write([]byte(strings.Repeat("x", maxRawLogLine+1)))
	stream.Write([]byte("unit-secret\n"))
	if out.String() != "[redacted oversized log entry]\n" {
		t.Fatal("oversized line was partially emitted")
	}
}

type synchronizedLogWriter struct {
	mu sync.Mutex
	bytes.Buffer
	signal chan struct{}
}

func (w *synchronizedLogWriter) WriteString(s string) (int, error) { return w.Write([]byte(s)) }

func (w *synchronizedLogWriter) Write(raw []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n, e := w.Buffer.Write(raw)
	select {
	case w.signal <- struct{}{}:
	default:
	}
	return n, e
}
func (w *synchronizedLogWriter) text() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.Buffer.String()
}
func TestProcessFollowRedactsAppendedSplitSecrets(t *testing.T) {
	a, _, raw := secretLogFixture(t)
	path := filepath.Join(a.Scope.StateRoot, "logs", "mihomo.log")
	if e := platform.AtomicWrite(path, []byte("initial safe line\ncontroller="+strings.Repeat("a", 24)), 0600); e != nil {
		t.Fatal(e)
	}
	writer := &synchronizedLogWriter{signal: make(chan struct{}, 20)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, e := Run(ctx, a, platform.Request{Command: []string{"logs"}, Options: map[string][]string{"follow": {}}, Output: writer})
		done <- e
	}()
	select {
	case <-writer.signal:
	case <-time.After(3 * time.Second):
		t.Fatal("follow did not print snapshot")
	}
	f, e := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.WriteString(strings.Repeat("a", 40) + " password=unit-secret\n" + raw); e != nil {
		f.Close()
		t.Fatal(e)
	}
	f.Close()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	for !strings.Contains(writer.text(), "query") && !strings.Contains(writer.text(), "ToKeN=") {
		select {
		case <-writer.signal:
		case <-deadline.C:
			t.Fatal("follow did not print appended redacted entries")
		}
	}
	cancel()
	select {
	case e := <-done:
		if e != context.Canceled {
			t.Fatal(e)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("follow ignored cancellation")
	}
	assertRedactedLog(t, writer.text())
	if strings.Contains(writer.text(), strings.Repeat("a", 24)) {
		t.Fatal("partial configured secret leaked from initial follow snapshot")
	}
}
func TestJournalSnapshotsCaptureUnitScopeAndRedact(t *testing.T) {
	for _, system := range []bool{false, true} {
		args := journalArguments(system, "2026-11-05 10:00:00", "now", 17, false)
		if member("--user", args...) == system || !member("mihomoctl-go.service", args...) {
			t.Fatal("incorrect captured journal scope/unit", args)
		}
		if system && runtime.GOOS == "linux" && os.Geteuid() != 0 {
			continue
		}
		a, m, raw := secretLogFixture(t)
		a.Scope.System = system
		if system {
			a.Scope.Name = "system"
		}
		m.Core.Backend = "systemd"
		if e := platform.WriteYAML(a.Scope.ManagerPath(), m); e != nil {
			t.Fatal(e)
		}
		called := false
		reader := func(ctx context.Context, args []string, r platform.Request, redactor logRedactor) ([]byte, error) {
			called = true
			joined := strings.Join(args, "|")
			if !strings.Contains(joined, "-u|mihomoctl-go.service") || !strings.Contains(joined, "--since=2026-11-05 10:00:00") || !strings.Contains(joined, "--until=now") || !strings.Contains(joined, "-n|17") {
				t.Fatal(args)
			}
			if member("--user", args...) == system {
				t.Fatal("journal scope argument mismatch", args)
			}
			return []byte(raw), nil
		}
		verify := func(ctx context.Context, got platform.App, gotManager manager) error {
			if got.Scope != a.Scope || gotManager.Core.Binary != m.Core.Binary {
				t.Fatal("wrong runtime ownership context")
			}
			return nil
		}
		doc, e := journalWithBackend(context.Background(), a, "2026-11-05 10:00:00", "now", 17, reader, verify)
		if e != nil || !called {
			t.Fatal(doc, e)
		}
		assertRedactedLog(t, doc.Data["entries"].([]string)[0])
		called = false
		doc, e = logsWithBackend(context.Background(), a, platform.Request{Command: []string{"logs"}}, func(context.Context, []string, platform.Request, logRedactor) ([]byte, error) {
			called = true
			return []byte(raw), nil
		}, verify)
		if e != nil || !called {
			t.Fatal(e)
		}
		assertRedactedLog(t, doc.Data["entries"].([]string)[0])
	}
}
func TestJournalProcessTimeFiltersAndInvalidInput(t *testing.T) {
	a, _, _ := secretLogFixture(t)
	path := filepath.Join(a.Scope.StateRoot, "logs", "mihomo.log")
	raw := []byte("time=\"2026-11-05T10:00:00+08:00\" unit-secret\ntime=\"2026-11-05T11:00:00+08:00\" unit-secret\ntime=\"2026-11-05T12:00:00+08:00\" unit-secret\n")
	if e := platform.AtomicWrite(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	doc, e := Journal(context.Background(), a, "2026-11-05T10:30:00+08:00", "2026-11-05T11:30:00+08:00", 20)
	if e != nil {
		t.Fatal(e)
	}
	entries := doc.Data["entries"].([]string)
	if len(entries) != 1 || !strings.Contains(entries[0], "11:00:00") {
		t.Fatal(entries)
	}
	assertRedactedLog(t, entries[0])
	for _, bad := range []string{"now\n-u unrelated.service", strings.Repeat("x", 129), "\x00"} {
		_, e = Journal(context.Background(), a, bad, "", 20)
		requireCode(t, e, "logs-time-invalid")
	}
	if e = platform.AtomicWrite(path, []byte("unstructured historic line\n"), 0600); e != nil {
		t.Fatal(e)
	}
	_, e = Journal(context.Background(), a, "today", "", 20)
	requireCode(t, e, "logs-time-filter-unavailable")
	_, e = Journal(context.Background(), a, "", "", 0)
	requireCode(t, e, "logs-lines-invalid")
}
func TestJournalOwnershipFailureDoesNotReadBackend(t *testing.T) {
	a, m, _ := secretLogFixture(t)
	m.Core.Backend = "systemd"
	if e := platform.WriteYAML(a.Scope.ManagerPath(), m); e != nil {
		t.Fatal(e)
	}
	read := false
	_, e := journalWithBackend(context.Background(), a, "", "", 10, func(context.Context, []string, platform.Request, logRedactor) ([]byte, error) {
		read = true
		return nil, nil
	}, func(context.Context, platform.App, manager) error { return platform.Usage("runtime-identity-mismatch") })
	requireCode(t, e, "runtime-identity-mismatch")
	if read {
		t.Fatal("queried journal after ownership failed")
	}
}
func TestNewLogRedactorSnapshotsAllProfileCredentialsWithoutPerLineReads(t *testing.T) {
	a, m, _ := secretLogFixture(t)
	secondPath := filepath.Join(a.Scope.ConfigRoot, "credentials", "secondary.yaml")
	if e := platform.WriteYAML(secondPath, credentials{"other-user", "secondary-private-password"}); e != nil {
		t.Fatal(e)
	}
	m.Profiles["secondary"] = profile{HTTP: "proxy", SOCKS: "proxy", Credentials: secondPath}
	if e := platform.WriteYAML(a.Scope.ManagerPath(), m); e != nil {
		t.Fatal(e)
	}
	redact, e := NewLogRedactor(a)
	if e != nil || redact == nil {
		t.Fatal(e)
	}
	for _, p := range []string{a.Scope.ManagerPath(), m.Core.Config, m.Profiles["default"].Credentials, secondPath} {
		if e = os.Remove(p); e != nil {
			t.Fatal(e)
		}
	}
	line := "controller=" + strings.Repeat("a", 64) + " password=unit-secret other=secondary-private-password https://userinfo-user:userinfo-password@host/?token=query-token\x1b"
	const workers = 12
	var wg sync.WaitGroup
	failures := make(chan string, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out := redact(line)
			if strings.Contains(out, "secondary-private-password") || strings.Contains(out, "unit-secret") || strings.Contains(out, "query-token") || strings.Contains(out, "userinfo-password") || strings.Contains(out, strings.Repeat("a", 64)) {
				failures <- out
			}
		}()
	}
	wg.Wait()
	close(failures)
	for range failures {
		t.Fatal("immutable shared redactor leaked cached secrets")
	}
}
func TestNewLogRedactorFailsClosedOnMissingOrUnreadableInputs(t *testing.T) {
	a := testApp(t)
	redact, e := NewLogRedactor(a)
	if e == nil || redact != nil {
		t.Fatal("missing config produced an unsafe generic redactor")
	}
	a, m := fixture(t)
	m.Profiles["broken"] = profile{HTTP: "proxy", Credentials: filepath.Join(a.Scope.ConfigRoot, "credentials", "missing.yaml")}
	if e := platform.WriteYAML(a.Scope.ManagerPath(), m); e != nil {
		t.Fatal(e)
	}
	redact, e = NewLogRedactor(a)
	if e == nil || redact != nil {
		t.Fatal("missing secondary credentials produced a redactor")
	}
	a, _ = fixture(t)
	if e := platform.WriteJSON(compoundPath(a), map[string]any{"pending": true}); e != nil {
		t.Fatal(e)
	}
	redact, e = NewLogRedactor(a)
	requireCode(t, e, "transaction-recovery-required")
	if redact != nil {
		t.Fatal("pending transaction exposed a redactor")
	}
}

var _ io.Writer = (*synchronizedLogWriter)(nil)
