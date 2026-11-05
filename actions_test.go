package main

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
)

// stubCli returns a canned envelope; recordingCli also captures the argv of
// every call so tests can assert how a command line was split.
type stubCli struct {
	env Envelope
	err error
}

func (c *stubCli) Run(args ...string) (Envelope, error)             { return c.env, c.err }
func (c *stubCli) RunWithStdin([]byte, ...string) (Envelope, error) { return c.env, c.err }

type recordingCli struct {
	calls [][]string
}

func (c *recordingCli) Run(args ...string) (Envelope, error) {
	c.calls = append(c.calls, args)
	return Envelope{Schema: "mihomoctl/v1", Overall: "PASS"}, nil
}

func (c *recordingCli) RunWithStdin(input []byte, args ...string) (Envelope, error) {
	return c.Run(args...)
}

// Regression: runLifecycleCLI used to slice envelopeLines(env)[1:4] without a
// length check, panicking (and killing the TUI) on envelopes with < 4 lines.
func TestRunLifecycleCLITinyEnvelopeDoesNotPanic(t *testing.T) {
	app := &App{cli: &stubCli{env: Envelope{Command: "start", Overall: "PASS"}}}
	msg := app.runLifecycleCLI("start")
	if msg.err != nil {
		t.Fatalf("unexpected error: %v", msg.err)
	}
	if msg.text != "" {
		t.Fatalf("header-only envelope must yield an empty summary, got %q", msg.text)
	}
}

// Regression: ':' passthrough used to hand the whole command line to the CLI
// as one argv element, so every multi-word passthrough verb failed.
func TestExecuteCommandPassthroughSplitsArgv(t *testing.T) {
	rec := &recordingCli{}
	app := NewApp(newDemoSource(), rec, 80, 24, pageOverview, true)
	app.executeCommand("rules status")
	msg := <-app.apiCh
	if msg.err != nil {
		t.Fatalf("passthrough failed: %v", msg.err)
	}
	if len(rec.calls) != 1 || !reflect.DeepEqual(rec.calls[0], []string{"rules", "status"}) {
		t.Fatalf("passthrough must send separate argv elements, got %q", rec.calls)
	}
}

func TestDropLastRune(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"abc", "ab"},
		{"节点", "节"},
		{"a香", "a"},
	}
	for _, c := range cases {
		if got := dropLastRune(c.in); got != c.want {
			t.Fatalf("dropLastRune(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	if !utf8.ValidString(dropLastRune("香")) {
		t.Fatal("dropLastRune must never split a multi-byte rune")
	}
}

// Regression: every fetch used to share the dedupe key "op", so a confirmed
// start/stop/restart could be silently swallowed by any other in-flight op.
func TestOpsDedupeIndependently(t *testing.T) {
	app := NewApp(newDemoSource(), &stubCli{env: Envelope{Overall: "PASS"}}, 80, 24, pageOverview, true)
	app.post("op:stop", func() apiMsg { return apiMsg{kind: "op:stop", opName: "stop"} })
	app.post("op:provider x", func() apiMsg { return apiMsg{kind: "op:provider x", opName: "provider x"} })
	// Drain until both ops landed: onAPI's refresh posts extra fetches whose
	// sends may interleave, so arrival order cannot be assumed.
	seen := map[string]bool{}
	for i := 0; i < 128 && len(seen) < 2; i++ {
		msg := <-app.apiCh
		if strings.HasPrefix(msg.kind, "op:") {
			seen[msg.kind] = true
		}
		app.onAPI(msg)
	}
	if len(seen) != 2 {
		t.Fatalf("both ops must run under distinct keys, saw %v", seen)
	}
	if app.inflight["op:stop"] || app.inflight["op:provider x"] {
		t.Fatal("each op must clear its own inflight key on completion")
	}
}

// Regression: the runtime page posted under key "cli:status" but returned
// kind "status", so inflight was never cleared and the page never refetched.
func TestRuntimeRefreshClearsInflight(t *testing.T) {
	app := NewApp(newDemoSource(), &stubCli{env: Envelope{Overall: "PASS"}}, 80, 24, pageRuntime, true)
	app.refresh(pageRuntime)
	app.onAPI(<-app.apiCh)
	if app.inflight["cli:status"] {
		t.Fatal("runtime status fetch must clear its dedupe key, or the page never refetches")
	}
}

// Regression: a FAIL envelope with exit 0 used to be announced as 完成.
func TestLifecycleFailEnvelopeReportsFailure(t *testing.T) {
	app := &App{cli: &stubCli{env: Envelope{
		Overall: "FAIL", Errors: []ErrDoc{{Code: "not-running", Detail: "服务未运行"}},
	}}}
	if msg := app.runLifecycleCLI("stop"); msg.err == nil {
		t.Fatal("FAIL envelope must surface as an error, not as 完成")
	}
}

// Regression: a stale subscription preview (the user re-previewed while the
// first request was in flight) used to install as current.
func TestStaleSubscriptionPreviewIgnored(t *testing.T) {
	app := NewApp(newDemoSource(), &stubCli{env: Envelope{Overall: "PASS"}}, 80, 24, pageSubscriptions, true)
	app.subSeq = 2 // the user already re-previewed
	preview := map[string]any{"id": "x", "sha256": "y"}
	app.onAPI(apiMsg{kind: "cli:subscription-preview:1", cliKind: "subscription-preview", preview: preview, subSeq: 1})
	if app.subPreview != nil {
		t.Fatal("stale preview must not install")
	}
	app.onAPI(apiMsg{kind: "cli:subscription-preview:2", cliKind: "subscription-preview", preview: preview, subSeq: 2})
	if app.subPreview == nil {
		t.Fatal("current preview must install")
	}
}

// Regression: PgUp on the logs page used to be a visual no-op — the window
// always re-showed the newest rows regardless of logOff.
func TestLogsPagingRevealsOlderLines(t *testing.T) {
	app := NewApp(newDemoSource(), &stubCli{env: Envelope{Overall: "PASS"}}, 100, 24, pageLogs, true)
	for i := 0; i < 60; i++ {
		app.logs = append(app.logs, LogLine{Type: "info", Payload: fmt.Sprintf("L%02dX", i)})
	}
	app.draw()
	if plain := app.scr.DumpPlain(); !strings.Contains(plain, "L59X") || strings.Contains(plain, "L20X") {
		t.Fatalf("newest window must show L59..L40, got:\n%s", plain)
	}
	app.logOff = 40
	app.draw()
	if plain := app.scr.DumpPlain(); !strings.Contains(plain, "L19X") || strings.Contains(plain, "L59X") {
		t.Fatalf("logOff=40 must reveal L19..L00, got:\n%s", plain)
	}
	if app.logOff != 40 {
		t.Fatalf("draw must not disturb a valid offset, got %d", app.logOff)
	}
	app.logOff = 500 // stale past the match set: draw-time clamp must fix it
	app.draw()
	if app.logOff != 59 {
		t.Fatalf("offset must clamp to len(rows)-1, got %d", app.logOff)
	}
}
