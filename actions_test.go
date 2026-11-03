package main

import (
	"reflect"
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
