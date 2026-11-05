package routing

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

// VerifyController is the root TUI startup gate: nil only after the same
// contract every read command proves (configuration, ownership, 401, probe).
func TestVerifyControllerAcceptsProvenSession(t *testing.T) {
	f := newFixtureServer(t)
	a, _ := fixtureScope(t, f)
	if err := VerifyController(context.Background(), a); err != nil {
		t.Fatalf("VerifyController = %v", err)
	}
}

func TestVerifyControllerRejectsWrongSecret(t *testing.T) {
	f := newFixtureServer(t)
	a, configPath := fixtureScope(t, f)
	wrong := "external-controller: 127.0.0.1:" + fmt.Sprint(f.port()) + "\n" +
		"secret: fixture-" + repeatStr("b", 40) + "\n"
	if err := platform.AtomicWrite(configPath, []byte(wrong), 0600); err != nil {
		t.Fatal(err)
	}
	err := VerifyController(context.Background(), a)
	if err == nil || ErrorCode(err) != "controller-authentication-failed" {
		t.Fatalf("VerifyController = %v code %q", err, ErrorCode(err))
	}
}

func TestVerifyControllerRejectsNonLoopback(t *testing.T) {
	f := newFixtureServer(t)
	a, configPath := fixtureScope(t, f)
	remote := "external-controller: 0.0.0.0:" + fmt.Sprint(f.port()) + "\n" +
		"secret: " + fixtureToken + "\n"
	if err := platform.AtomicWrite(configPath, []byte(remote), 0600); err != nil {
		t.Fatal(err)
	}
	err := VerifyController(context.Background(), a)
	if err == nil || ErrorCode(err) != "controller-not-configured-as-loopback" {
		t.Fatalf("VerifyController = %v code %q", err, ErrorCode(err))
	}
}

func TestErrorCodeReturnsControlAndPlatformCodes(t *testing.T) {
	if ErrorCode(control("some-code", exitFail)) != "some-code" {
		t.Fatal("control code lost")
	}
	if ErrorCode(&platform.Error{Code: "platform-code"}) != "platform-code" {
		t.Fatal("platform code lost")
	}
	if ErrorCode(os.ErrNotExist) != "" {
		t.Fatal("foreign error produced a code")
	}
}

func repeatStr(s string, n int) string {
	out := make([]byte, 0, n*len(s))
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}

// tokenCommandRequest runs "controller token" with an explicit output buffer
// and returns both, so tests can prove what physically reached the writer.
// The mutation-gated command goes through the full Run path on Linux and the
// dispatch layer elsewhere, exactly like runMutationRequest.
func tokenCommandRequest(t *testing.T, a platform.App, options map[string]string, jsonFlag bool) (platform.Envelope, string) {
	t.Helper()
	out := &bytes.Buffer{}
	request := platform.Request{
		Command: []string{"controller", "token"},
		Options: map[string][]string{},
		Input:   strings.NewReader(""),
		Output:  out,
		Stderr:  &bytes.Buffer{},
		JSON:    jsonFlag,
	}
	for key, value := range options {
		request.Options[key] = []string{value}
	}
	if runtime.GOOS == "linux" {
		envelope, err := Run(context.Background(), a, request)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		return envelope, out.String()
	}
	configPath, manager, err := resolveRoutingContext(a, request)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := dispatch(context.Background(), a, request, manager, configPath, "")
	if err != nil {
		return failureEnvelope(request.Command[0], scopeLabel(a.Scope.System), err), out.String()
	}
	return bridgedEnvelope(request.Command[0], scopeLabel(a.Scope.System), controllerCommandWord(request.Command), payload), out.String()
}

// withTerminalOutput fakes a private terminal writer for the duration of one
// test: the JSON refusal must hold even when the output really is a tty.
func withTerminalOutput(t *testing.T) {
	t.Helper()
	previous := writerIsTerminal
	writerIsTerminal = func(io.Writer) bool { return true }
	t.Cleanup(func() { writerIsTerminal = previous })
}

// TestControllerTokenRefusesJSONBeforeAnyOutput is the disclosure fix: with
// --json requested the raw token never reaches the writer, terminal or not.
func TestControllerTokenRefusesJSONBeforeAnyOutput(t *testing.T) {
	f := newFixtureServer(t)
	a, _ := fixtureScope(t, f)

	for _, scenario := range []struct {
		name    string
		options map[string]string
		json    bool
	}{
		{"option-terminal", map[string]string{"json": "true"}, false},
		{"flag-terminal", nil, true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			withTerminalOutput(t)
			envelope, written := tokenCommandRequest(t, a, scenario.options, scenario.json)
			if envelope.Overall == "PASS" {
				t.Fatalf("token command passed under JSON: %v", envelope.Data)
			}
			if envelope.Errors[0].Code != "token-display-requires-terminal-without-json" {
				t.Fatalf("code = %q", envelope.Errors[0].Code)
			}
			if written != "" {
				t.Fatalf("raw output reached the writer under JSON: %q", written)
			}
			if strings.Contains(written, fixtureToken) || strings.Contains(fmt.Sprint(envelope.Data), fixtureToken) {
				t.Fatal("token disclosed")
			}
		})
	}
}

// TestControllerTokenWritesOnlyToPrivateTerminal keeps the allowed path
// honest: a real terminal without --json still gets the raw token, and the
// envelope still carries only the placeholder.
func TestControllerTokenWritesOnlyToPrivateTerminal(t *testing.T) {
	f := newFixtureServer(t)
	a, _ := fixtureScope(t, f)
	withTerminalOutput(t)
	envelope, written := tokenCommandRequest(t, a, nil, false)
	if envelope.Overall != "PASS" {
		t.Fatalf("overall = %s %v", envelope.Overall, envelope.Errors)
	}
	if written != fixtureToken+"\n" {
		t.Fatalf("terminal output = %q", written)
	}
	legacy := dataLegacy(t, envelope)
	if legacy["output"] != "unstructured controller output omitted" {
		t.Fatalf("payload = %v", legacy)
	}
	if strings.Contains(fmt.Sprint(envelope.Data), fixtureToken) {
		t.Fatal("token entered the envelope")
	}
}

func TestControllerConfigReturnsProvenSession(t *testing.T) {
	f := newFixtureServer(t)
	a, configPath := fixtureScope(t, f)
	// A second plausible configuration inside the same tree must not divert
	// the proof: the manager's recorded path is the only source.
	decoyDir := privateTempDir(t)
	decoy := "external-controller: 127.0.0.1:19999\nsecret: fixture-" + repeatStr("c", 40) + "\n"
	if err := platform.AtomicWrite(filepath.Join(decoyDir, "config.yaml"), []byte(decoy), 0600); err != nil {
		t.Fatal(err)
	}

	host, port, token, path, err := ControllerConfig(context.Background(), a)
	if err != nil {
		t.Fatalf("ControllerConfig: %v", err)
	}
	if host != "127.0.0.1" || port != f.port() || token != fixtureToken || path != configPath {
		t.Fatalf("ControllerConfig = %s/%d/%s/%s want 127.0.0.1/%d/%s/%s",
			host, port, token, path, f.port(), fixtureToken, configPath)
	}
}

func TestControllerConfigRejectsUnprovenSession(t *testing.T) {
	f := newFixtureServer(t)
	a, configPath := fixtureScope(t, f)
	wrong := "external-controller: 127.0.0.1:" + fmt.Sprint(f.port()) + "\n" +
		"secret: fixture-" + repeatStr("d", 40) + "\n"
	if err := platform.AtomicWrite(configPath, []byte(wrong), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := ControllerConfig(context.Background(), a); err == nil ||
		ErrorCode(err) != "controller-authentication-failed" {
		t.Fatalf("ControllerConfig = %v code %q", err, ErrorCode(err))
	}
}

// TestSubscriptionSaveAndStartGateOffLinux pins the mutation gate of the new
// native TUI capability where the foundation refuses mutations.
func TestSubscriptionSaveAndStartGateOffLinux(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("covered by the Linux activation tests")
	}
	f := newFixtureServer(t)
	a, _ := fixtureScope(t, f)
	envelope, err := SubscriptionSaveAndStart(context.Background(), a, "x", "y")
	if err != nil {
		t.Fatal(err)
	}
	if envelope.Overall == "PASS" || envelope.Errors[0].Code != "linux-required" {
		t.Fatalf("gate = %s %v", envelope.Overall, envelope.Errors)
	}
}
