package command

import (
	"strings"
	"testing"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

func TestPublicGrammar(t *testing.T) {
	for _, tt := range []struct {
		args []string
		want string
	}{
		{[]string{"--json", "version"}, "version"},
		{[]string{"--system", "config", "validate", "--json", "--file", "/private/config.yaml"}, "config-validate"},
		{[]string{"health", "check", "--profile", "default", "--json"}, "health"},
		{[]string{"select", "my group", "my node", "--allow-cross-level"}, "select"},
		{[]string{"subscription", "apply", strings.Repeat("a", 32), "--sha256", strings.Repeat("b", 64)}, "subscription-apply"},
		{[]string{"integration", "--json"}, "integration-list"},
		{[]string{"direct", "--", "tool", "--json", "--system"}, "direct"},
	} {
		p, e := Parse(tt.args, nil, nil, nil)
		if e != nil {
			t.Fatalf("%v: %v", tt.args, e)
		}
		if p.Request.Name() != tt.want {
			t.Fatalf("%v: %s", tt.args, p.Request.Name())
		}
		if tt.want == "direct" && (p.JSON || p.System || len(p.Request.Child) != 3) {
			t.Fatal("child arguments leaked into manager")
		}
	}
}

func TestRejectedArgumentsDoNotLeakSecrets(t *testing.T) {
	secret := "https://example.invalid/token-SECRET"
	for _, args := range [][]string{{secret, "--json"}, {"status", "--secret", secret}, {"--system", "--user", "status"}, {"reset", "--apply", "--dry-run"}, {"env", "export"}, {"env", "show", "--profile", "a", "--binding", "b"}, {"latency"}, {"mode", "invalid"}, {"logs", "--lines", "NaN"}, {"status", "--system"}, {"diagnose", "url", secret}, {"update", "--python", secret}} {
		p, e := Parse(args, nil, nil, nil)
		if e == nil {
			t.Fatalf("accepted %v", args)
		}
		env := platform.Failure("mihomoctl", "user", e)
		if strings.Contains(e.Error(), secret) || strings.Contains(env.Command, secret) || strings.Contains(p.Request.Name(), secret) {
			t.Fatalf("private argument disclosed: %v", args)
		}
	}
}

func TestEveryContractHelpBeforeInitialization(t *testing.T) {
	if len(Specs()) != 74 {
		t.Fatal("baseline coverage changed without review")
	}
	for _, s := range Specs() {
		args := append(append([]string{}, s.Command...), "--help")
		p, e := Parse(args, nil, nil, nil)
		if e != nil || !strings.Contains(p.Help, strings.Join(s.Command, " ")) {
			t.Fatalf("help %v: %v", args, e)
		}
	}
}

func TestEmptyJSONIsUsage(t *testing.T) {
	p, e := Parse([]string{"--json"}, nil, nil, nil)
	if e == nil || !p.JSON {
		t.Fatal("missing command must produce JSON usage failure")
	}
}

func TestJSONModeTravelsToService(t *testing.T) {
	p, e := Parse([]string{"controller", "token", "--json"}, nil, nil, nil)
	if e != nil || !p.JSON || !p.Request.JSON {
		t.Fatal("JSON lost at service boundary", p, e)
	}
}
