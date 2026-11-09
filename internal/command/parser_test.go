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

func TestBaselineUsageErrorContract(t *testing.T) {
	for _, tt := range []struct {
		args   []string
		code   string
		detail string
		remedy string
	}{
		{[]string{"--json"}, "usage-error", "a command is required", "run mihomoctl --help"},
		{[]string{"--system", "--user", "status"}, "scope-flags-exclusive", "--user and --system are mutually exclusive", ""},
		{[]string{"status", "--secret-option", "private-value"}, "usage-error", "invalid arguments for mihomoctl status", "mihomoctl status --help; valid options: --help, --json, -h"},
		{[]string{"config", "validate", "--secret-option", "private-value"}, "usage-error", "invalid arguments for mihomoctl config", "mihomoctl config --help; valid options: --help, -h"},
		{[]string{"config", "validate", "--file"}, "usage-error", "invalid arguments for mihomoctl config validate", "mihomoctl config validate --help; valid options: --file, --help, --json, --profile, -h"},
		{[]string{"exec"}, "usage-error", "exec requires: exec [--profile P] -- COMMAND [ARGS...]", ""},
		{[]string{"direct"}, "usage-error", "direct requires: direct -- COMMAND [ARGS...]", ""},
		{[]string{"env", "show", "--profile", "a", "--binding", "b"}, "profile-binding-exclusive", "--profile and --binding are mutually exclusive", ""},
		{[]string{"private-unknown-command"}, "unknown-command", "unrecognized command; run mihomoctl --help", ""},
	} {
		t.Run(strings.Join(tt.args, " "), func(t *testing.T) {
			p, err := Parse(tt.args, nil, nil, nil)
			if err == nil {
				t.Fatal("accepted invalid arguments")
			}
			env := platform.Failure(p.Request.TopLevel(), "user", err)
			if env.ExitCode() != 2 || len(env.Errors) != 1 {
				t.Fatal(env)
			}
			doc := env.Errors[0]
			if doc.Code != tt.code || doc.Detail != tt.detail || doc.Remediation != tt.remedy {
				t.Fatalf("got %+v; want code=%s detail=%q remedy=%q", doc, tt.code, tt.detail, tt.remedy)
			}
			if strings.Contains(doc.Detail+doc.Remediation, "private-") {
				t.Fatal("private argument disclosed")
			}
			if tt.code == "scope-flags-exclusive" && p.System {
				t.Fatal("scope conflict selected system scope")
			}
		})
	}
}

func TestInvalidPinnedCoreVersionIsAParserRefusal(t *testing.T) {
	for _, verb := range []string{"install", "update"} {
		p, err := Parse([]string{"core", verb, "--version", "untrusted-version", "--dry-run"}, nil, nil, nil)
		if err == nil {
			t.Fatal("invalid core version reached acquisition")
		}
		env := platform.Failure(p.Request.TopLevel(), "user", err)
		if env.Errors[0].Code != "usage-error" || strings.Contains(env.Errors[0].Detail, "untrusted-version") {
			t.Fatal(env)
		}
	}
}

func TestEveryPythonPackagingFlagExplainsTheGoInstallationPath(t *testing.T) {
	for _, legacy := range []string{"--python", "--wheelhouse", "--extras", "--no-extras"} {
		args := []string{"update", legacy}
		if legacy != "--no-extras" {
			args = append(args, "PRIVATE_INSTALL_ARGUMENT")
		}
		_, err := Parse(args, nil, nil, nil)
		if err == nil {
			t.Fatalf("accepted %s", legacy)
		}
		env := platform.Failure("update", "user", err)
		problem := env.Errors[0]
		if env.ExitCode() != 2 || problem.Code != "python-packaging-not-supported" || !strings.Contains(problem.Remediation, "sh install.sh --user") {
			t.Fatalf("%s: %+v", legacy, env)
		}
		if strings.Contains(problem.Detail+problem.Remediation, "PRIVATE_INSTALL_ARGUMENT") {
			t.Fatal("private installation argument disclosed")
		}
	}
}
