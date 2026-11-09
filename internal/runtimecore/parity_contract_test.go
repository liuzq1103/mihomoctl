package runtimecore

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

func missingManagerDetail(a platform.App) string {
	return fmt.Sprintf("missing or unreadable: %s (No such file or directory)", a.Scope.ManagerPath())
}

func TestManagerMissingContractAndPrimitiveIsolation(t *testing.T) {
	a := testApp(t)
	_, err := loadManager(a)
	var problem *platform.Error
	if !errors.As(err, &problem) || problem.Code != "config-invalid" || problem.Detail != missingManagerDetail(a) || problem.Exit != 2 {
		t.Fatalf("manager failure: %#v", err)
	}
	for _, read := range []func() error{
		func() error { _, e := platform.ReadPrivate(a.Scope.ManagerPath()); return e },
		func() error { _, e := platform.ReadYAML(a.Scope.ManagerPath(), true); return e },
		func() error {
			_, e := loadCredentials(profile{Credentials: filepath.Join(a.Scope.ConfigRoot, "missing-credential.yaml")})
			return e
		},
	} {
		err = read()
		requireCode(t, err, "config-missing")
		if errors.As(err, &problem) && problem.Detail != "" {
			t.Fatal("manager translation escaped into shared/credential reader", problem)
		}
	}
}

func TestMissingCoreBinaryContract(t *testing.T) {
	a := testApp(t)
	path := filepath.Join(a.Scope.DataRoot, "missing-core")
	_, _, _, err := initialPlan(context.Background(), a, platform.Request{Options: map[string][]string{"core": {path}}})
	var problem *platform.Error
	if !errors.As(err, &problem) || problem.Code != "core-binary-invalid" || problem.Exit != 2 || problem.Detail != "missing binary: "+path+" (No such file or directory)" {
		t.Fatalf("missing core diagnostic: %#v", err)
	}
}

func TestRollbackRefusalContract(t *testing.T) {
	a := testApp(t)
	doc, err := Run(context.Background(), a, platform.Request{Command: []string{"rollback"}, Args: []string{"missing"}})
	if err == nil || doc.Command != "rollback" || doc.ExitCode() != 2 || len(doc.Errors) != 1 || doc.Errors[0].Code != "historical-rollback-disabled" || doc.Errors[0].Detail != "historical rollback is not supported" {
		t.Fatal(doc, err)
	}
}

func TestConfigValidationSafeYAMLDiagnostics(t *testing.T) {
	for _, row := range []struct{ name, text, detail string }{
		{"malformed", "mode: [\n", "YAML error (line 2 column 1)"},
		{"duplicate", "mode: rule\nmode: direct\n", "duplicate YAML key at line 2 column 1"},
		{"sequence", "- private-input\n", "core configuration must be a YAML mapping"},
		{"multiple", "mode: rule\n---\nmode: direct\n", "expected exactly one YAML document"},
	} {
		t.Run(row.name, func(t *testing.T) {
			a := testApp(t)
			path := filepath.Join(a.Scope.ConfigRoot, "input.yaml")
			if err := platform.AtomicWrite(path, []byte(row.text), 0600); err != nil {
				t.Fatal(err)
			}
			doc, err := Run(context.Background(), a, platform.Request{Command: []string{"config", "validate"}, Options: map[string][]string{"file": {path}}})
			if err == nil || doc.Command != "config" || doc.ExitCode() != 2 || len(doc.Errors) != 1 || doc.Errors[0].Code != "config-invalid" || doc.Errors[0].Detail != row.detail {
				t.Fatalf("public YAML diagnostic: %+v %v", doc, err)
			}
			// Shared/internal safety codes remain available to their owners.
			_, rawErr := platform.DecodeYAML([]byte(row.text))
			if row.name == "duplicate" {
				requireCode(t, rawErr, "yaml-duplicate-or-invalid-key")
			}
		})
	}
}

func TestRuntimeFailureUsesRequestedTopLevel(t *testing.T) {
	a := testApp(t)
	for _, words := range [][]string{{"profile", "list"}, {"profile", "show"}, {"env", "show"}, {"config", "validate"}, {"config", "check"}} {
		t.Run(platform.Request{Command: words}.Name(), func(t *testing.T) {
			doc, err := Run(context.Background(), a, platform.Request{Command: words, Args: []string{"default"}})
			if err == nil || doc.Command != words[0] || doc.Overall != "UNVERIFIED" || doc.ExitCode() != 2 || len(doc.Errors) != 1 || doc.Errors[0].Code != "config-invalid" || doc.Errors[0].Detail != missingManagerDetail(a) {
				t.Fatalf("failure contract: %+v, %v", doc, err)
			}
		})
	}
}

func TestStatusUninitializedContract(t *testing.T) {
	a := testApp(t)
	doc, err := Run(context.Background(), a, platform.Request{Command: []string{"status"}})
	want := map[string]any{
		"scope": "user", "backend": nil, "core": map[string]any{"initialized": false},
		"controller": nil, "listeners": []any{}, "active_config": nil, "proxy": nil,
		"mode": nil, "tun": nil,
		"errors": []string{"config-invalid: " + missingManagerDetail(a)}, "error": "config-invalid",
		"overall": "UNVERIFIED", "evidence": "unavailable",
	}
	if err != nil || doc.Command != "status" || doc.ExitCode() != 2 || len(doc.Errors) != 0 || !reflect.DeepEqual(doc.Data, want) {
		t.Fatalf("status: %+v, %v\nwant data: %#v", doc, err, want)
	}
	if _, err := os.Lstat(a.Scope.RuntimeRoot); !os.IsNotExist(err) {
		t.Fatal("read created runtime directory", err)
	}
}

func TestHealthUninitializedContract(t *testing.T) {
	a := testApp(t)
	for _, words := range [][]string{{"health"}, {"health", "check"}} {
		doc, err := Run(context.Background(), a, platform.Request{Command: words})
		want := []platform.Check{{Name: "manager-config", Status: "FAIL", Evidence: "confirmed", Detail: "config-invalid: " + missingManagerDetail(a)}}
		if err != nil || doc.Command != "health" || doc.ExitCode() != 1 || len(doc.Errors) != 0 || !reflect.DeepEqual(doc.Checks, want) || !reflect.DeepEqual(doc.Data, map[string]any{"overall": "FAIL"}) {
			t.Fatalf("health %v: %+v, %v", words, doc, err)
		}
	}
}

func TestDoctorUninitializedContract(t *testing.T) {
	a := testApp(t)
	doc, err := Run(context.Background(), a, platform.Request{Command: []string{"doctor"}})
	if err != nil || doc.ExitCode() != 1 || len(doc.Errors) != 0 || len(doc.Checks) != 5 {
		t.Fatalf("doctor: %+v, %v", doc, err)
	}
	wantNames := []string{"manager-config", "runtime", "manager-config", "dependency-systemctl", "dependency-go-binary"}
	for i, name := range wantNames {
		if doc.Checks[i].Name != name {
			t.Fatalf("check %d: %+v", i, doc.Checks[i])
		}
	}
	if doc.Checks[0].Detail != "config-invalid: "+missingManagerDetail(a) || doc.Checks[1].Status != "UNVERIFIED" || doc.Checks[1].Detail != "running=None" {
		t.Fatalf("diagnostic checks: %+v", doc.Checks)
	}
	want := map[string]any{"scope": "user", "backend": nil, "controller": nil, "listeners": []any{}, "tun": nil, "errors": []string{"config-invalid: " + missingManagerDetail(a)}}
	if doc.Data["scope"] != "user" || !reflect.DeepEqual(doc.Data["status"], want) {
		t.Fatalf("doctor data: %#v", doc.Data)
	}
}

func TestLogsMissingContract(t *testing.T) {
	a, _ := fixture(t)
	doc, err := Run(context.Background(), a, platform.Request{Command: []string{"logs"}})
	requireCode(t, err, "logs-unavailable")
	if doc.ExitCode() != 2 || doc.Command != "logs" || len(doc.Errors) != 1 || doc.Errors[0].Detail != "no process logs yet; backend=process" {
		t.Fatalf("logs: %+v", doc)
	}
}

func TestProfileListContainsOnlyProfiles(t *testing.T) {
	a, _ := fixture(t)
	for _, words := range [][]string{{"profile", "list"}, {"profiles"}} {
		doc, err := Run(context.Background(), a, platform.Request{Command: words})
		if err != nil || doc.Overall != "PASS" || len(doc.Data) != 1 || doc.Data["profiles"] == nil || doc.Command != (platform.Request{Command: words}).Name() {
			t.Fatalf("profiles: %+v %v", doc, err)
		}
	}
}

func TestProfileSetDefaultNormalizesSchema(t *testing.T) {
	a, m := fixture(t)
	raw, err := platform.ReadYAML(a.Scope.ManagerPath(), true)
	if err != nil {
		t.Fatal(err)
	}
	p := platform.Map(platform.Map(raw["profiles"])["default"])
	delete(p, "no_proxy")
	delete(p, "health")
	if err = platform.WriteYAML(a.Scope.ManagerPath(), raw); err != nil {
		t.Fatal(err)
	}
	// Exercise the same handler under test without the Linux mutation gate on
	// non-Linux hosts; Linux public Run is covered by the lifecycle test below.
	doc, err := dispatch(context.Background(), a, platform.Request{Command: []string{"profile", "set-default"}, Args: []string{"default"}})
	if err != nil || doc.Overall != "PASS" {
		t.Fatal(doc, err)
	}
	written, err := platform.ReadYAML(a.Scope.ManagerPath(), true)
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := written["tun"]; exists {
		t.Fatal("implicit TUN authorization serialized", written)
	}
	p = platform.Map(platform.Map(written["profiles"])["default"])
	if !reflect.DeepEqual(p["no_proxy"], []any{"localhost", "127.0.0.1", "::1"}) || platform.Int(platform.Map(p["health"])["timeout"]) != 10 {
		t.Fatalf("profile defaults lost: %#v", p)
	}
	m.Tun.Device = "custom0"
	if err := platform.WriteYAML(a.Scope.ManagerPath(), m); err != nil {
		t.Fatal(err)
	}
	written, err = platform.ReadYAML(a.Scope.ManagerPath(), true)
	if err != nil || platform.Map(written["tun"])["device"] != "custom0" {
		t.Fatal("explicit TUN device lost", written, err)
	}
}

func TestConfigCheckCanonicalCommandWithoutManager(t *testing.T) {
	a := testApp(t)
	path := filepath.Join(filepath.Dir(a.Scope.ConfigRoot), "input.yaml")
	if err := platform.AtomicWrite(path, []byte("mode: rule\nrules: [MATCH,DIRECT]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"check", "validate"} {
		doc, err := Run(context.Background(), a, platform.Request{Command: []string{"config", action}, Options: map[string][]string{"file": {path}}})
		want := []platform.Check{
			{Name: "config-parse", Status: "PASS", Evidence: "confirmed", Detail: "0 listening surfaces"},
			{Name: "core-validate", Status: "UNVERIFIED", Evidence: "unavailable", Detail: "initialize a trusted core before semantic validation"},
		}
		if err != nil || doc.Command != "config-validate" || doc.ExitCode() != 2 || !reflect.DeepEqual(doc.Checks, want) {
			t.Fatalf("config %s: %+v %v", action, doc, err)
		}
	}
}

func TestMigrationSuccessCommandNames(t *testing.T) {
	a := testApp(t)
	for _, flag := range []string{"dry-run", "apply"} {
		doc, err := dispatch(context.Background(), a, platform.Request{Command: []string{"migrate"}, Options: map[string][]string{flag: {}, "no-import": {}}})
		want := "migrate-apply"
		if flag == "dry-run" {
			want = "migrate-preview"
		}
		if err != nil || doc.Command != want || doc.Overall != "PASS" {
			t.Fatal(doc, err)
		}
	}
}
