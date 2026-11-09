//go:build linux

package runtimecore

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

func TestConfigValidationSuccessContract(t *testing.T) {
	a := initializedApp(t)
	for _, action := range []string{"validate", "check"} {
		doc, err := Run(context.Background(), a, platform.Request{Command: []string{"config", action}})
		want := []platform.Check{
			{Name: "config-parse", Status: "PASS", Evidence: "confirmed", Detail: "1 listening surfaces"},
			{Name: "core-validate", Status: "PASS", Evidence: "confirmed"},
		}
		if err != nil || doc.Command != "config-validate" || doc.ExitCode() != 0 || !reflect.DeepEqual(doc.Checks, want) {
			t.Fatalf("config %s: %+v %v", action, doc, err)
		}
		raw, _ := json.Marshal(doc.Checks[1])
		if string(raw) != `{"name":"core-validate","status":"PASS","evidence":"confirmed"}` {
			t.Fatalf("unexpected core check detail: %s", raw)
		}
	}
}

func TestInitialPlanReceiptContract(t *testing.T) {
	a := initializedApp(t)
	m, err := loadManager(a)
	if err != nil {
		t.Fatal(err)
	}
	for _, explicit := range []bool{false, true} {
		opts := map[string][]string{"core": {m.Core.Binary}}
		if explicit {
			opts["port"] = []string{"18879"}
		}
		_, _, result, err := initialPlan(context.Background(), a, platform.Request{Options: opts})
		if err != nil {
			t.Fatal(err)
		}
		if result["backend"] != "process" || platform.Map(result["core"])["adopted"] != true || result["listener"] != "proxy" || result["port_is_candidate"] != !explicit || len(result) != 9 {
			t.Fatalf("init receipt: %#v", result)
		}
		if _, present := result["scope"]; present {
			t.Fatal("unexpected redundant scope field", result)
		}
		if _, present := result["state"]; present {
			t.Fatal("unexpected init state field", result)
		}
	}
}

func TestStatusAndHealthLiveContract(t *testing.T) {
	a := initializedApp(t)
	ctx := context.Background()
	started, err := Run(ctx, a, platform.Request{Command: []string{"start"}})
	if err != nil || started.ExitCode() != 0 {
		t.Fatal(started, err)
	}
	runtime := platform.Map(started.Data["runtime"])
	if runtime["backend"] != "process" || runtime["running"] != true || runtime["listening"] != true || len(platform.Map(runtime["identity"])) != 5 || started.Data["error"] != nil || !reflect.DeepEqual(started.Data["errors"], []string{}) {
		t.Fatalf("live status: %+v", started)
	}
	if _, exists := runtime["detail"]; exists {
		t.Fatal("live runtime must not add detail", runtime)
	}
	if platform.Map(started.Data["core"])["backend"] != "process" || platform.Map(started.Data["controller"])["status"] != "listening" || platform.Map(started.Data["controller"])["evidence"] != "inferred" {
		t.Fatalf("live ownership: %#v", started.Data)
	}
	health, err := Run(ctx, a, platform.Request{Command: []string{"health", "check"}})
	if err != nil || health.Command != "health" || health.ExitCode() != 0 || !reflect.DeepEqual(health.Data, map[string]any{"overall": "PASS"}) {
		t.Fatal(health, err)
	}
	x, err := resolve(a, "")
	if err != nil {
		t.Fatal(err)
	}
	want := []platform.Check{
		{Name: "manager-config", Status: "PASS", Evidence: "confirmed"},
		{Name: "runtime", Status: "PASS", Evidence: "inferred", Detail: "identity checked"},
		{Name: "listener-proxy", Status: "PASS", Evidence: "inferred", Detail: x.Endpoints[0].address() + " listening (uid ownership confirmed)"},
		{Name: "auth-anon-proxy", Status: "PASS", Evidence: "confirmed", Detail: "407"},
		{Name: "auth-http-proxy", Status: "PASS", Evidence: "confirmed", Detail: "status=502"},
		{Name: "auth-socks-anon-proxy", Status: "PASS", Evidence: "confirmed", Detail: "anonymous-rejected"},
		{Name: "auth-socks-proxy", Status: "PASS", Evidence: "confirmed", Detail: "authenticated"},
		{Name: "controller-ownership", Status: "PASS", Evidence: "inferred"},
		{Name: "controller", Status: "PASS", Evidence: "confirmed", Detail: "anonymous-401+authorized-200"},
	}
	if !reflect.DeepEqual(health.Checks, want) {
		t.Fatalf("live health checks: %+v\nwant %+v", health.Checks, want)
	}
	stopped, err := Run(ctx, a, platform.Request{Command: []string{"stop"}})
	if err != nil || stopped.ExitCode() != 0 {
		t.Fatal(stopped, err)
	}
	wantRuntime := map[string]any{"backend": "process", "running": false, "detail": "no-state"}
	if !reflect.DeepEqual(stopped.Data["runtime"], wantRuntime) || stopped.Data["error"] != "no-state" || platform.Map(stopped.Data["core"])["status"] != "no-state" || platform.Map(stopped.Data["controller"])["evidence"] != "unavailable" || platform.Map(stopped.Data["controller"])["status"] != "not-listening" {
		t.Fatalf("stopped status: %+v", stopped)
	}
	if _, exists := platform.Map(stopped.Data["controller"])["listening"]; exists {
		t.Fatal("controller must report status/evidence", stopped.Data)
	}
	health, err = Run(ctx, a, platform.Request{Command: []string{"health"}})
	want = []platform.Check{
		{Name: "manager-config", Status: "PASS", Evidence: "confirmed"},
		{Name: "runtime", Status: "FAIL", Evidence: "inferred", Detail: "no-state"},
		{Name: "listener-proxy", Status: "SKIPPED", Evidence: "confirmed", Detail: "runtime-not-running"},
		{Name: "controller", Status: "SKIPPED", Evidence: "confirmed", Detail: "runtime-not-running"},
	}
	if err != nil || health.ExitCode() != 1 || !reflect.DeepEqual(health.Checks, want) {
		t.Fatalf("stopped health: %+v %v", health, err)
	}
}

func TestResetSuccessCommandNames(t *testing.T) {
	a := initializedApp(t)
	doc, err := Run(context.Background(), a, platform.Request{Command: []string{"reset"}, Options: map[string][]string{"dry-run": {}}})
	if err != nil || doc.Command != "reset-preview" || doc.Overall != "PASS" {
		t.Fatal(doc, err)
	}
	doc, err = Run(context.Background(), a, platform.Request{Command: []string{"reset"}, Options: map[string][]string{"apply": {}, "plan-sha256": {doc.Data["plan_sha256"].(string)}}})
	if err != nil || doc.Command != "reset-apply" || doc.Overall != "PASS" {
		t.Fatal(doc, err)
	}
}

func TestManagerUnsafeReadKeepsSpecificCode(t *testing.T) {
	a, _ := fixture(t)
	if err := os.Chmod(a.Scope.ManagerPath(), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := loadManager(a)
	requireCode(t, err, "private-permissions-required")
	if renderError(err) != "private-permissions-required: file must have mode 600: "+a.Scope.ManagerPath() {
		t.Fatal(renderError(err))
	}
}
