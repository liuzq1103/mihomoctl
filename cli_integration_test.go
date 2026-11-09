package main

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/liuzq1103/mihomoctl/internal/command"
	"github.com/liuzq1103/mihomoctl/internal/platform"
)

func TestBridgeUnwrapsControllerPayload(t *testing.T) {
	env := platform.Document("subscription", "user", map[string]any{"legacy": map[string]any{"schema": "controller/v1", "command": "subscription", "overall": "PASS", "id": "abc", "sha256": "digest"}, "exit": 0})
	got, e := bridgeEnvelope(env)
	if e != nil || got.Data["id"] != "abc" || got.Schema != platform.Schema {
		t.Fatal(got, e)
	}
	if _, ok := got.Data["schema"]; ok {
		t.Fatal("controller metadata leaked into TUI payload")
	}
}
func TestBuiltInServiceDoesNotNeedAnExecutable(t *testing.T) {
	cli := newRealCli("missing-python-mihomoctl")
	env, e := cli.Run("version")
	if e != nil || env.Overall != "PASS" || env.Data["version"] != platform.Version {
		t.Fatal(env, e)
	}
}
func TestNativeServiceRefusalsRemainEnvelopes(t *testing.T) {
	env, e := newRealCli("").Run("status", "--bad", "private-token")
	if e != nil || env.Overall != "UNVERIFIED" {
		t.Fatal(env, e)
	}
	b, _ := json.Marshal(env)
	if strings.Contains(string(b), "private-token") {
		t.Fatal("private argument disclosed")
	}
}

func TestConsoleServiceAndCLIUseTheSameParserRefusal(t *testing.T) {
	args := []string{"config", "validate", "--private-bad-option"}
	p, err := command.Parse(args, nil, nil, nil)
	if err == nil {
		t.Fatal("parser accepted invalid option")
	}
	want := platform.Failure(p.Request.TopLevel(), "user", err)
	got, err := newRealCli("").Run(args...)
	if err != nil {
		t.Fatal(err)
	}
	left, _ := json.Marshal(want)
	right, _ := json.Marshal(got)
	var leftValue, rightValue any
	_ = json.Unmarshal(left, &leftValue)
	_ = json.Unmarshal(right, &rightValue)
	if !reflect.DeepEqual(leftValue, rightValue) {
		t.Fatalf("CLI and TUI refusal differ: %s / %s", left, right)
	}
}
func TestInProcessCapabilitiesImplemented(t *testing.T) {
	var cli any = newRealCli("")
	if _, ok := cli.(SubscriptionInputCli); !ok {
		t.Fatal("guided input not implemented")
	}
	if _, ok := cli.(SubscriptionDiscardCli); !ok {
		t.Fatal("discard not implemented")
	}
	if _, ok := cli.(RuntimeOwnerSource); !ok {
		t.Fatal("owner proof missing")
	}
}
func TestNoCommandHandlerIsSilentlySkipped(t *testing.T) {
	p, e := command.Parse([]string{"release", "fetch", "--help"}, nil, nil, nil)
	if e != nil || !strings.Contains(p.Help, "--sha256") {
		t.Fatal("reviewed download hash unavailable through CLI", e)
	}
	env := command.Execute(context.Background(), false, platform.Request{Command: []string{"not-a-command"}})
	if env.Overall == "PASS" {
		t.Fatal(env)
	}
}

func TestHumanHealthFailureExplainsChecks(t *testing.T) {
	env := platform.Document("health", "user", nil)
	env.Overall = "FAIL"
	env.Checks = []platform.Check{{Name: "runtime-running", Status: "FAIL", Evidence: "confirmed"}}
	if !strings.Contains(humanOutput(env), "FAIL runtime-running") {
		t.Fatal("silent failure")
	}
}
func TestEnvironmentRevealTextIsNotJSON(t *testing.T) {
	env := platform.Document("env-export", "user", map[string]any{"environment": map[string]string{"http_proxy": "http://u:p@127.0.0.1:7890"}})
	out := humanOutput(env)
	if !strings.HasPrefix(out, "http_proxy=http://") || strings.HasPrefix(out, "{") {
		t.Fatal(out)
	}
}
