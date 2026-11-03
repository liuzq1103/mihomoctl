package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDiscoverCtlAcceptsValidConfig(t *testing.T) {
	path := writeConfig(t, strings.Join([]string{
		"mixed-port: 7890",
		"external-controller: 127.0.0.1:9090",
		"secret: AbCdEf1234567890AbCdEf1234567890Ab",
		"",
	}, "\n"))
	cfg, err := discoverCtl(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != 9090 || cfg.Token != "AbCdEf1234567890AbCdEf1234567890Ab" {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}

func TestDiscoverCtlRejectsBadValues(t *testing.T) {
	if _, err := discoverCtl(writeConfig(t, "external-controller: 0.0.0.0:9090\nsecret: AbCdEf1234567890AbCdEf1234567890Ab\n")); err == nil {
		t.Fatal("non-loopback controller must be rejected")
	}
	if _, err := discoverCtl(writeConfig(t, "external-controller: 127.0.0.1:9090\nsecret: short\n")); err == nil {
		t.Fatal("short secret must be rejected")
	}
	if _, err := discoverCtl(writeConfig(t, "external-controller: 127.0.0.1:9090\n")); err == nil {
		t.Fatal("missing secret must be rejected")
	}
}

func TestDiscoverCtlIgnoresNestedKeys(t *testing.T) {
	path := writeConfig(t, strings.Join([]string{
		"external-controller: 127.0.0.1:9090",
		"secret: AbCdEf1234567890AbCdEf1234567890Ab",
		"tun:",
		"  external-controller: 0.0.0.0:1",
		"  secret: nested-not-read",
		"",
	}, "\n"))
	if _, err := discoverCtl(path); err != nil {
		t.Fatalf("nested duplicates must be ignored: %v", err)
	}
}
