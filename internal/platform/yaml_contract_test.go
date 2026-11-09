package platform

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestYAMLDiagnosticsPreservePublicContractWithoutSourceValues(t *testing.T) {
	for _, tt := range []struct {
		name, input, internalCode, detail string
	}{
		{"malformed", "listeners: [\n", "config-invalid", "YAML error (line 2 column 1)"},
		{"duplicate", "password: PRIVATE_VALUE\npassword: ANOTHER_PRIVATE_VALUE\n", "yaml-duplicate-or-invalid-key", "duplicate YAML key at line 2 column 1"},
		{"sequence", "- PRIVATE_VALUE\n", "config-must-be-mapping", "core configuration must be a YAML mapping"},
		{"multiple", "a: PRIVATE_VALUE\n---\nb: ANOTHER_PRIVATE_VALUE\n", "config-multiple-documents", "expected exactly one YAML document"},
		{"empty", "", "config-invalid", "expected exactly one YAML document"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeYAML([]byte(tt.input))
			internal := Failure("config", "user", err)
			if err == nil || len(internal.Errors) != 1 || internal.Errors[0].Code != tt.internalCode {
				t.Fatalf("internal safety contract changed: %+v", internal)
			}
			public := Failure("config", "user", ConfigDiagnostic(err))
			if public.ExitCode() != 2 || public.Errors[0].Code != "config-invalid" || public.Errors[0].Detail != tt.detail {
				t.Fatalf("public diagnostic: %+v", public)
			}
			encoded, _ := json.Marshal(public)
			if strings.Contains(string(encoded), "PRIVATE_VALUE") {
				t.Fatal("source value leaked through YAML diagnostic")
			}
		})
	}
}
