package delivery

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

func TestVersionPreservesLegacyJSONWithoutInitialization(t *testing.T) {
	a := testApp(t)
	doc, e := Run(context.Background(), a, platform.Request{Command: []string{"version"}})
	if e != nil || doc.Overall != "PASS" {
		t.Fatal(doc, e)
	}
	for k, want := range map[string]any{"mihomoctl": Version, "schema": platform.Schema, "core": nil, "version": Version, "project": Project} {
		got, ok := doc.Data[k]
		if !ok || got != want {
			t.Fatalf("data.%s=%v, want %v", k, got, want)
		}
	}
	b, e := json.Marshal(doc)
	if e != nil {
		t.Fatal(e)
	}
	var decoded struct {
		Data map[string]any `json:"data"`
	}
	if e = json.Unmarshal(b, &decoded); e != nil {
		t.Fatal(e)
	}
	if v, ok := decoded.Data["core"]; !ok || v != nil {
		t.Fatal("core must be explicit JSON null")
	}
	if _, e = os.Stat(a.Scope.ConfigRoot); !os.IsNotExist(e) {
		t.Fatal("version initialized persistent state")
	}
}
