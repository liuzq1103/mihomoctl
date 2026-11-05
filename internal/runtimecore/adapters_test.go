package runtimecore

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

func TestCustomAdaptersMatchV151TemplateEscaping(t *testing.T) {
	values := map[string]string{"http_url": "http://u:p%40ss@127.0.0.1:1234", "binding": "应用😀\"\\%", "profile": "default", "no_proxy": "localhost,::1", "connect_host": "127.0.0.1"}
	for _, kind := range []string{"kubernetes", "pm2", "ci"} {
		text, e := renderTemplate(`value: {binding}`, values, kind)
		if e != nil || text != `value: "\u5e94\u7528\ud83d\ude00\"\\%"` {
			t.Fatal(kind, text, e)
		}
	}
	text, e := renderTemplate(`environment=BINDING={binding}`, values, "supervisor")
	if e != nil || text != `environment=BINDING="应用😀\"\\%%"` {
		t.Fatal(text, e)
	}
	text, e = renderTemplate("HTTP_PROXY={http_url}", values, "docker")
	if e != nil || text != "HTTP_PROXY="+values["http_url"] {
		t.Fatal(text, e)
	}
	values["binding"] = "{profile}"
	text, e = renderTemplate("{binding}", values, "ci")
	if e != nil || text != `"{profile}"` {
		t.Fatal("values evaluated as template", text, e)
	}
}
func TestCustomAdapterSchemaAndMalformedPlaceholders(t *testing.T) {
	a := testApp(t)
	path := filepath.Join(a.Scope.ConfigRoot, "adapters", "custom.json")
	valid := map[string]any{"format": 1, "kind": "ci", "template": "BINDING: {binding}"}
	if e := platform.WriteYAML(path, valid); e != nil {
		t.Fatal(e)
	}
	if _, e := loadAdapter(a, "custom"); e != nil {
		t.Fatal(e)
	}
	for _, bad := range []map[string]any{{"format": 2, "kind": "ci", "template": "x"}, {"format": 1, "kind": "exec", "template": "x"}, {"format": 1, "kind": "ci", "template": "{unknown}"}, {"format": 1, "kind": "ci", "template": strings.Repeat("x", 65537)}, {"format": 1, "kind": "ci", "template": "x", "extra": true}, {"format": "1", "kind": "ci", "template": "x"}} {
		if e := platform.WriteYAML(path, bad); e != nil {
			t.Fatal(e)
		}
		_, e := loadAdapter(a, "custom")
		requireCode(t, e, "adapter-invalid")
	}
	for _, text := range []string{"{binding", "{binding!}", `"{binding}"`, "'{binding}'", "{not_allowed}", "{http_url:bad}"} {
		_, e := renderTemplate(text, map[string]string{"binding": "a", "http_url": "b"}, "ci")
		requireCode(t, e, "adapter-invalid")
	}
	_, e := renderTemplate("{socks_url}", nil, "docker")
	requireCode(t, e, "adapter-incomplete")
	_, e = renderTemplate("{binding}", map[string]string{"binding": "line\nbreak"}, "docker")
	requireCode(t, e, "adapter-invalid")
	_, e = loadAdapter(a, "../outside")
	requireCode(t, e, "adapter-invalid")
}
func TestCustomAdapterEndToEndExportAndNamespaceRehost(t *testing.T) {
	a, m := fixture(t)
	m.Bindings = map[string]binding{"client": {Profile: "default", Adapter: "container", ConnectHost: "[2001:db8::1]"}}
	if e := platform.WriteYAML(a.Scope.ManagerPath(), m); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(a.Scope.ConfigRoot, "adapters", "container.json")
	custom := map[string]any{"format": 1, "kind": "docker", "template": "PROXY={http_url}\nPROFILE={profile}\nHOST={connect_host}\n"}
	if e := platform.WriteJSON(path, custom); e != nil {
		t.Fatal(e)
	}
	doc, e := Run(context.Background(), a, platform.Request{Command: []string{"integration", "export"}, Args: []string{"client"}, Options: map[string][]string{"reveal": {}}})
	if e != nil {
		t.Fatal(e)
	}
	files := doc.Data["artifacts"].(map[string]string)
	text := files["custom.docker"]
	if !strings.Contains(text, "@[2001:db8::1]:18789") || !strings.Contains(text, "PROFILE=default") {
		t.Fatal(text)
	}
	m.Bindings["client"] = binding{Profile: "default", Adapter: "container"}
	if e = platform.WriteYAML(a.Scope.ManagerPath(), m); e != nil {
		t.Fatal(e)
	}
	_, e = Run(context.Background(), a, platform.Request{Command: []string{"integration", "export"}, Args: []string{"client"}, Options: map[string][]string{"reveal": {}}})
	requireCode(t, e, "export-requires-connect-host")
	if e = os.Remove(path); e != nil {
		t.Fatal(e)
	}
	_, e = loadAdapter(a, "container")
	requireCode(t, e, "adapter-unknown")
}
func TestCustomTemplateJSONIsData(t *testing.T) {
	text, e := renderTemplate(`{"value": {binding}}`, map[string]string{"binding": `"};require('fs').writeFileSync('/tmp/pwn','x');//`}, "pm2")
	if e != nil {
		t.Fatal(e)
	}
	var decoded map[string]string
	if json.Unmarshal([]byte(text), &decoded) != nil || !strings.Contains(decoded["value"], "require(") {
		t.Fatal(text)
	}
}
func TestIntegrationExportRedactedPreviewAndCombinedRevealOutput(t *testing.T) {
	a, m := fixture(t)
	m.Bindings = map[string]binding{"client": {Profile: "default", Adapter: "custom-ci"}}
	if e := platform.WriteYAML(a.Scope.ManagerPath(), m); e != nil {
		t.Fatal(e)
	}
	if e := platform.WriteJSON(filepath.Join(a.Scope.ConfigRoot, "adapters", "custom-ci.json"), map[string]any{"format": 1, "kind": "ci", "template": "PROXY: {http_url}\nNAME: {binding}\n"}); e != nil {
		t.Fatal(e)
	}
	doc, e := Run(context.Background(), a, platform.Request{Command: []string{"integration", "export"}, Args: []string{"client"}})
	if e != nil {
		t.Fatal(e)
	}
	text := doc.Data["artifacts"].(map[string]string)["custom.ci"]
	if strings.Contains(text, "unit-secret") || !strings.Contains(text, "REDACTED:REDACTED@") {
		t.Fatal("default export not redacted", text)
	}
	if len(doc.Data["written"].([]string)) != 0 || doc.Data["deployed"] != false {
		t.Fatal(doc)
	}
	doc, e = Run(context.Background(), a, platform.Request{Command: []string{"integration", "check"}, Args: []string{"client"}})
	if e != nil || doc.Overall != "FAIL" || doc.Data["live_environment"] != "UNVERIFIED" {
		t.Fatal(doc, e)
	}
	out := filepath.Join(a.Scope.ConfigRoot, "exports")
	r := platform.Request{Command: []string{"integration", "export"}, Args: []string{"client"}, Options: map[string][]string{"reveal": {}, "output-dir": {out}}}
	if mutating(r) && a.Scope.RequireMutation() != nil {
		return
	}
	doc, e = Run(context.Background(), a, r)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := platform.ReadPrivate(filepath.Join(out, "custom.ci"))
	if e != nil || !strings.Contains(string(raw), "unit-secret") {
		t.Fatal("private output redacted", e)
	}
	if !strings.Contains(doc.Data["artifacts"].(map[string]string)["custom.ci"], "unit-secret") {
		t.Fatal("explicit reveal not honored")
	}
	delete(r.Options, "reveal")
	doc, e = Run(context.Background(), a, r)
	if e != nil {
		t.Fatal(e)
	}
	raw, e = platform.ReadPrivate(filepath.Join(out, "custom.ci"))
	if e != nil || !strings.Contains(string(raw), "unit-secret") || strings.Contains(doc.Data["artifacts"].(map[string]string)["custom.ci"], "unit-secret") {
		t.Fatal("output/preview confidentiality mismatch", e)
	}
}
