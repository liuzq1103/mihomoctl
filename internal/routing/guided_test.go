package routing

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestGuidedShapeContract(t *testing.T) {
	cases := map[string]struct {
		config string
		want   bool
	}{
		"untouched-fresh": {
			"rules:\n  - MATCH,DIRECT\n", true,
		},
		"fresh-with-inline-nodes": {
			"proxies: []\nrules:\n  - MATCH,DIRECT\n", true,
		},
		"empty-config-not-guided": {
			"proxies: []\n", false,
		},
		"exact-simple-preset": {
			"proxy-groups:\n  - name: Proxy\n    type: select\n    proxies:\n      - A\nrules:\n  - MATCH,Proxy\n", true,
		},
		"preset-with-use": {
			"proxy-groups:\n  - name: Proxy\n    type: select\n    use:\n      - p1\nrules:\n  - MATCH,Proxy\n", true,
		},
		"preset-with-extra-key": {
			"proxy-groups:\n  - name: Proxy\n    type: select\n    interval: 300\n    proxies:\n      - A\nrules:\n  - MATCH,Proxy\n", false,
		},
		"preset-wrong-type": {
			"proxy-groups:\n  - name: Proxy\n    type: url-test\n    proxies:\n      - A\nrules:\n  - MATCH,Proxy\n", false,
		},
		"preset-wrong-name": {
			"proxy-groups:\n  - name: Other\n    type: select\n    proxies:\n      - A\nrules:\n  - MATCH,Proxy\n", false,
		},
		"two-groups": {
			"proxy-groups:\n  - name: Proxy\n    type: select\n    proxies:\n      - A\n  - name: B\n    type: select\n    proxies:\n      - A\nrules:\n  - MATCH,Proxy\n", false,
		},
		"custom-rules": {
			"proxy-groups:\n  - name: Proxy\n    type: select\n    proxies:\n      - A\nrules:\n  - DOMAIN-SUFFIX,example.com,Proxy\n  - MATCH,Proxy\n", false,
		},
		"advanced-groups": {
			"proxy-groups:\n  - name: P\n    type: select\n    proxies:\n      - A\nrules:\n  - MATCH,P\n", false,
		},
	}
	for name, c := range cases {
		_, data, err := readOrderedYAML([]byte(c.config))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := guidedShape(data); got != c.want {
			t.Errorf("%s: guidedShape = %v want %v", name, got, c.want)
		}
	}
}

func TestGuidedPolicyBuildsSimplePreset(t *testing.T) {
	incoming := map[string]any{
		"proxies": []any{
			map[string]any{"name": "a", "type": "ss"},
			map[string]any{"name": "b", "type": "ss"},
		},
		"proxy-providers": map[string]any{
			"zeta":  map[string]any{"type": "http", "url": "https://example.com/sub", "path": "providers/zeta.yaml"},
			"alpha": map[string]any{"type": "http", "url": "https://example.com/sub2", "path": "providers/alpha.yaml"},
		},
	}
	// The subscription document ordered zeta before alpha; the preset's use
	// list must preserve that order, not sort it.
	changes, err := guidedPolicy(incoming, []string{"zeta", "alpha"})
	if err != nil {
		t.Fatal(err)
	}
	groups := anyList(changes["proxy-groups"])
	if len(groups) != 1 {
		t.Fatalf("groups = %v", groups)
	}
	group := groups[0].(map[string]any)
	if group["name"] != "Proxy" || group["type"] != "select" {
		t.Fatalf("group = %v", group)
	}
	mustEqual(t, "proxies", group["proxies"], []any{"a", "b"})
	mustEqual(t, "use", group["use"], []any{"zeta", "alpha"})
	mustEqual(t, "rules", changes["rules"], []any{"MATCH,Proxy"})
	if len(anyMap(changes["rule-providers"])) != 0 {
		t.Fatalf("rule-providers = %v", changes["rule-providers"])
	}
	// Without the document order the fallback is sorted, still deterministic.
	changes, err = guidedPolicy(incoming, nil)
	if err != nil {
		t.Fatal(err)
	}
	mustEqual(t, "use", anyList(changes["proxy-groups"])[0].(map[string]any)["use"], []any{"alpha", "zeta"})
}

func TestGuidedPolicyValidation(t *testing.T) {
	_, err := guidedPolicy(map[string]any{"proxies": []any{}, "proxy-providers": map[string]any{}}, nil)
	mustCode(t, err, "subscription-node-list-invalid")

	// A providers-only subscription is still a valid guided preset.
	incoming := map[string]any{
		"proxy-providers": map[string]any{"p": map[string]any{"type": "http", "url": "https://example.com/s", "path": "providers/p.yaml"}},
	}
	if _, err := guidedPolicy(incoming, nil); err != nil {
		t.Fatal(err)
	}

	reserved := map[string]any{
		"proxies": []any{
			map[string]any{"name": "Proxy", "type": "ss"},
			map[string]any{"name": "ok", "type": "ss"},
		},
	}
	_, err = guidedPolicy(reserved, nil)
	mustCode(t, err, "subscription-reserved-node-name-use-advanced")
	for _, name := range []string{"DIRECT", "REJECT"} {
		reserved := map[string]any{
			"proxies": []any{map[string]any{"name": name, "type": "ss"}},
		}
		_, err = guidedPolicy(reserved, nil)
		mustCode(t, err, "subscription-reserved-node-name-use-advanced")
	}
}

func TestMappingKeyOrder(t *testing.T) {
	document := []byte("top: 1\nproxy-providers:\n  zeta:\n    type: http\n  alpha:\n    type: file\nrules:\n  - MATCH,DIRECT\n")
	order := mappingKeyOrder(document, "proxy-providers")
	if len(order) != 2 || order[0] != "zeta" || order[1] != "alpha" {
		t.Fatalf("order = %v", order)
	}
	if mappingKeyOrder(document, "absent") != nil {
		t.Fatal("absent key returned an order")
	}
	if mappingKeyOrder(document, "top") != nil {
		t.Fatal("non-mapping value returned an order")
	}
	if mappingKeyOrder([]byte("a: [\n"), "a") != nil {
		t.Fatal("invalid document returned an order")
	}
}

func TestExpandSubscriptionPath(t *testing.T) {
	home := expandSubscriptionPath("~/subs.yaml")
	if strings.Contains(home, "~") || !strings.HasSuffix(home, "subs.yaml") || !filepath.IsAbs(home) {
		t.Fatalf("home expansion = %q", home)
	}
	relative := expandSubscriptionPath("subs.yaml")
	if !filepath.IsAbs(relative) {
		t.Fatalf("relative expansion = %q", relative)
	}
}
