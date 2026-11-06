package routing

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func validProviderPolicy() map[string]any {
	return map[string]any{
		"proxies": []any{
			map[string]any{"name": "a", "type": "ss"},
		},
		"proxy-groups": []any{
			map[string]any{"name": "g", "type": "select", "proxies": []any{"a"}},
		},
		"rules": []any{"MATCH,g"},
	}
}

func TestProviderPolicyDefaultsAndValidation(t *testing.T) {
	changes, err := providerPolicy(validProviderPolicy())
	if err != nil {
		t.Fatal(err)
	}
	// Absent dict/list fields default to empty, completing the five-field set.
	if _, ok := changes["proxies"].([]any); !ok {
		t.Fatalf("proxies = %v", changes["proxies"])
	}
	if v, ok := changes["proxy-providers"].(map[string]any); !ok || len(v) != 0 {
		t.Fatalf("proxy-providers default = %v", changes["proxy-providers"])
	}
	if v, ok := changes["rule-providers"].(map[string]any); !ok || len(v) != 0 {
		t.Fatalf("rule-providers default = %v", changes["rule-providers"])
	}

	_, err = providerPolicy(map[string]any{})
	mustCode(t, err, "subscription-routing-policy-missing")

	_, err = providerPolicy(map[string]any{"proxies": map[string]any{}})
	mustCode(t, err, "subscription-policy-shape-invalid")

	_, err = providerPolicy(map[string]any{"proxies": []any{map[string]any{"name": "a"}}})
	mustCode(t, err, "subscription-policy-entry-invalid")

	_, err = providerPolicy(map[string]any{"proxies": []any{map[string]any{"name": "DIRECT", "type": "ss"}}})
	mustCode(t, err, "subscription-policy-name-invalid")
}

func TestProviderPolicyReferenceChecks(t *testing.T) {
	policy := validProviderPolicy()
	policy["proxy-groups"] = []any{map[string]any{"name": "g", "type": "select", "proxies": []any{"ghost"}}}
	_, err := providerPolicy(policy)
	mustCode(t, err, "subscription-group-reference-missing")

	policy = validProviderPolicy()
	policy["proxy-groups"] = []any{map[string]any{"name": "g", "type": "select", "use": []any{"missing-provider"}}}
	_, err = providerPolicy(policy)
	mustCode(t, err, "subscription-provider-reference-missing")

	policy = validProviderPolicy()
	policy["rules"] = []any{"MATCH,nowhere"}
	_, err = providerPolicy(policy)
	mustCode(t, err, "subscription-rule-target-missing")

	policy = validProviderPolicy()
	policy["rules"] = []any{"RULE-SET,custom-direct,DIRECT"}
	_, err = providerPolicy(policy)
	mustCode(t, err, "subscription-rule-provider-missing")

	policy = validProviderPolicy()
	policy["rules"] = []any{"RULE-SET,custom-direct,DIRECT"}
	policy["rule-providers"] = map[string]any{"custom-direct": map[string]any{"type": "file", "behavior": "classical", "format": "yaml", "path": "rules/custom-direct.yaml"}}
	if _, err := providerPolicy(policy); err != nil {
		t.Fatal(err)
	}
}

func TestProviderPolicyProviderPathSafety(t *testing.T) {
	for _, path := range []string{"../escape.yaml", "/abs.yaml", `back\slash.yaml`, "col:on.yaml"} {
		policy := validProviderPolicy()
		policy["rule-providers"] = map[string]any{"rp": map[string]any{"type": "http", "path": path}}
		_, err := providerPolicy(policy)
		mustCode(t, err, "subscription-provider-path-unsafe")
	}
	policy := validProviderPolicy()
	policy["rule-providers"] = map[string]any{"rp": map[string]any{"type": "file", "behavior": "classical", "format": "yaml"}}
	_, err := providerPolicy(policy)
	mustCode(t, err, "subscription-provider-path-required")
}

func TestPolicyOverlayFieldsAndMergedValidation(t *testing.T) {
	current := map[string]any{
		"proxies":      []any{map[string]any{"name": "a", "type": "ss"}},
		"proxy-groups": []any{map[string]any{"name": "g", "type": "select", "proxies": []any{"a"}}},
	}
	overlay, err := policyOverlay(map[string]any{"rules": []any{"MATCH,g"}}, current)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := overlay["rules"]; !ok {
		t.Fatalf("overlay = %v", overlay)
	}

	_, err = policyOverlay(map[string]any{}, current)
	mustCode(t, err, "subscription-policy-overlay-fields-only")

	_, err = policyOverlay(map[string]any{"proxies": []any{}}, current)
	mustCode(t, err, "subscription-policy-overlay-fields-only")

	// The merged result must validate: a group may not reference a node that
	// only the overlay was allowed to introduce through a forbidden field.
	_, err = policyOverlay(map[string]any{"proxy-groups": []any{
		map[string]any{"name": "g2", "type": "select", "proxies": []any{"ghost"}},
	}}, current)
	mustCode(t, err, "subscription-group-reference-missing")
}

func TestOutsideBoundaryEqualDistinguishesAbsentAndNull(t *testing.T) {
	allowed := map[string]bool{"proxies": true}
	if !outsideBoundaryEqual(map[string]any{"a": 1, "proxies": 1}, map[string]any{"a": 1, "proxies": 9}, allowed) {
		t.Fatal("change inside the boundary must be allowed")
	}
	if outsideBoundaryEqual(map[string]any{"a": 1}, map[string]any{"a": 2}, allowed) {
		t.Fatal("value drift outside the boundary accepted")
	}
	if outsideBoundaryEqual(map[string]any{"a": 1}, map[string]any{"a": 1, "b": nil}, allowed) {
		t.Fatal("added null key outside the boundary accepted")
	}
	if outsideBoundaryEqual(map[string]any{"a": nil}, map[string]any{}, allowed) {
		t.Fatal("removed null key outside the boundary accepted")
	}
	if outsideBoundaryEqual(map[string]any{"a": 1}, map[string]any{}, allowed) {
		t.Fatal("removed key outside the boundary accepted")
	}
}

func TestContainsAnyValue(t *testing.T) {
	values := []any{"x", "y"}
	if !containsAnyValue(values, "y") || containsAnyValue(values, "z") {
		t.Fatal("membership check failed")
	}
	if containsAnyValue(nil, "y") {
		t.Fatal("nil list reported a member")
	}
}

func TestReadOrderedYAMLPreservesTopLevelOrder(t *testing.T) {
	order, data, err := readOrderedYAML([]byte("b: 1\na: 2\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(order) != 2 || order[0] != "b" || order[1] != "a" {
		t.Fatalf("order = %v", order)
	}
	if len(data) != 2 || data["a"] != 2 {
		t.Fatalf("data = %v", data)
	}
	if _, _, err := readOrderedYAML([]byte("a:\n\t- 1\n")); err == nil {
		t.Fatal("tab-indented document accepted")
	}
}

func TestParseSubscriptionURLContract(t *testing.T) {
	parts, err := parseSubscriptionURL("https://Example.COM:8443/path")
	if err != nil || parts.scheme != "https" || parts.hostname != "example.com" || parts.hasUserinfo || parts.fragment {
		t.Fatalf("parts = %+v err = %v", parts, err)
	}
	parts, _ = parseSubscriptionURL("https://user:pass@example.com/")
	if !parts.hasUserinfo {
		t.Fatal("userinfo not detected")
	}
	parts, _ = parseSubscriptionURL("https://example.com/x#frag")
	if !parts.fragment {
		t.Fatal("fragment not detected")
	}
	parts, _ = parseSubscriptionURL("http://example.com/")
	if parts.scheme != "http" {
		t.Fatal("scheme not lowercased")
	}
	parts, _ = parseSubscriptionURL("https://[2001:db8::1]/x")
	if parts.hostname != "2001:db8::1" {
		t.Fatalf("ipv6 hostname = %q", parts.hostname)
	}
	if _, err := parseSubscriptionURL("example.com/no-scheme"); err == nil {
		t.Fatal("schemeless URL accepted")
	}
}

func TestDownloadRejectsNonHTTPSAndCredentialURLs(t *testing.T) {
	for _, url := range []string{
		"http://example.com/sub",
		"https://user:pass@example.com/",
		"https://example.com/#fragment",
		"https://example.com/ with-space",
		"https://example.com/\x01",
	} {
		_, err := download(context.Background(), url)
		mustCode(t, err, "subscription-requires-https-url-without-userinfo")
	}
}

// TestDownloadBodyStallIsBounded proves the whole-exchange deadline: a server
// that flushes headers and then never sends a body byte must fail within the
// download budget instead of pinning the reader inside a blocking read.
func TestDownloadBodyStallIsBounded(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/yaml")
		w.WriteHeader(http.StatusOK)
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		<-release // headers delivered, body never arrives
	}))
	defer server.Close()
	defer close(release)

	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	savedDeadline, savedTLS := downloadDeadline, downloadTLSConfig
	downloadDeadline, downloadTLSConfig = 500*time.Millisecond, &tls.Config{RootCAs: pool}
	t.Cleanup(func() { downloadDeadline, downloadTLSConfig = savedDeadline, savedTLS })

	begin := time.Now()
	_, err := download(context.Background(), server.URL)
	elapsed := time.Since(begin)
	if err == nil {
		t.Fatal("stalled body download unexpectedly succeeded")
	}
	mustCode(t, err, "subscription-download-timeout")
	if elapsed > 5*time.Second {
		t.Fatalf("stalled body download took %s; the hard deadline did not bound it", elapsed)
	}
	if elapsed < 400*time.Millisecond {
		t.Fatalf("stalled body download failed after %s; the exchange was not actually attempted", elapsed)
	}
}
