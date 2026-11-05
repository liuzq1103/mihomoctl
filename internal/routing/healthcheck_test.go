package routing

import "testing"

func TestPublicHTTPSURLContract(t *testing.T) {
	valid := []string{
		"https://example.com/",
		"https://api.example.com/v1",
		"https://example.com:8443/path",
		"https://sub.domain.example.com",
		"https://203.0.113.10/",
	}
	for _, url := range valid {
		if !publicHTTPSURL(url) {
			t.Errorf("publicHTTPSURL(%q) = false", url)
		}
	}
	invalid := map[string]string{
		"empty":             "",
		"not-a-url":         "example.com",
		"plain-http":        "http://example.com/",
		"userinfo":          "https://user:pass@example.com/",
		"at-sign":           "https://token@example.com/",
		"query":             "https://example.com/?next=/",
		"fragment":          "https://example.com/#top",
		"credential-key":    "https://example.com/?password=x",
		"localhost":         "https://localhost/",
		"dot-local":         "https://printer.local/",
		"no-dot":            "https://intranet/",
		"loopback-ip":       "https://127.0.0.1/",
		"private-ip":        "https://192.168.1.10/",
		"unspecified-ip":    "https://0.0.0.0/",
		"space":             "https://example.com/a b",
		"control-character": "https://example.com/\x01",
	}
	for name, url := range invalid {
		if publicHTTPSURL(url) {
			t.Errorf("publicHTTPSURL(%q) [%s] = true", url, name)
		}
	}
}

func TestValidStatusRangeContract(t *testing.T) {
	for _, value := range []string{"200", "200-299", "200-299/301/304", "301"} {
		if !validStatusRange(value) {
			t.Errorf("validStatusRange(%q) = false", value)
		}
	}
	for _, value := range []string{"", "600", "99", "200-", "-200", "301-200", "200/301-200", "abc", "200 201"} {
		if validStatusRange(value) {
			t.Errorf("validStatusRange(%q) = true", value)
		}
	}
}

func TestSettingsDTRedactsImportedURLs(t *testing.T) {
	dto := settingsDTO(map[string]any{
		"url":             "https://token@example.com/",
		"expected-status": "200-299",
		"interval":        300,
		"enable":          true,
		"lazy":            "yes",
	})
	if url, ok := dto["url"].(string); !ok || url != "[redacted: non-public-or-credential-url]" {
		t.Fatalf("url = %v", dto["url"])
	}
	if dto["interval"] != 300 {
		t.Fatalf("interval = %v", dto["interval"])
	}
	if dto["expected-status"] != "200-299" {
		t.Fatalf("expected-status = %v", dto["expected-status"])
	}
	if dto["enable"] != true {
		t.Fatalf("enable = %v", dto["enable"])
	}
	if dto["lazy"] != "[invalid]" {
		t.Fatalf("lazy = %v", dto["lazy"])
	}

	// A public URL is preserved verbatim.
	dto = settingsDTO(map[string]any{"url": "https://probe.example.com/health"})
	if dto["url"] != "https://probe.example.com/health" {
		t.Fatalf("url = %v", dto["url"])
	}

	dto = settingsDTO(map[string]any{"expected-status": "999"})
	if dto["expected-status"] != "[invalid]" {
		t.Fatalf("expected-status = %v", dto["expected-status"])
	}
}
