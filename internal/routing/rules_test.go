package routing

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

func writeRulesFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(privateTempDir(t), "custom-direct.yaml")
	if err := platform.AtomicWrite(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

const validPayload = "payload:\n  - DOMAIN-SUFFIX,example.com\n  - DOMAIN,api.example.com\n"

func TestParseRuleFilePassesContract(t *testing.T) {
	path := writeRulesFile(t, validPayload)
	row, err := parseRuleFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if row["name"] != "custom-direct.yaml" || row["exists"] != true || row["rules"] != 2 {
		t.Fatalf("row = %v", row)
	}
	if row["status"] != "PASS" || row["mode"] != "600" {
		t.Fatalf("row = %v", row)
	}
	if sha, ok := row["sha256"].(string); !ok || len(sha) != 64 {
		t.Fatalf("sha256 = %v", row["sha256"])
	}
	if stamp, ok := row["modified_utc"].(string); !ok || !strings.HasSuffix(stamp, "+00:00") {
		t.Fatalf("modified_utc = %v", row["modified_utc"])
	}
}

func TestParseRuleFileRejectsUnsupportedYAML(t *testing.T) {
	cases := map[string]string{
		"tab":              "payload:\n  - a\n\t- b\n",
		"flow-list":        "payload:\n  - [1, 2]\n",
		"anchor":           "payload:\n  - &anchor a\n",
		"alias":            "payload:\n  - *alias\n",
		"merge":            "payload:\n  - <<: base\n",
		"bare-list":        "- a\n- b\n",
		"empty-payload":    "payload:\n",
		"two-payloads":     validPayload + "payload:\n  - a\n",
		"inline-extension": "payload: [a]\n",
		"comment-item":     "payload:\n  - # not an item\n  - a\n",
	}
	for name, content := range cases {
		_, err := parseRuleFile(writeRulesFile(t, content))
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		re := err.(*ruleError)
		if name == "empty-payload" {
			if re.code != "rule-file-invalid-payload" {
				t.Errorf("%s: code = %s", name, re.code)
			}
			continue
		}
		if re.code != "rule-file-unsupported-yaml" {
			t.Errorf("%s: code = %s", name, re.code)
		}
	}
}

func TestFileStatusMapsFailures(t *testing.T) {
	row := fileStatus(writeRulesFile(t, validPayload))
	if row["status"] != "PASS" {
		t.Fatalf("valid row = %v", row)
	}
	row = fileStatus(writeRulesFile(t, "payload:\n  - a\n\t- b\n"))
	if row["status"] != "UNVERIFIED" || row["exists"] != true {
		t.Fatalf("unsupported row = %v", row)
	}
	if row["error"] != "rule-file-unsupported-yaml" {
		t.Fatalf("error code = %v", row["error"])
	}
	missing := fileStatus(filepath.Join(privateTempDir(t), "absent.yaml"))
	if missing["status"] != "FAIL" || missing["exists"] != false {
		t.Fatalf("missing row = %v", missing)
	}
	if missing["error"] != "rule-file-missing-or-unreadable" {
		t.Fatalf("missing error = %v", missing["error"])
	}
}

func TestStripCommentHonorsQuotes(t *testing.T) {
	cases := []struct{ line, want string }{
		{"a # comment", "a"},
		{"#leading", ""},
		{"a#b", "a#b"},
		{"a 'x # y' b", "a 'x # y' b"},
		{"say \"quote \\\" # inside\" tail", "say \"quote \\\" # inside\" tail"},
		{"a\t# tabbed", "a"},
	}
	for _, c := range cases {
		got, err := stripComment(c.line)
		if err != nil {
			t.Errorf("%q: error %v", c.line, err)
			continue
		}
		if got != c.want {
			t.Errorf("stripComment(%q) = %q want %q", c.line, got, c.want)
		}
	}
	if _, err := stripComment("a \"unclosed"); err == nil {
		t.Error("unterminated quote accepted")
	} else {
		mustRuleCode(t, err, "config-unsupported-yaml")
	}
}

func TestScalarContract(t *testing.T) {
	cases := []struct{ value, want string }{
		{"plain", "plain"},
		{"  'quoted value'  ", "quoted value"},
		{"\"double\"", "double"},
		{"MATCH,Proxy", "MATCH,Proxy"},
	}
	for _, c := range cases {
		got, err := scalar(c.value)
		if err != nil || got != c.want {
			t.Errorf("scalar(%q) = %q, %v; want %q", c.value, got, err, c.want)
		}
	}
	for _, bad := range []string{"", "{a}", "[b]", "*alias", "a\tb", "&anchor"} {
		if _, err := scalar(bad); err == nil {
			t.Errorf("scalar(%q) accepted", bad)
		} else {
			mustRuleCode(t, err, "config-unsupported-yaml")
		}
	}
}

func TestRuleErrorRCMapping(t *testing.T) {
	if ruleErrorRC(ruleUsage("x-must-be-safe-absolute-path")) != exitUnverify {
		t.Fatal("usage must exit 2")
	}
	if ruleErrorRC(ruleFail("config-unsupported-yaml")) != exitUnverify {
		t.Fatal("unsupported must exit 2")
	}
	if ruleErrorRC(ruleFail("provider-contract-mismatch")) != exitFail {
		t.Fatal("checker failure must exit 1")
	}
}

func TestISOTimestampFormat(t *testing.T) {
	stamp := isoTimestamp(time.Date(2024, 1, 2, 3, 4, 5, 123456000, time.UTC))
	if stamp != "2024-01-02T03:04:05.123456+00:00" {
		t.Fatalf("stamp = %q", stamp)
	}
	stamp = isoTimestamp(time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC))
	if stamp != "2024-01-02T03:04:05+00:00" {
		t.Fatalf("stamp = %q", stamp)
	}
}

func TestSafeAbsolute(t *testing.T) {
	valid := filepath.Join(privateTempDir(t), "x.yaml")
	if got, err := safeAbsolute(valid, "path"); err != nil || got != filepath.Clean(valid) {
		t.Fatalf("safeAbsolute(%q) = %q, %v", valid, got, err)
	}
	if _, err := safeAbsolute(filepath.Join("relative", "x"), "path"); err == nil {
		t.Fatal("relative path accepted")
	} else {
		mustRuleCode(t, err, "path-must-be-safe-absolute-path")
	}
	if _, err := safeAbsolute(valid+"\x1b", "path"); err == nil {
		t.Fatal("control-character path accepted")
	}
}

const validRulesConfig = `port: 0
rule-providers:
  custom-direct:
    type: file
    behavior: classical
    format: yaml
    path: ./rules/custom-direct.yaml
  custom-proxy:
    type: file
    behavior: classical
    format: yaml
    path: ./rules/custom-proxy.yaml
  custom-reject:
    type: file
    behavior: classical
    format: yaml
    path: ./rules/custom-reject.yaml
proxy-groups:
  - name: Proxy
    type: select
    proxies:
      - Node A
rules:
  - RULE-SET,custom-direct,DIRECT
  - RULE-SET,custom-proxy,Proxy
  - RULE-SET,custom-reject,REJECT
  - MATCH,Proxy
`

func writeRulesConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(privateTempDir(t), "config.yaml")
	if err := platform.AtomicWrite(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestParseConfigProviderContract(t *testing.T) {
	missingFallback, err := parseConfig(writeRulesConfig(t, validRulesConfig))
	if err != nil {
		t.Fatal(err)
	}
	if missingFallback {
		t.Fatal("MATCH fallback present but reported missing")
	}

	noMatch := strings.Replace(validRulesConfig, "  - MATCH,Proxy\n", "", 1)
	missingFallback, err = parseConfig(writeRulesConfig(t, noMatch))
	if err != nil {
		t.Fatal(err)
	}
	if !missingFallback {
		t.Fatal("missing MATCH fallback not reported")
	}
}

func TestParseConfigContractViolations(t *testing.T) {
	cases := map[string]func(string) string{
		"provider-contract-mismatch": func(s string) string {
			return strings.Replace(s, "path: ./rules/custom-direct.yaml", "path: ./rules/other.yaml", 1)
		},
		"required-provider-missing": func(s string) string {
			return strings.Replace(s, "  custom-reject:\n    type: file\n    behavior: classical\n    format: yaml\n    path: ./rules/custom-reject.yaml\n", "", 1)
		},
		"provider-target-mismatch": func(s string) string {
			return strings.Replace(s, "  - RULE-SET,custom-proxy,Proxy\n", "  - RULE-SET,custom-proxy,DIRECT\n", 1)
		},
		"duplicate-provider-rule": func(s string) string {
			return strings.Replace(s, "  - MATCH,Proxy\n", "  - RULE-SET,custom-direct,DIRECT\n  - MATCH,Proxy\n", 1)
		},
		"custom-rule-after-match": func(s string) string {
			// Relocate custom-reject after MATCH: first occurrence of that
			// provider, but still behind the terminal fallback.
			without := strings.Replace(s, "  - RULE-SET,custom-reject,REJECT\n", "", 1)
			return strings.Replace(without, "  - MATCH,Proxy\n", "  - MATCH,Proxy\n  - RULE-SET,custom-reject,REJECT\n", 1)
		},
		"required-proxy-group-missing": func(s string) string {
			return strings.Replace(s, "  - name: Proxy\n    type: select\n    proxies:\n      - Node A\n", "  - name: Other\n    type: select\n    proxies:\n      - Node A\n", 1)
		},
		"duplicate-rule-provider": func(s string) string {
			return strings.Replace(s, "  custom-proxy:\n", "  custom-direct:\n", 1)
		},
		"provider-rule-reference-missing": func(s string) string {
			return strings.Replace(s, "  - RULE-SET,custom-proxy,Proxy\n", "", 1)
		},
		"unknown-rule-target": func(s string) string {
			return strings.Replace(s, "  - RULE-SET,custom-proxy,Proxy\n", "  - RULE-SET,custom-proxy,Missing\n", 1)
		},
		"config-unsupported-yaml": func(s string) string {
			return strings.Replace(s, "rules:\n", "rules: inline\n", 1)
		},
	}
	for code, mutate := range cases {
		_, err := parseConfig(writeRulesConfig(t, mutate(validRulesConfig)))
		if err == nil {
			t.Errorf("%s: accepted", code)
			continue
		}
		mustRuleCode(t, err, code)
	}
}

func TestInspectOwnedRejectsWrongType(t *testing.T) {
	dir := privateTempDir(t)
	if _, err := inspectOwned(dir, 0600, "rule-file", false); err == nil {
		t.Fatal("directory accepted as file")
	} else {
		mustRuleCode(t, err, "rule-file-wrong-type")
	}
	if _, err := inspectOwned(filepath.Join(dir, "absent"), 0600, "rule-file", false); err == nil {
		t.Fatal("absent path accepted")
	} else {
		mustRuleCode(t, err, "rule-file-missing-or-unreadable")
	}
	if runtime.GOOS == "linux" {
		target := writeRulesFile(t, validPayload)
		link := filepath.Join(privateTempDir(t), "link.yaml")
		if err := os.Symlink(target, link); err != nil {
			t.Skip("symlink creation unavailable")
		}
		if _, err := inspectOwned(link, 0600, "rule-file", false); err == nil {
			t.Fatal("symlink accepted")
		} else {
			mustRuleCode(t, err, "rule-file-symlink-not-supported")
		}
	}
}
