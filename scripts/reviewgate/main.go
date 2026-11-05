// reviewgate checks evidence; it never invents or performs a model review.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/liuzq1103/mihomoctl/internal/delivery"
	"github.com/liuzq1103/mihomoctl/internal/platform"
)

type review struct {
	Model        string `json:"model"`
	CandidateSHA string `json:"candidate_sha"`
	Status       string `json:"status"`
	CompletedAt  string `json:"completed_at"`
	Report       string `json:"report"`
	ReportSHA256 string `json:"report_sha256"`
}
type evidence struct {
	Format       int      `json:"format"`
	Project      string   `json:"project"`
	Version      string   `json:"version"`
	CandidateSHA string   `json:"candidate_sha"`
	Reviews      []review `json:"reviews"`
}

var commitPattern = regexp.MustCompile(`^[a-f0-9]{40}$`)
var digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

// Exact approved review profiles bind the three independent model families.
// Arbitrary labels and multiple names from one family cannot satisfy the gate.
func modelFamily(model string) string {
	switch model {
	case "gpt-6.1-sol":
		return "GPT"
	case "zcode/GLM-5.3[1m]":
		return "GLM"
	case "minimax-cn/MiniMax-M3.1-Flash[1m]":
		return "MiniMax"
	}
	return ""
}

func validate(b []byte, candidate, base string) error {
	if !commitPattern.MatchString(candidate) {
		return fmt.Errorf("candidate must be a full commit SHA")
	}
	var ev evidence
	if e := delivery.StrictJSON(b, &ev); e != nil {
		return e
	}
	if ev.Format != 1 || ev.Project != delivery.Project || ev.Version != delivery.Version || ev.CandidateSHA != candidate || len(ev.Reviews) != 3 {
		return fmt.Errorf("three completed reviews for this exact candidate are required")
	}
	seen := map[string]bool{}
	for _, r := range ev.Reviews {
		family := modelFamily(r.Model)
		if family == "" || seen[family] || r.Status != "PASS" || r.CandidateSHA != candidate || !digestPattern.MatchString(r.ReportSHA256) {
			return fmt.Errorf("model review identity/status/digest mismatch")
		}
		seen[family] = true
		completed, e := time.Parse(time.RFC3339, r.CompletedAt)
		if e != nil || completed.After(time.Now().Add(5*time.Minute)) {
			return fmt.Errorf("model review completion time invalid")
		}
		// Local reports allow checking bytes rather than trusting a mutable URL.
		u, e := url.Parse(r.Report)
		if e != nil || u.Scheme != "" || r.Report == "" || path.Clean(r.Report) != r.Report || strings.HasPrefix(r.Report, "/") || strings.HasPrefix(r.Report, "../") || strings.ContainsAny(r.Report, "\\:\x00") {
			return fmt.Errorf("review report must be a checked-in relative artifact")
		}
		p := filepath.Join(base, filepath.FromSlash(r.Report))
		if e = platform.CheckPath(p); e != nil {
			return e
		}
		st, e := os.Stat(p)
		if e != nil || !st.Mode().IsRegular() || st.Size() > 2<<20 {
			return fmt.Errorf("review report unavailable")
		}
		report, e := os.ReadFile(p)
		if e != nil {
			return e
		}
		if platform.Hash(report) != r.ReportSHA256 {
			return fmt.Errorf("review report digest mismatch")
		}
	}
	return nil
}
func main() {
	file := flag.String("evidence", ".github/release-evidence.json", "checked-in review evidence")
	candidate := flag.String("candidate", "", "reviewed full candidate commit SHA")
	flag.Parse()
	b, e := os.ReadFile(*file)
	if e == nil {
		e = validate(b, *candidate, ".")
	}
	if e == nil {
		var ev evidence
		_ = json.Unmarshal(b, &ev)
		for _, r := range ev.Reviews {
			if !strings.HasPrefix(r.Report, ".github/reviews/") {
				e = fmt.Errorf("checked-in reports must be under .github/reviews/")
				break
			}
			if ge := exec.Command("git", "ls-files", "--error-unmatch", "--", r.Report).Run(); ge != nil {
				e = fmt.Errorf("review report is not checked in: %s", r.Report)
				break
			}
		}
	}
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	fmt.Println("three model source-review records verified for " + *candidate)
}
