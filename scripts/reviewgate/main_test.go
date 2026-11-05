package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/liuzq1103/mihomoctl/internal/delivery"
	"github.com/liuzq1103/mihomoctl/internal/platform"
)

func TestExactCandidateAndThreeDistinctCompletedReviews(t *testing.T) {
	base := t.TempDir()
	candidate := strings.Repeat("a", 40)
	report := []byte("review fixture: deterministic test input, not an actual source review")
	if e := os.WriteFile(filepath.Join(base, "review.txt"), report, 0600); e != nil {
		t.Fatal(e)
	}
	ev := evidence{Format: 1, Project: delivery.Project, Version: delivery.Version, CandidateSHA: candidate}
	for _, model := range []string{"gpt-6.1-sol", "zcode/GLM-5.3[1m]", "minimax-cn/MiniMax-M3.1-Flash[1m]"} {
		ev.Reviews = append(ev.Reviews, review{model, candidate, "PASS", time.Now().UTC().Format(time.RFC3339), "review.txt", platform.Hash(report)})
	}
	b, _ := json.Marshal(ev)
	if e := validate(b, candidate, base); e != nil {
		t.Fatal(e)
	}
	for _, test := range []string{"wrong-sha", "duplicate-model", "incomplete", "report-tamper", "three-gpt", "missing-family", "arbitrary-model"} {
		t.Run(test, func(t *testing.T) {
			var changed evidence
			json.Unmarshal(b, &changed)
			switch test {
			case "wrong-sha":
				changed.CandidateSHA = strings.Repeat("b", 40)
			case "duplicate-model":
				changed.Reviews[2].Model = changed.Reviews[0].Model
			case "incomplete":
				changed.Reviews[1].Status = "PENDING"
			case "report-tamper":
				changed.Reviews[0].ReportSHA256 = strings.Repeat("0", 64)
			case "three-gpt":
				for i := range changed.Reviews {
					changed.Reviews[i].Model = "gpt-6.1-sol"
				}
			case "missing-family":
				changed.Reviews = changed.Reviews[:2]
			case "arbitrary-model":
				changed.Reviews[2].Model = "arbitrary-independent-model"
			}
			bad, _ := json.Marshal(changed)
			if e := validate(bad, candidate, base); e == nil {
				t.Fatal("invalid evidence accepted")
			}
		})
	}
}
