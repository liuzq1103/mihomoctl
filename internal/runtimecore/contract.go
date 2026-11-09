package runtimecore

import (
	"errors"
	"fmt"
	"os"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

func missingCoreError(path string, err error) error {
	reason := "unreadable"
	if os.IsNotExist(err) {
		reason = "No such file or directory"
	} else if os.IsPermission(err) {
		reason = "Permission denied"
	}
	return platform.UsageDetail("core-binary-invalid", fmt.Sprintf("missing binary: %s (%s)", path, reason), "")
}

func renderError(err error) string {
	var e *platform.Error
	if !errors.As(err, &e) {
		return platform.SafeError(err)
	}
	text := e.Code
	if e.Detail != "" {
		text += ": " + e.Detail
	}
	if e.Remediation != "" {
		text += " (" + e.Remediation + ")"
	}
	return text
}

func verdict(ok bool) string {
	if ok {
		return "PASS"
	}
	return "FAIL"
}

func addCheckEvidence(doc *platform.Envelope, name, status, evidence, detail string) {
	doc.Checks = append(doc.Checks, platform.Check{Name: name, Status: status, Evidence: evidence, Detail: detail})
	if status == "FAIL" || status == "UNVERIFIED" && doc.Overall == "PASS" {
		doc.Overall = status
	}
}
