//go:build linux

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestDifferentialAgainstArchivedBaseline runs the bounded differential
// harness from scripts/parity against the archived Python v1.5.1 baseline.
//
// The harness needs the exact git-archive tar of the baseline commit and a
// Python interpreter with PyYAML. Both are verification-only inputs: the Go
// product has no Python dependency. Without them the test is skipped, so the
// normal unit suite stays hermetic.
//
// Environment:
//
//	MIHOMOCTL_GO_PARITY_ARCHIVE   path to the git-archive tar of the baseline commit
//	MIHOMOCTL_GO_PARITY_CORE     optional reviewed local Mihomo executable
//	MIHOMOCTL_GO_PARITY_GO       optional existing Go toolchain (default: PATH)
//	MIHOMOCTL_GO_PARITY_GO_CACHE optional existing Go build cache
//	MIHOMOCTL_GO_PARITY_MODCACHE optional existing Go module cache
func TestDifferentialAgainstArchivedBaseline(t *testing.T) {
	archive := os.Getenv("MIHOMOCTL_GO_PARITY_ARCHIVE")
	if archive == "" {
		t.Skip("set MIHOMOCTL_GO_PARITY_ARCHIVE to the baseline git-archive tar to run the differential harness")
	}
	if _, err := os.Stat(archive); err != nil {
		t.Fatalf("baseline archive is unusable: %v", err)
	}
	harness, err := filepath.Abs(filepath.Join("scripts", "parity", "run.py"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(harness); err != nil {
		t.Fatalf("differential harness is missing: %v", err)
	}
	python := os.Getenv("MIHOMOCTL_GO_PARITY_PYTHON")
	if python == "" {
		python = "python3"
	}
	arguments := []string{"-B", harness, "--baseline-archive", archive,
		"--work-dir", filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(harness))), ".work", "parity")}
	if value := os.Getenv("MIHOMOCTL_GO_PARITY_GO"); value != "" {
		arguments = append(arguments, "--go", value)
	}
	if value := os.Getenv("MIHOMOCTL_GO_PARITY_GO_CACHE"); value != "" {
		arguments = append(arguments, "--go-cache", value)
	}
	if value := os.Getenv("MIHOMOCTL_GO_PARITY_MODCACHE"); value != "" {
		arguments = append(arguments, "--module-cache", value)
	}
	if value := os.Getenv("MIHOMOCTL_GO_PARITY_CORE"); value != "" {
		arguments = append(arguments, "--core", value)
	}
	command := exec.Command(python, arguments...)
	command.Env = os.Environ()
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("differential harness failed: %v\n%s", err, output)
	}
	t.Logf("differential harness output:\n%s", output)
}
