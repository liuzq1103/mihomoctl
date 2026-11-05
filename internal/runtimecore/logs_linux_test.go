//go:build linux

package runtimecore

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

func TestJournalChildLogHelper(t *testing.T) {
	if os.Getenv("RUNTIMECORE_LOG_CHILD") != "1" {
		return
	}
	raw, e := base64.StdEncoding.DecodeString(os.Getenv("RUNTIMECORE_LOG_FIXTURE"))
	if e != nil {
		os.Exit(119)
	}
	text := string(raw)
	for i := 0; i < len(text); i += 7 {
		end := i + 7
		if end > len(text) {
			end = len(text)
		}
		os.Stdout.WriteString(text[i:end])
	}
	os.Stderr.WriteString("unit-secret query-password\n")
	os.Exit(0)
}
func TestSystemdJournalTransportSnapshotAndFollowRedact(t *testing.T) {
	_, m, raw := secretLogFixture(t)
	cfg, e := platform.ReadYAML(m.Core.Config, true)
	if e != nil {
		t.Fatal(e)
	}
	redactor := makeLogRedactor(cfg)
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	for _, follow := range []bool{false, true} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		cmd := exec.CommandContext(ctx, exe, "-test.run=^TestJournalChildLogHelper$")
		cmd.Env = append(os.Environ(), "RUNTIMECORE_LOG_CHILD=1", "RUNTIMECORE_LOG_FIXTURE="+base64.StdEncoding.EncodeToString([]byte(raw)))
		var out bytes.Buffer
		r := platform.Request{Command: []string{"logs"}, Output: &out, Stderr: &out}
		if follow {
			r.Options = map[string][]string{"follow": {}}
		}
		result, e := readJournalCommand(ctx, cmd, r, redactor)
		cancel()
		if e != nil {
			t.Fatal(e)
		}
		if follow {
			assertRedactedLog(t, out.String())
			if len(result) != 0 {
				t.Fatal("follow retained raw journal snapshot")
			}
		} else {
			entries := redactor.entries(result)
			if len(entries) != 1 {
				t.Fatal(entries)
			}
			assertRedactedLog(t, entries[0])
			if out.Len() != 0 {
				t.Fatal("snapshot transport leaked diagnostic output")
			}
		}
	}
}
func TestLocalJournalReadersRefuseFIFOWithoutBlocking(t *testing.T) {
	a := testApp(t)
	if e := platform.PrivateDir(a.Scope.StateRoot); e != nil {
		t.Fatal(e)
	}
	fifo := filepath.Join(a.Scope.StateRoot, "fifo")
	if e := syscall.Mkfifo(fifo, 0600); e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"bounded-journal", "log-window"} {
		done := make(chan error, 1)
		go func() {
			var e error
			if kind == "bounded-journal" {
				_, e = readPrivateBounded(fifo, fileJournalLimit)
			} else {
				_, _, e = readLogWindow(fifo)
			}
			done <- e
		}()
		select {
		case e := <-done:
			if e == nil {
				t.Fatal("FIFO accepted", kind)
			}
		case <-time.After(time.Second):
			t.Fatal("local reader blocked opening a FIFO", kind)
		}
	}
	if os.Geteuid() == 0 {
		done := make(chan error, 1)
		go func() { _, e := readSystemConfig(fifo); done <- e }()
		select {
		case e := <-done:
			requireCode(t, e, "core-config-untrusted")
		case <-time.After(time.Second):
			t.Fatal("system config reader blocked on FIFO")
		}
	}
	real := filepath.Join(a.Scope.StateRoot, "regular")
	if e := platform.AtomicWrite(real, []byte("safe"), 0600); e != nil {
		t.Fatal(e)
	}
	link := filepath.Join(a.Scope.StateRoot, "link")
	if e := os.Symlink(real, link); e != nil {
		t.Fatal(e)
	}
	_, e := readPrivateBounded(link, 100)
	requireCode(t, e, "symlink-refused")
}
func TestLogRedactorLengthAndControlCharacters(t *testing.T) {
	r := makeLogRedactor(map[string]any{"secret": "controller-secret"})
	text := r.line("controller-secret\x1b\x00\t\x7f" + strings.Repeat("中", 5000))
	if len([]rune(text)) != 4096 || strings.Contains(text, "controller-secret") {
		t.Fatal("redaction truncation contract failed")
	}
}
