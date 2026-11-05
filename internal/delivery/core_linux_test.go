//go:build linux

package delivery

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

func TestCoreVersionProbeAndBounds(t *testing.T) {
	for _, tc := range []struct {
		name, script string
		valid        bool
	}{
		{"valid", "#!/bin/sh\necho 'Mihomo Meta v1.19.33 linux amd64'\n", true},
		{"wrong-version", "#!/bin/sh\necho 'Mihomo Meta v1.19.32 linux amd64'\n", false},
		{"prefix-spoof", "#!/bin/sh\necho 'foreign Mihomo Meta v1.19.33'\n", false},
		{"failed-exit", "#!/bin/sh\necho 'Mihomo Meta v1.19.33 linux amd64'\nexit 1\n", false},
		{"output-limit", "#!/bin/sh\ni=0; while [ \"$i\" -lt 9000 ]; do printf x; i=$((i+1)); done\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(privateTemp(t), "probe")
			if e := os.WriteFile(p, []byte(tc.script), 0700); e != nil {
				t.Fatal(e)
			}
			e := verifyCoreVersion(context.Background(), p, "v1.19.33", os.Geteuid() == 0)
			if (e == nil) != tc.valid {
				t.Fatal(e)
			}
		})
	}
}

func TestLocalCoreInputRefusesFIFOWithoutBlocking(t *testing.T) {
	p := filepath.Join(privateTemp(t), "fifo")
	if e := syscall.Mkfifo(p, 0600); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { _, _, e := fileDigest(p); done <- e }()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("FIFO accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("local core input blocked on FIFO")
	}
}

func TestConfiguredVersionProbeIsBestEffortAndReadOnly(t *testing.T) {
	a := testApp(t)
	p := filepath.Join(privateTemp(t), "mihomo")
	line := "Mihomo Meta v1.19.33 linux amd64 test-build"
	if e := os.WriteFile(p, []byte("#!/bin/sh\necho '"+line+"'\n"), 0700); e != nil {
		t.Fatal(e)
	}
	if e := platform.WriteYAML(a.Scope.ManagerPath(), map[string]any{"version": 1, "core": map[string]any{"binary": p}}); e != nil {
		t.Fatal(e)
	}
	before, e := os.ReadFile(a.Scope.ManagerPath())
	if e != nil {
		t.Fatal(e)
	}
	doc, e := Run(context.Background(), a, platform.Request{Command: []string{"version"}})
	if e != nil || doc.Data["core"] != line {
		t.Fatal(doc, e)
	}
	after, e := os.ReadFile(a.Scope.ManagerPath())
	if e != nil || !bytes.Equal(before, after) {
		t.Fatal("version mutated manager")
	}
	if e = os.Chmod(p, 0777); e != nil {
		t.Fatal(e)
	}
	doc, e = Run(context.Background(), a, platform.Request{Command: []string{"version"}})
	if e != nil || doc.Data["core"] != nil {
		t.Fatal("untrusted core must become null", doc, e)
	}
	if e = os.Remove(p); e != nil {
		t.Fatal(e)
	}
	doc, e = Run(context.Background(), a, platform.Request{Command: []string{"version"}})
	if e != nil || doc.Data["core"] != nil {
		t.Fatal("missing core must become null", doc, e)
	}
}
