//go:build linux

package runtimecore

import (
	"bytes"
	"context"
	"os"
	"testing"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

func TestCommitAndStartStoppedAndRunning(t *testing.T) {
	for _, running := range []bool{false, true} {
		name := "stopped"
		if running {
			name = "running"
		}
		t.Run(name, func(t *testing.T) {
			a := initializedApp(t)
			if running {
				if _, e := Run(context.Background(), a, platform.Request{Command: []string{"start"}}); e != nil {
					t.Fatal(e)
				}
			}
			x, e := resolve(a, "")
			if e != nil {
				t.Fatal(e)
			}
			x.Config["mode"] = "direct"
			after, e := marshalYAML(x.Config)
			if e != nil {
				t.Fatal(e)
			}
			receipt := x.Manager.Core.Config + ".userctl-state.json"
			if e = platform.WriteJSON(receipt, map[string]any{"state": "restart-required"}); e != nil {
				t.Fatal(e)
			}
			result, e := CommitAndStart(context.Background(), a, x.Manager.Core.Config, x.Text, after)
			if e != nil || result["state"] != "running" || result["verified"] != true {
				t.Fatal(result, e)
			}
			actual, e := readManagedFile(a, x.Manager.Core.Config)
			if e != nil || !bytes.Equal(actual, after) {
				t.Fatal("configuration not published", e)
			}
			if _, e = os.Lstat(receipt); !os.IsNotExist(e) {
				t.Fatal("restart-pending receipt not cleared")
			}
			assertHealthy(t, a)
		})
	}
}
func TestCommitAndStartRefusesStaleBaseAndSecurityChanges(t *testing.T) {
	a := initializedApp(t)
	x, e := resolve(a, "")
	if e != nil {
		t.Fatal(e)
	}
	x.Config["mode"] = "direct"
	candidate, e := marshalYAML(x.Config)
	if e != nil {
		t.Fatal(e)
	}
	_, e = CommitAndStart(context.Background(), a, x.Manager.Core.Config, []byte("stale"), candidate)
	requireCode(t, e, "config-changed-during-policy-edit")
	x.Config["secret"] = "unreviewed-controller-secret-which-is-long-enough"
	candidate, e = marshalYAML(x.Config)
	if e != nil {
		t.Fatal(e)
	}
	_, e = CommitAndStart(context.Background(), a, x.Manager.Core.Config, x.Text, candidate)
	requireCode(t, e, "configuration-security-envelope-changed")
	actual, e := readManagedFile(a, x.Manager.Core.Config)
	if e != nil || !bytes.Equal(actual, x.Text) {
		t.Fatal("refused save mutated configuration", e)
	}
}
func TestCommitAndStartFailedActivationRestoresRuntimeAndPendingReceipt(t *testing.T) {
	for _, running := range []bool{false, true} {
		name := "stopped"
		if running {
			name = "running"
		}
		t.Run(name, func(t *testing.T) {
			a := initializedApp(t)
			if running {
				if _, e := Run(context.Background(), a, platform.Request{Command: []string{"start"}}); e != nil {
					t.Fatal(e)
				}
			}
			x, e := resolve(a, "")
			if e != nil {
				t.Fatal(e)
			}
			x.Config["helper-start-reject"] = true
			after, e := marshalYAML(x.Config)
			if e != nil {
				t.Fatal(e)
			}
			receipt := x.Manager.Core.Config + ".userctl-state.json"
			originalReceipt := []byte("{\"state\":\"restart-required\"}\n")
			if e = platform.AtomicWrite(receipt, originalReceipt, 0600); e != nil {
				t.Fatal(e)
			}
			result, e := CommitAndStart(context.Background(), a, x.Manager.Core.Config, x.Text, after)
			if e == nil || result != nil {
				t.Fatal("failed activation reported success", result, e)
			}
			actual, e := readManagedFile(a, x.Manager.Core.Config)
			if e != nil || !bytes.Equal(actual, x.Text) {
				t.Fatal("base not restored", e)
			}
			raw, e := platform.ReadPrivate(receipt)
			if e != nil || !bytes.Equal(raw, originalReceipt) {
				t.Fatal("pending restart receipt lost", e)
			}
			id, e := runningIdentity(context.Background(), a, x.Manager)
			if e != nil || (id != nil) != running {
				t.Fatal("prior running/stopped state not restored", id, e)
			}
			if running {
				assertHealthy(t, a)
			}
		})
	}
}
func TestInterruptedCommitAndStartRestoresOriginalRuntime(t *testing.T) {
	a := initializedApp(t)
	if _, e := Run(context.Background(), a, platform.Request{Command: []string{"start"}}); e != nil {
		t.Fatal(e)
	}
	x, e := resolve(a, "")
	if e != nil {
		t.Fatal(e)
	}
	x.Config["mode"] = "direct"
	after, e := marshalYAML(x.Config)
	if e != nil {
		t.Fatal(e)
	}
	crashAt(t, crashSpec{App: a, Activate: true, Config: x.Manager.Core.Config, Before: x.Text, After: after, Phase: "process-started-before-state"})
	recoverViaMutation(t, a)
	actual, e := readManagedFile(a, x.Manager.Core.Config)
	if e != nil || !bytes.Equal(actual, x.Text) {
		t.Fatal("interrupted private activation not restored", e)
	}
	assertHealthy(t, a)
}
