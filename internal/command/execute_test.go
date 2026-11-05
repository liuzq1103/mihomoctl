package command

import (
	"context"
	"io"
	"path/filepath"
	"testing"

	"github.com/liuzq1103/mihomoctl/internal/delivery"
	"github.com/liuzq1103/mihomoctl/internal/routing"
	"github.com/liuzq1103/mihomoctl/internal/runtimecore"
)

func TestEveryLeafReachesNativeImplementation(t *testing.T) {
	for _, s := range Specs() {
		if s.Command[0] == "tui" || s.Command[0] == "export" {
			continue
		}
		n := 0
		for _, handles := range []func([]string) bool{delivery.Handles, routing.Handles, runtimecore.Handles} {
			if handles(s.Command) {
				n++
			}
		}
		if n != 1 {
			t.Errorf("%v has %d native handlers", s.Command, n)
		}
	}
}

func TestNativeVersionWithoutConfiguration(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(t.TempDir(), "absent"))
	p, e := Parse([]string{"--json", "version"}, nil, io.Discard, io.Discard)
	if e != nil {
		t.Fatal(e)
	}
	env := Execute(context.Background(), false, p.Request)
	if env.Overall != "PASS" || env.Data["version"] != "0.2.0" {
		t.Fatal(env)
	}
}

func TestCLIHelpDoesNotOpenConfiguration(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "deliberately-relative")
	p, e := Parse([]string{"subscription", "apply", "--help"}, nil, nil, nil)
	if e != nil || p.Help == "" {
		t.Fatal("help loaded configuration", e)
	}
}
