package main

import (
	"github.com/liuzq1103/mihomoctl/internal/platform"
	"os"
	"path/filepath"
)

func validateConsoleOptions(r platform.Request, system bool) error {
	plain := r.Has("plain") || r.Get("engine") == "plain"
	if plain && r.Get("script") != "" {
		return platform.Usage("script-preview-requires-fullscreen-tui-or-override-command")
	}
	if plain && (r.Has("theme") || r.Has("ascii")) {
		return platform.Usage("theme-options-require-fullscreen-tui")
	}
	if r.Has("flclash-compat") && r.Get("script") == "" {
		return platform.Usage("flclash-compat-requires-script")
	}
	if r.Has("policy") && !r.Has("stdin") {
		return platform.Usage("policy-requires-subscription-preview")
	}
	if r.Has("stdin") && r.Get("engine") == "curses" {
		return platform.Usage("tui-stdin-requires-textual-or-plain")
	}
	if dir := r.Get("home-dir"); dir != "" {
		s, e := platform.NewScope(system)
		if e != nil {
			return e
		}
		p, e := filepath.Abs(dir)
		if e != nil || filepath.Clean(p) != filepath.Clean(s.CoreHome()) {
			return platform.Usage("home-dir-outside-managed-runtime")
		}
	}
	return nil
}
func stdinConsolePreview(cli CliSource, r platform.Request) (Envelope, error) {
	raw, e := platform.ReadLimited(os.Stdin)
	if e != nil {
		return Envelope{}, e
	}
	policy := r.Get("policy")
	if policy == "" {
		policy = "auto"
	}
	env, e := cli.RunWithStdin(raw, "subscription", "preview", "--stdin", "--policy", policy)
	if e != nil {
		return env, e
	}
	return env, serviceError(env, nil)
}
func restoreConsoleInput() error {
	tty, e := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if e != nil {
		return platform.Usage("tui-requires-interactive-terminal")
	}
	os.Stdin = tty
	return nil
}
