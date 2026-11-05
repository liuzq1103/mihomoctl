package main

import (
	"github.com/liuzq1103/mihomoctl/internal/platform"
	"testing"
)

func TestConsoleOptionIncompatibleCombinationsRefused(t *testing.T) {
	for _, opts := range []map[string][]string{{"plain": {"true"}, "script": {"/private/script.js"}}, {"policy": {"provider"}}, {"flclash-compat": {"true"}}, {"stdin": {"true"}, "engine": {"curses"}}, {"plain": {"true"}, "theme": {"dark"}}, {"home-dir": {"/outside/home"}}} {
		if e := validateConsoleOptions(platform.Request{Options: opts}, false); e == nil {
			t.Fatalf("ignored options %v", opts)
		}
	}
}
func TestConsoleOptionSupportedCombinations(t *testing.T) {
	for _, opts := range []map[string][]string{{"plain": {"true"}}, {"engine": {"textual"}, "theme": {"light"}}, {"stdin": {"true"}, "policy": {"provider"}}, {"script": {"/private/script.js"}, "flclash-compat": {"true"}}} {
		if e := validateConsoleOptions(platform.Request{Options: opts}, false); e != nil {
			t.Fatal(opts, e)
		}
	}
}
