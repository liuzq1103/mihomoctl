package main

import (
	"encoding/json"
	"fmt"
	"github.com/liuzq1103/mihomoctl/internal/command"
	"github.com/liuzq1103/mihomoctl/internal/platform"
	"sort"
	"strings"
)

func humanOutput(env platform.Envelope) string {
	if env.Command == "env-export" {
		if vars, ok := env.Data["environment"].(map[string]string); ok {
			return environmentText(vars)
		}
		if vars, ok := env.Data["environment"].(map[string]any); ok {
			m := map[string]string{}
			for k, v := range vars {
				m[k] = fmt.Sprint(v)
			}
			return environmentText(m)
		}
	}
	if env.Command == "version" {
		return fmt.Sprintf("mihomoctl %s\ncore %v\n", platform.Version, env.Data["core"])
	}
	data := env.Data
	if legacy, ok := data["legacy"].(map[string]any); ok {
		data = legacy
	}
	if output, ok := data["output"].(string); ok && strings.HasPrefix(env.Command, "rules-") {
		return output + "\n"
	}
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		switch v := data[k].(type) {
		case string:
			fmt.Fprintf(&b, "%s=%s\n", k, v)
		default:
			raw, _ := json.Marshal(v)
			fmt.Fprintf(&b, "%s=%s\n", k, raw)
		}
	}
	for _, check := range env.Checks {
		fmt.Fprintf(&b, "%s %s (%s)\n", check.Status, check.Name, check.Evidence)
	}
	return b.String()
}
func environmentText(vars map[string]string) string {
	var b strings.Builder
	for _, k := range []string{"http_proxy", "https_proxy", "all_proxy", "no_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"} {
		if v, ok := vars[k]; ok {
			fmt.Fprintf(&b, "%s=%s\n", k, v)
		}
	}
	return b.String()
}

func helpDocument(args []string, help string) map[string]any {
	leaf := false
	for _, v := range args {
		if v != "help" && v != "--help" && v != "-h" && v != "--json" && v != "--system" && v != "--user" {
			leaf = true
		}
	}
	if leaf {
		return map[string]any{"help": strings.TrimSpace(help)}
	}
	seen := map[string]bool{}
	commands := []string{}
	for _, s := range command.Specs() {
		n := s.Command[0]
		if n == "profiles" || n == "export" || n == "dashboard" || seen[n] {
			continue
		}
		seen[n] = true
		commands = append(commands, n)
	}
	return map[string]any{"commands": commands}
}
