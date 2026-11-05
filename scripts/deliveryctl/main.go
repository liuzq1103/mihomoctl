// deliveryctl is an installation/recovery entry point and a delivery API smoke
// harness. The main product CLI is built from the repository root.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/liuzq1103/mihomoctl/internal/delivery"
	"github.com/liuzq1103/mihomoctl/internal/platform"
)

func main() {
	r := platform.Request{Options: map[string][]string{}, Input: os.Stdin, Output: os.Stdout, Stderr: os.Stderr}
	args := os.Args[1:]
	system := false
	values := map[string]bool{"source": true, "bin-dir": true, "version": true, "sha256": true, "output-dir": true, "kind": true, "target": true, "asset": true}
	flags := map[string]bool{"dry-run": true, "reinstall": true, "allow-same-version": true, "allow-downgrade": true, "latest": true, "json": true}
	for i := 0; i < len(args); i++ {
		s := args[i]
		if s == "--system" {
			system = true
			continue
		}
		if strings.HasPrefix(s, "--") {
			k, v, has := strings.Cut(s[2:], "=")
			if values[k] {
				if !has {
					i++
					if i >= len(args) {
						fmt.Fprintln(os.Stderr, "missing option value")
						os.Exit(2)
					}
					v = args[i]
				}
				r.Options[k] = append(r.Options[k], v)
			} else if flags[k] && !has {
				r.Options[k] = []string{"true"}
			} else {
				fmt.Fprintln(os.Stderr, "unknown option")
				os.Exit(2)
			}
			continue
		}
		if len(r.Command) == 0 {
			r.Command = append(r.Command, s)
		} else if len(r.Command) == 1 && (r.Command[0] == "release" || r.Command[0] == "core" || r.Command[0] == "installation") {
			r.Command = append(r.Command, s)
		} else {
			r.Args = append(r.Args, s)
		}
	}
	s, e := platform.NewScope(system)
	if e != nil {
		fmt.Fprintln(os.Stderr, platform.SafeError(e))
		os.Exit(2)
	}
	doc, _ := delivery.Run(context.Background(), platform.App{Scope: s}, r)
	if e = json.NewEncoder(os.Stdout).Encode(doc); e != nil {
		os.Exit(1)
	}
	os.Exit(doc.ExitCode())
}
