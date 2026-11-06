package command

import (
	"context"
	"io"

	"github.com/liuzq1103/mihomoctl/internal/delivery"
	"github.com/liuzq1103/mihomoctl/internal/platform"
	"github.com/liuzq1103/mihomoctl/internal/routing"
	"github.com/liuzq1103/mihomoctl/internal/runtimecore"
)

// Execute is the single application entry point used by CLI and TUI.
func Execute(ctx context.Context, system bool, r platform.Request) platform.Envelope {
	s, err := platform.NewScope(system)
	scope := "user"
	if system {
		scope = "system"
	}
	name := r.Name()
	if name == "" {
		name = "mihomoctl"
	}
	if err != nil {
		return platform.Failure(name, scope, err)
	}
	a := platform.App{Scope: s}
	if recoversOnMutation(r) {
		if err := platform.WithLock(ctx, s, func() error { return nil }); err != nil {
			return platform.Failure(name, scope, err)
		}
	}
	if !recoversOnMutation(r) {
		if err := platform.CheckPending(s); err != nil {
			return platform.Failure(name, scope, err)
		}
	}
	if len(r.Command) == 1 && r.Command[0] == "export" {
		r.Command = []string{"integration", "export"}
		r.Args = []string{r.Get("binding")}
	}
	if r.Output == nil {
		r.Output = io.Discard
	}
	if r.Stderr == nil {
		r.Stderr = io.Discard
	}
	var env platform.Envelope
	switch {
	case delivery.Handles(r.Command):
		env, err = delivery.Run(ctx, a, r)
	case runtimecore.Handles(r.Command):
		env, err = runtimecore.Run(ctx, a, r)
	case routing.Handles(r.Command):
		env, err = routing.Run(ctx, a, r)
	default:
		err = platform.Usage("unknown-command")
	}
	if err != nil {
		return platform.Failure(name, scope, err)
	}
	if env.Schema == "" {
		return platform.Failure(name, scope, platform.Usage("invalid-service-response"))
	}
	return env
}

func recoversOnMutation(r platform.Request) bool {
	switch r.Name() {
	case "init", "start", "stop", "restart", "profile-set-default", "core-adopt", "service-install", "service-start", "service-stop", "service-restart", "service-uninstall", "tun-enable", "tun-disable", "integration-install", "integration-remove", "controller-initialize", "controller-setup", "subscription-preview", "subscription-apply", "installation-install", "installation-uninstall", "installation-recover":
		return true
	case "reset", "migrate", "manual", "override", "health-check":
		return r.Has("apply")
	case "update", "core-install", "core-update":
		return !r.Has("dry-run")
	case "env-export":
		return r.Get("output") != ""
	case "integration-export", "export":
		return r.Get("output-dir") != ""
	}
	return false
}
