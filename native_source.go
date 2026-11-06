package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/liuzq1103/mihomoctl/internal/command"
	"github.com/liuzq1103/mihomoctl/internal/delivery"
	"github.com/liuzq1103/mihomoctl/internal/platform"
	"github.com/liuzq1103/mihomoctl/internal/routing"
	"github.com/liuzq1103/mihomoctl/internal/runtimecore"
)

// nativeSource resolves the owned configuration again after initialization or
// restart, so a disconnected UI can recover without restarting the console.
type nativeSource struct {
	system   bool
	explicit string
	cli      CliSource
	mu       sync.Mutex
	cfg      CtlConfig
	api      *apiSource
	details  bool
}

func (s *nativeSource) current() (Source, error) {
	scope, e := platform.NewScope(s.system)
	if e != nil {
		return nil, e
	}
	if e = platform.CheckPending(scope); e != nil {
		return nil, e
	}
	p := s.explicit
	if p == "" {
		p, e = (platform.App{Scope: scope}).CoreConfigPath()
		if e != nil {
			return nil, e
		}
	} else {
		owned, err := (platform.App{Scope: scope}).CoreConfigPath()
		if err != nil {
			return nil, err
		}
		abs, err := filepath.Abs(p)
		if err != nil || filepath.Clean(abs) != filepath.Clean(owned) {
			return nil, platform.Usage("config-outside-managed-runtime")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	host, port, token, managed, e := routing.ControllerConfig(ctx, platform.App{Scope: scope})
	if e != nil {
		return nil, e
	}
	if filepath.Clean(p) != filepath.Clean(managed) {
		return nil, platform.Usage("config-outside-managed-runtime")
	}
	cfg := CtlConfig{Host: host, Port: port, Token: token, Path: managed}
	s.mu.Lock()
	if s.api == nil || s.cfg != cfg {
		s.cfg = cfg
		s.api = newAPISourceWithService(cfg, s.cli)
		s.api.SetConnectionDetails(s.details)
	}
	api := s.api
	s.mu.Unlock()
	if e = api.verify(); e != nil {
		return nil, e
	}
	return api, nil
}
func (s *nativeSource) source() Source {
	api, e := s.current()
	if e != nil {
		return newDisconnectedSource(e.Error())
	}
	return api
}

func (s *nativeSource) SetConnectionDetails(enabled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.details != enabled {
		s.details = enabled
		s.api = nil
	}
}
func (s *nativeSource) Version() (VersionDoc, error)             { return s.source().Version() }
func (s *nativeSource) Configs() (ConfigsDoc, error)             { return s.source().Configs() }
func (s *nativeSource) Proxies() (ProxiesDoc, error)             { return s.source().Proxies() }
func (s *nativeSource) Connections() (ConnectionsDoc, error)     { return s.source().Connections() }
func (s *nativeSource) Rules() (RulesDoc, error)                 { return s.source().Rules() }
func (s *nativeSource) RuleProviders() (RuleProvidersDoc, error) { return s.source().RuleProviders() }
func (s *nativeSource) Memory() (MemoryDoc, error)               { return s.source().Memory() }
func (s *nativeSource) ProxyProviders() (ProxyProvidersDoc, error) {
	return s.source().ProxyProviders()
}
func (s *nativeSource) Select(g, n string) error { return s.source().Select(g, n) }
func (s *nativeSource) SelectAllowCrossLevel(g, n string) error {
	env, e := s.cli.Run("select", g, n, "--allow-cross-level")
	if e != nil {
		return e
	}
	return serviceError(env, nil)
}
func (s *nativeSource) DelayFor(p, n string, t int) (int, error) { return s.source().DelayFor(p, n, t) }
func (s *nativeSource) Delay(n string, t int) (int, error)       { return s.source().Delay(n, t) }
func (s *nativeSource) SetMode(m string) error                   { return s.source().SetMode(m) }
func (s *nativeSource) RefreshProvider(n string) error           { return s.source().RefreshProvider(n) }
func (s *nativeSource) DNS(n, r string) (DNSAnswer, error)       { return s.source().DNS(n, r) }
func (s *nativeSource) Download(u string) ([]byte, error) {
	return newAPISource(CtlConfig{}).Download(u)
}
func (s *nativeSource) StartTraffic(ctx context.Context) (<-chan Traffic, error) {
	return s.source().StartTraffic(ctx)
}
func (s *nativeSource) StartLogs(ctx context.Context) (<-chan LogLine, error) {
	return s.StartLogsAt(ctx, "info")
}
func (s *nativeSource) StartLogsAt(ctx context.Context, l string) (<-chan LogLine, error) {
	scope, e := platform.NewScope(s.system)
	if e != nil {
		return nil, e
	}
	redact, e := runtimecore.NewLogRedactor(platform.App{Scope: scope})
	if e != nil {
		return nil, e
	}
	api := s.source()
	var input <-chan LogLine
	if v, ok := api.(LogLevelSource); ok {
		input, e = v.StartLogsAt(ctx, l)
	} else {
		input, e = api.StartLogs(ctx)
	}
	if e != nil {
		return nil, e
	}
	out := make(chan LogLine, 128)
	go func() {
		defer close(out)
		for {
			select {
			case <-ctx.Done():
				return
			case line, ok := <-input:
				if !ok {
					return
				}
				line.Payload = redact(line.Payload)
				line.Type = redact(line.Type)
				select {
				case out <- line:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return out, nil
}

// prepareConsole follows the upstream first-use behavior. It never imports a
// Python manager: only a verified offline core or an explicitly trusted PATH
// core can initialize the independent namespace.
func prepareConsole(ctx context.Context, system bool) error {
	scope, e := platform.NewScope(system)
	if e != nil {
		return e
	}
	if _, e = os.Lstat(scope.ManagerPath()); e == nil {
		return nil
	} else if !os.IsNotExist(e) {
		return e
	}
	binary := ""
	if exe, e := os.Executable(); e == nil {
		root := filepath.Dir(filepath.Dir(exe))
		if m, e := delivery.LoadManifest(root); e == nil && m.Kind == "offline" && m.Arch == runtime.GOARCH {
			if e = delivery.VerifyTree(root, m); e != nil {
				return e
			}
			binary = filepath.Join(root, "core", "mihomo")
		}
	}
	if binary == "" {
		if p, e := exec.LookPath("mihomo"); e == nil {
			binary = p
		}
	}
	if binary == "" {
		return platform.Usage("core-required-run-init-with-core")
	}
	env := command.Execute(ctx, system, platform.Request{Command: []string{"init"}, Options: map[string][]string{"core": {binary}}})
	if env.Overall != "PASS" {
		return platform.Usage(env.Errors[0].Code)
	}
	return nil
}
