// mihomoctl is an independently scoped native Go Mihomo manager.
//
// It applies the techniques that make htop feel instant: a double-buffered
// cell grid flushed as per-cell diffs, immediate-mode drawing, one event loop
// that never blocks on I/O, and keep-alive HTTP to the controller. Build with:
//
//	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o mihomoctl-tui .
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/liuzq1103/mihomoctl/internal/command"
	"github.com/liuzq1103/mihomoctl/internal/platform"
	"os"
	"os/signal"
	"strings"
)

func main() { os.Exit(runMain(os.Args[1:])) }

func runMain(args []string) int {
	if len(args) == 0 {
		if st, e := os.Stdin.Stat(); e != nil || st.Mode()&os.ModeCharDevice == 0 {
			// Without a command the original prints its grouped help and
			// then refuses with a usage error; it never exits successfully
			// without having done something.
			fmt.Print(command.Help(nil))
			env := platform.Failure("mihomoctl", "user", platform.UsageDetail("usage-error", "a command is required", "run mihomoctl --help"))
			fmt.Fprintln(os.Stderr, "mihomoctl:", "usage-error: a command is required (run mihomoctl --help)")
			return env.ExitCode()
		}
	}
	legacy := len(args) == 0
	if len(args) > 0 {
		for _, f := range []string{"-config", "-page", "-demo", "-render", "-mihomoctl", "-width", "-height"} {
			if args[0] == f || strings.HasPrefix(args[0], f+"=") {
				legacy = true
			}
		}
	}
	var consoleRequest platform.Request
	plain := false
	system := false
	theme := "dark"
	ascii := false
	if !legacy {
		p, err := command.Parse(args, os.Stdin, os.Stdout, os.Stderr)
		if err != nil {
			name := p.Request.TopLevel()
			if name == "" {
				name = "mihomoctl"
			}
			env := platform.Failure(name, scopeName(p.System), err)
			if env.Command == "" {
				env.Command = "mihomoctl"
			}
			return emitCLI(env, p.JSON)
		}
		if p.Help != "" {
			if p.JSON {
				return emitCLI(platform.Document("help", scopeName(p.System), helpDocument(args, p.Help)), true)
			}
			fmt.Print(p.Help)
			return 0
		}
		if len(p.Request.Command) > 0 && p.Request.Command[0] == "tui" {
			if p.JSON {
				return emitCLI(platform.Failure("tui", scopeName(p.System), platform.Usage("tui-json-not-supported")), true)
			}
			if err := validateConsoleOptions(p.Request, p.System); err != nil {
				return emitCLI(platform.Failure("tui", scopeName(p.System), err), false)
			}
			consoleRequest = p.Request
			system = p.System
			theme = p.Request.Get("theme")
			ascii = p.Request.Has("ascii")
			plain = p.Request.Has("plain") || p.Request.Get("engine") == "plain"
			args = []string{}
		} else {
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
			defer cancel()
			env := command.Execute(ctx, p.System, p.Request)
			return emitCLI(env, p.JSON)
		}
	}
	flags := flag.NewFlagSet("mihomoctl", flag.ContinueOnError)
	config := flags.String("config", consoleRequest.Get("config"), "explicit private core configuration")
	page := flags.String("page", "overview", "initial page")
	demo := flags.Bool("demo", false, "use synthetic data")
	render := flags.Bool("render", false, "render one frame without a tty")
	binary := flags.String("mihomoctl", "", "deprecated compatibility option; backend is always built in")
	width := flags.Int("width", 100, "render width")
	height := flags.Int("height", 30, "render height")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "mihomoctl: invalid arguments")
		return 2
	}
	if !*render && !consoleRequest.Has("stdin") && !interactiveConsole() {
		fmt.Fprintln(os.Stderr, "mihomoctl: tui-requires-interactive-linux-terminal")
		return 2
	}
	var src Source
	var cli CliSource
	if *demo {
		src = newDemoSource()
		cli = &demoCli{}
	} else {
		cli = &realCli{system: system}
		// First-use preparation belongs only to a human console, never render.
		if !*render {
			if err := prepareConsole(context.Background(), system); err != nil {
				fmt.Fprintln(os.Stderr, "mihomoctl:", platform.SafeError(err))
			}
		}
		src = &nativeSource{system: system, explicit: *config, cli: cli}
	}
	var seeded *Envelope
	if consoleRequest.Has("stdin") {
		env, err := stdinConsolePreview(cli, consoleRequest)
		if err != nil {
			fmt.Fprintln(os.Stderr, "mihomoctl:", err)
			return 2
		}
		seeded = &env
		if err = restoreConsoleInput(); err != nil {
			fmt.Fprintln(os.Stderr, "mihomoctl:", err)
			return 2
		}
	}
	_ = binary
	if *render {
		return renderFrame(src, cli, *page, *width, *height)
	}
	if plain {
		if seeded != nil {
			if err := offerPlainPreview(src, cli, os.Stdin, os.Stdout, *seeded); err != nil {
				fmt.Fprintln(os.Stderr, "mihomoctl:", err)
				return 2
			}
		}
		if err := runPlainConsole(src, cli, os.Stdin, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "mihomoctl:", err)
			return 2
		}
		return 0
	}
	raw, err := enterRaw()
	if err != nil {
		fmt.Fprintln(os.Stderr, "mihomoctl:", err)
		return 2
	}
	defer raw.restore()
	w, h := termSize()
	fmt.Print("\x1b[?1049h\x1b[?25l\x1b[?7l")
	defer fmt.Print("\x1b[?7h\x1b[?25h\x1b[?1049l\x1b[0m")
	app := NewApp(src, cli, w, h, *page, *demo)
	app.Configure(theme, ascii)
	app.ConfigureScript(consoleRequest.Get("script"), consoleRequest.Has("flclash-compat"))
	app.SetDetails(consoleRequest.Has("details"))
	if seeded != nil {
		app.onAPI(apiMsg{kind: "cli:subscription-preview", preview: seeded.Data})
		app.changePage(pageSubscriptions)
	}
	if err := app.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "mihomoctl:", err)
		return 2
	}
	return 0
}

func emitCLI(env platform.Envelope, jsonMode bool) int {
	if jsonMode {
		if err := json.NewEncoder(os.Stdout).Encode(env); err != nil {
			return 2
		}
	} else if env.Overall != "PASS" {
		for _, e := range env.Errors {
			line := e.Code
			if e.Detail != "" {
				line += ": " + e.Detail
			}
			if e.Remediation != "" {
				line += " (" + e.Remediation + ")"
			}
			fmt.Fprintln(os.Stderr, "mihomoctl:", line)
		}
		fmt.Fprint(os.Stderr, humanOutput(env))
	} else {
		fmt.Fprint(os.Stdout, humanOutput(env))
	}
	return env.ExitCode()
}

func pickSource(demo bool, config, binary string) (Source, CliSource) {
	if demo {
		return newDemoSource(), &demoCli{}
	}
	cfg, err := discoverCtl(config)
	if err != nil {
		fatal(err)
	}
	api := newAPISource(cfg)
	if err := api.verify(); err != nil {
		fatal(err)
	}
	return api, newRealCli(binary)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "mihomoctl-tui:", err)
	os.Exit(2)
}

// renderFrame runs the same state machine once against synchronous fetches and
// prints the frame as plain text, so every page can be verified without a tty
// and asserted in CI.
func renderFrame(src Source, cli CliSource, page string, width, height int) int {
	if width < 20 || height < 10 {
		fmt.Fprintln(os.Stderr, "render size too small")
		return 2
	}
	if _, ok := pageNames[page]; !ok {
		fmt.Fprintln(os.Stderr, "unknown page:", page)
		return 2
	}
	app := NewApp(src, cli, width, height, page, true)

	version, _ := src.Version()
	configs, _ := src.Configs()
	memory, _ := src.Memory()
	proxies, _ := src.Proxies()
	conns, _ := src.Connections()
	rules, _ := src.Rules()
	providers, _ := src.RuleProviders()
	pProv, _ := src.ProxyProviders()
	app.onAPI(apiMsg{kind: "version", version: &version})
	app.onAPI(apiMsg{kind: "configs", configs: &configs})
	app.onAPI(apiMsg{kind: "memory", memory: &memory})
	app.onAPI(apiMsg{kind: "proxies", proxies: &proxies})
	app.onAPI(apiMsg{kind: "connections", conns: &conns})
	app.onAPI(apiMsg{kind: "rules", rules: &rules})
	app.onAPI(apiMsg{kind: "providers", providers: &providers})
	app.onAPI(apiMsg{kind: "proxy-providers", pProv: &pProv})
	app.traffic = Traffic{Up: 240_000, Down: 3_100_000}
	for i := 0; i < 40; i++ {
		app.logs = append(app.logs, LogLine{
			Type: []string{"info", "info", "warning", "error"}[i%4],
			Payload: fmt.Sprintf("[TCP] 127.0.0.1:%d --> api.example-%02d.com:443 match Demo using PROXY",
				40000+i, i),
		})
	}
	app.nodeIdx = 5
	switch page {
	case pageSubscriptions:
		msg := app.runCLI("cli:subscription-preview", "subscription", []string{"preview", "--policy", "provider"}, "subscription-preview")
		env, _ := cli.Run("subscription", "preview", "--policy", "provider")
		msg.preview = env.Data
		app.onAPI(msg)
	case pageProfile:
		app.onAPI(app.loadProfile())
	case pageRuntime:
		app.onAPI(app.runCLI("cli:status", "status", nil, "status"))
	case pageDiagnostics:
		app.onAPI(app.runCLI("cli:health", "health", []string{"check"}, "health"))
		app.diagTitle = "health check"
	case pageOverview:
		if env, err := cli.Run("status"); err == nil {
			app.onAPI(apiMsg{kind: "cli:status:overview", data: env.Data, overall: env.Overall})
		}
	}
	app.draw()
	fmt.Print(app.scr.DumpPlain())
	return 0
}
