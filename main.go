// mihomoctl-tui is the Go rewrite of the mihomoctl interactive console.
//
// It applies the techniques that make htop feel instant: a double-buffered
// cell grid flushed as per-cell diffs, immediate-mode drawing, one event loop
// that never blocks on I/O, and keep-alive HTTP to the controller. Zero
// third-party dependencies; build with:
//
//	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o mihomoctl-tui .
package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	config := flag.String("config", "", "mihomo config path (default $XDG_CONFIG_HOME/mihomo/config.yaml)")
	page := flag.String("page", "overview", "initial page")
	demo := flag.Bool("demo", false, "use synthetic data instead of a live controller")
	render := flag.Bool("render", false, "dump one rendered frame to stdout and exit (no tty needed)")
	binary := flag.String("mihomoctl", "mihomoctl", "mihomoctl CLI binary for transactional operations")
	width := flag.Int("width", 100, "render width with -render")
	height := flag.Int("height", 30, "render height with -render")
	flag.Parse()

	src, cli := pickSource(*demo, *config, *binary)

	if *render {
		os.Exit(renderFrame(src, cli, *page, *width, *height))
	}

	raw, err := enterRaw()
	if err != nil {
		fatal(err)
	}
	defer raw.restore()
	w, h := termSize()
	fmt.Print("\x1b[?1049h\x1b[?25l\x1b[?7l")
	defer fmt.Print("\x1b[?7h\x1b[?25h\x1b[?1049l\x1b[0m")
	app := NewApp(src, cli, w, h, *page, *demo)
	if err := app.Run(); err != nil {
		fatal(err)
	}
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
	}
	app.draw()
	fmt.Print(app.scr.DumpPlain())
	return 0
}
