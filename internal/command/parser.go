// Package command owns the public grammar shared by the CLI and in-process TUI.
package command

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

//go:embed spec.json
var specification []byte

type Option struct {
	Name     string   `json:"name"`
	Flags    []string `json:"flags"`
	Required bool     `json:"required"`
	Nargs    any      `json:"nargs"`
	Choices  []string `json:"choices"`
	Type     string   `json:"type"`
	Help     string   `json:"help"`
	Repeat   bool     `json:"repeat"`
}
type Exclusive struct {
	Required bool     `json:"required"`
	Names    []string `json:"names"`
}
type Spec struct {
	Command     []string    `json:"command"`
	Options     []Option    `json:"options"`
	Args        []Option    `json:"args"`
	Exclusive   []Exclusive `json:"exclusive"`
	Description string      `json:"description"`
}

func Specs() []Spec {
	var specs []Spec
	if e := json.Unmarshal(specification, &specs); e != nil {
		panic("invalid embedded CLI grammar")
	}
	return specs
}
func key(o Option) string {
	for _, f := range o.Flags {
		if strings.HasPrefix(f, "--") {
			return strings.TrimPrefix(f, "--")
		}
	}
	return o.Name
}

type Parsed struct {
	Request      platform.Request
	System, JSON bool
	Help         string
}

func Parse(argv []string, input io.Reader, output, stderr io.Writer) (Parsed, error) {
	p := Parsed{Request: platform.Request{Options: map[string][]string{}, Input: input, Output: output, Stderr: stderr}}
	args := append([]string(nil), argv...)
	for i, v := range args {
		if v == "--" {
			p.Request.Child = append([]string{}, args[i+1:]...)
			args = args[:i]
			break
		}
	}
	cleaned := []string{}
	for _, v := range args {
		if v == "--json" {
			p.JSON = true
		} else {
			cleaned = append(cleaned, v)
		}
	}
	args = cleaned
	p.Request.JSON = p.JSON
	userFlag, systemFlag := false, false
	for _, arg := range args {
		userFlag = userFlag || arg == "--user"
		systemFlag = systemFlag || arg == "--system"
	}
	if userFlag && systemFlag {
		return p, platform.UsageDetail("scope-flags-exclusive", "--user and --system are mutually exclusive", "")
	}
	scope := ""
	for len(args) > 0 && (args[0] == "--system" || args[0] == "--user") {
		v := args[0]
		if scope != "" && scope != v {
			p.System = false
			return p, platform.UsageDetail("scope-flags-exclusive", "--user and --system are mutually exclusive", "")
		}
		scope = v
		p.System = v == "--system"
		args = args[1:]
	}
	if len(args) == 0 {
		if p.JSON {
			return p, platform.UsageDetail("usage-error", "a command is required", "run mihomoctl --help")
		}
		p.Help = Help(nil)
		return p, nil
	}
	if args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		p.Help = Help(args[1:])
		return p, nil
	}
	for _, retired := range []string{"paseo", "codex", "opencode", "diagnose", "ready"} {
		if args[0] == retired {
			p.Request.Command = []string{retired}
			return p, platform.UsageDetail("retired-command", "the legacy application-specific or readiness entry has been retired",
				"Use mihomoctl exec -- COMMAND for explicit environment injection, mihomoctl health check or mihomoctl doctor; migrate old configuration with mihomoctl migrate --dry-run.")
		}
	}
	if args[0] == "health" && len(args) > 1 && args[1] == "check" {
		args = append([]string{"health"}, args[2:]...)
	}
	if args[0] == "integration" && (len(args) == 1 || strings.HasPrefix(args[1], "-")) {
		args = append([]string{"integration", "list"}, args[1:]...)
	}
	var selected *Spec
	known := false
	specs := Specs()
	for i := range specs {
		s := &specs[i]
		if s.Command[0] != args[0] {
			continue
		}
		known = true
		if len(args) >= len(s.Command) {
			match := true
			for j, w := range s.Command {
				if args[j] != w {
					match = false
				}
			}
			if match {
				selected = s
				break
			}
		}
	}
	if selected == nil {
		if known {
			p.Request.Command = []string{args[0]}
			for _, v := range args[1:] {
				if v == "--help" || v == "-h" {
					p.Help = Help([]string{args[0]})
					return p, nil
				}
			}
			// A group command without a known action reports the group
			// parser, exactly like the original argparse hierarchy.
			return p, groupArguments(args[0])
		}
		return p, platform.UsageDetail("unknown-command", "unrecognized command; run mihomoctl --help", "")
	}
	p.Request.Command = selected.Command
	args = args[len(selected.Command):]
	flags := map[string]Option{}
	for _, o := range selected.Options {
		for _, f := range o.Flags {
			flags[f] = o
		}
	}
	unknown := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--help" || arg == "-h" {
			p.Help = Help(selected.Command)
			return p, nil
		}
		if strings.HasPrefix(arg, "-") {
			f, v, inline := strings.Cut(arg, "=")
			switch f {
			case "--python", "--wheelhouse", "--extras", "--no-extras":
				return p, pythonPackagingRefusal()
			}
			o, ok := flags[f]
			if !ok {
				// argparse validates required values before the outer parser
				// reports its unknown options. Retain the refusal until those
				// checks have run, without retaining the private spelling.
				unknown = true
				continue
			}
			k := key(o)
			if o.Type == "bool" {
				if inline {
					return p, invalidValue(selected)
				}
				v = "true"
			} else if !inline {
				i++
				if i >= len(args) {
					return p, invalidValue(selected)
				}
				v = args[i]
			}
			if e := validate(o, v); e != nil {
				return p, invalidValue(selected)
			}
			if k == "version" && (selected.Command[0] == "core" || selected.Command[0] == "release") && !coreVersionArgument.MatchString(v) {
				return p, invalidValue(selected)
			}
			p.Request.Options[k] = append(p.Request.Options[k], v)
		} else {
			p.Request.Args = append(p.Request.Args, arg)
		}
	}
	for _, o := range selected.Options {
		if o.Required && !p.Request.Has(key(o)) {
			return p, invalidValue(selected)
		}
	}
	if len(p.Request.Args) > len(selected.Args) {
		return p, unknownOption(selected)
	}
	for i, o := range selected.Args {
		if i >= len(p.Request.Args) {
			if o.Nargs != "?" && o.Nargs != "*" {
				return p, invalidValue(selected)
			}
		} else if e := validate(o, p.Request.Args[i]); e != nil {
			return p, invalidValue(selected)
		}
	}
	for _, g := range selected.Exclusive {
		n := 0
		destinations := map[string]bool{}
		for _, dest := range g.Names {
			destinations[dest] = true
		}
		for _, o := range selected.Options {
			if destinations[o.Name] && p.Request.Has(key(o)) {
				n++
			}
		}
		if n > 1 || (n == 0 && g.Required) {
			return p, invalidValue(selected)
		}
	}
	if p.Request.Has("profile") && p.Request.Has("binding") {
		return p, platform.UsageDetail("profile-binding-exclusive", "--profile and --binding are mutually exclusive", "")
	}
	if unknown {
		return p, unknownOption(selected)
	}
	if len(p.Request.Child) > 0 && selected.Command[0] != "exec" && selected.Command[0] != "direct" {
		return p, invalidValue(selected)
	}
	if (selected.Command[0] == "exec" || selected.Command[0] == "direct") && len(p.Request.Child) == 0 {
		verb := selected.Command[0] + " requires: " + selected.Command[0]
		if selected.Command[0] == "exec" {
			verb = "exec requires: exec [--profile P] -- COMMAND [ARGS...]"
		} else {
			verb = "direct requires: direct -- COMMAND [ARGS...]"
		}
		return p, platform.UsageDetail("usage-error", verb, "")
	}
	if p.Request.Has("python") || p.Request.Has("wheelhouse") || p.Request.Has("extras") || p.Request.Has("no-extras") {
		return p, pythonPackagingRefusal()
	}
	return p, nil
}

var coreVersionArgument = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)

func pythonPackagingRefusal() error {
	return platform.UsageDetail("python-packaging-not-supported",
		"Python packaging options are not supported by the Go distribution.",
		"Install a verified Go bundle with sh install.sh --user; use mihomoctl update SOURCE for Go updates.")
}

func validate(o Option, v string) error {
	if o.Type == "int" {
		if _, e := strconv.Atoi(v); e != nil {
			return platform.Usage("usage-error")
		}
	}
	if len(o.Choices) > 0 {
		for _, c := range o.Choices {
			if c == v {
				return nil
			}
		}
		return platform.Usage("usage-error")
	}
	if strings.IndexByte(v, 0) >= 0 {
		return platform.Usage("usage-error")
	}
	return nil
}

// groupCommands are the original's nested command families. Their dispatcher
// builds a parent parser with subparsers, so an unknown option is refused by
// that parent, which only knows --help. Every other command is a flat leaf.
var groupCommands = map[string]bool{
	"config": true, "profile": true, "env": true, "core": true,
	"tun": true, "integration": true, "service": true, "release": true,
	"rules": true, "controller": true, "subscription": true, "provider": true,
}

// invalidValue mirrors the original's leaf-parser refusal: the diagnostic
// names the leaf command and the remediation lists the accepted options.
func invalidValue(spec *Spec) error {
	return platform.UsageDetail("usage-error", invalidArgumentsFor(spec), validOptionsFor(spec))
}

// unknownOption mirrors the original's parser hierarchy. An unrecognized
// option is refused by the outermost parser: for a group command that is the
// group itself, which only knows --help.
func unknownOption(spec *Spec) error {
	if groupCommands[spec.Command[0]] {
		return groupArguments(spec.Command[0])
	}
	return platform.UsageDetail("usage-error", invalidArgumentsFor(spec), validOptionsFor(spec))
}

// groupArguments reports a group command that cannot accept the arguments.
func groupArguments(group string) error {
	return platform.UsageDetail("usage-error", "invalid arguments for mihomoctl "+group, "mihomoctl "+group+" --help; valid options: --help, -h")
}

func invalidArgumentsFor(spec *Spec) string {
	return "invalid arguments for mihomoctl " + strings.Join(spec.Command, " ")
}

// validOptionsFor lists the accepted option spellings of a leaf parser.
func validOptionsFor(spec *Spec) string {
	seen := map[string]bool{}
	for _, o := range spec.Options {
		for _, f := range o.Flags {
			// The inherited parser diagnostic lists the inherited options.
			// Go distribution extensions are advertised by their own help;
			// they do not alter a baseline invocation's error contract.
			if spec.Command[0] == "core" && f == "--asset" {
				continue
			}
			if (spec.Command[0] == "release" || spec.Command[0] == "update") && (f == "--kind" || f == "--sha256") {
				continue
			}
			seen[f] = true
		}
	}
	seen["--json"] = true
	seen["--help"] = true
	seen["-h"] = true
	list := make([]string, 0, len(seen))
	for f := range seen {
		list = append(list, f)
	}
	sort.Strings(list)
	return "mihomoctl " + strings.Join(spec.Command, " ") + " --help; valid options: " + strings.Join(list, ", ")
}
func Help(words []string) string {
	var b strings.Builder
	b.WriteString("Usage: mihomoctl [--user|--system] COMMAND [OPTIONS] [--json]\nIndependent Go Mihomo manager; private namespace: mihomoctl-go.\n")
	for _, s := range Specs() {
		match := len(words) <= len(s.Command)
		for i, w := range words {
			if i >= len(s.Command) || s.Command[i] != w {
				match = false
				break
			}
		}
		if !match {
			continue
		}
		fmt.Fprintf(&b, "\n%s\n%s\n", strings.Join(s.Command, " "), s.Description)
		if len(words) == len(s.Command) {
			for _, o := range s.Options {
				if o.Name == "python" || o.Name == "wheelhouse" || o.Name == "extras" {
					continue
				}
				fmt.Fprintf(&b, "  %-25s %s\n", strings.Join(o.Flags, ", "), o.Help)
			}
			for _, o := range s.Args {
				fmt.Fprintf(&b, "  %-25s %s\n", o.Name, o.Help)
			}
		}
	}
	return b.String()
}
