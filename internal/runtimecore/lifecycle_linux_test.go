//go:build linux

package runtimecore

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

// The test executable doubles as a real child core. It opens actual sockets,
// enforces HTTP/SOCKS/controller authentication, and supports isolated -t checks.
func TestMain(m *testing.M) {
	if spec := os.Getenv("MIHOMOCTL_GO_TEST_WORKER"); spec != "" {
		runPrivilegedUserWorker(spec)
		return
	}
	if len(os.Args) > 1 && member(os.Args[1], "-t", "-d", "-v") {
		os.Exit(testCore())
	}
	if spec := os.Getenv("RUNTIMECORE_CRASH_SPEC"); spec != "" {
		runCrashHelper(spec)
		return
	}
	if os.Getenv("RUNTIMECORE_REPLACE") == "direct" {
		_, e := Run(context.Background(), platform.App{}, platform.Request{Command: []string{"direct"}, Child: []string{"/bin/sh", "-c", os.Getenv("RUNTIMECORE_SCRIPT")}})
		if e != nil {
			os.Exit(120)
		}
		os.Exit(121)
	}
	os.Exit(m.Run())
}
func testCore() int {
	if os.Args[1] == "-v" {
		fmt.Println("Mihomo Meta v1.19.33 linux amd64")
		return 0
	}
	file, home := "", ""
	validate := false
	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "-t":
			validate = true
		case "-f":
			i++
			if i >= len(os.Args) {
				return 2
			}
			file = os.Args[i]
		case "-d":
			i++
			if i >= len(os.Args) {
				return 2
			}
			home = os.Args[i]
		}
	}
	raw, e := os.ReadFile(file)
	if e != nil {
		return 3
	}
	cfg, e := platform.DecodeYAML(raw)
	if e != nil || platform.Bool(cfg["helper-reject"]) {
		fmt.Fprintln(os.Stderr, "private URL and password must never escape")
		return 4
	}
	if !validate && platform.Bool(cfg["helper-start-reject"]) {
		return 8
	}
	if validate {
		if marker := os.Getenv("RUNTIMECORE_VALIDATION_MARKER"); marker != "" {
			_ = os.WriteFile(marker, []byte(home+"\n"+file), 0600)
		}
		return 0
	}
	eps, ctrl, e := parseEndpoints(cfg, false, nil)
	if e != nil {
		return 5
	}
	var wg sync.WaitGroup
	for _, ep := range eps {
		l, e := net.Listen("tcp", ep.address())
		if e != nil {
			return 6
		}
		wg.Add(1)
		go func(ep endpoint, l net.Listener) {
			defer wg.Done()
			for {
				c, e := l.Accept()
				if e != nil {
					return
				}
				go serveProxy(c, ep.Users[0])
			}
		}(ep, l)
	}
	if ctrl != nil {
		ln, e := net.Listen("tcp", ctrl.address())
		if e != nil {
			return 7
		}
		secret := platform.String(cfg["secret"])
		go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer "+secret {
				w.WriteHeader(401)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"version":"1.19.33"}`)
		}))
	}
	fmt.Println("test core running")
	wg.Wait()
	return 0
}
func serveProxy(c net.Conn, creds credentials) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(6 * time.Second))
	reader := bufio.NewReader(c)
	first, e := reader.Peek(1)
	if e != nil {
		return
	}
	if first[0] == 5 {
		header := make([]byte, 2)
		if _, e = io.ReadFull(reader, header); e != nil {
			return
		}
		methods := make([]byte, int(header[1]))
		if _, e = io.ReadFull(reader, methods); e != nil {
			return
		}
		supported := false
		for _, v := range methods {
			if v == 2 {
				supported = true
			}
		}
		if !supported {
			c.Write([]byte{5, 255})
			return
		}
		c.Write([]byte{5, 2})
		if _, e = io.ReadFull(reader, header); e != nil {
			return
		}
		user := make([]byte, int(header[1]))
		if _, e = io.ReadFull(reader, user); e != nil {
			return
		}
		size, e := reader.ReadByte()
		if e != nil {
			return
		}
		pass := make([]byte, int(size))
		if _, e = io.ReadFull(reader, pass); e != nil {
			return
		}
		verdict := byte(1)
		if string(user) == creds.Username && string(pass) == creds.Password {
			verdict = 0
		}
		c.Write([]byte{1, verdict})
		return
	}
	r, e := http.ReadRequest(reader)
	if e != nil {
		return
	}
	if r.Header.Get("Proxy-Connection") != "close" || r.Header.Get("Connection") != "close" {
		fmt.Fprint(c, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		return
	}
	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte(creds.Username+":"+creds.Password))
	status := "407 Proxy Authentication Required"
	if r.Header.Get("Proxy-Authorization") == auth {
		if delay, e := strconv.Atoi(os.Getenv("RUNTIMECORE_HTTP_DELAY_MS")); e == nil && delay > 0 && delay <= 5000 {
			time.Sleep(time.Duration(delay) * time.Millisecond)
		}
		status = "502 Bad Gateway"
	}
	fmt.Fprintf(c, "HTTP/1.1 %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", status)
}

func TestNativeStartAcceptsFourSecondHTTPHealthResponse(t *testing.T) {
	a := initializedApp(t)
	x, e := resolve(a, "")
	if e != nil {
		t.Fatal(e)
	}
	if defaults(x.Profile).Health.Timeout != 10 {
		t.Fatal("default startup budget must remain ten seconds")
	}
	t.Setenv("RUNTIMECORE_HTTP_DELAY_MS", "4000")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	started := time.Now()
	doc, e := Run(ctx, a, platform.Request{Command: []string{"start"}})
	if e != nil || doc.Overall != "PASS" {
		t.Fatalf("four-second authenticated HEAD was blocked during default startup: %v %+v", e, doc)
	}
	if time.Since(started) < 4*time.Second {
		t.Fatal("test core did not exercise delayed authenticated response")
	}
	if ctx.Err() != nil {
		t.Fatal("health checks exhausted ten-second startup budget", ctx.Err())
	}
}
func initializedApp(t *testing.T) platform.App {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("public user mutation intentionally refuses root")
	}
	a := testApp(t)
	source, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(source)
	if e != nil {
		t.Fatal(e)
	}
	binary := filepath.Join(filepath.Dir(a.Scope.ConfigRoot), "test-core")
	if e = platform.PrivateDir(filepath.Dir(binary)); e != nil {
		t.Fatal(e)
	}
	if e = platform.AtomicWrite(binary, b, 0700); e != nil {
		t.Fatal(e)
	}
	doc, e := Run(context.Background(), a, platform.Request{Command: []string{"init"}, Options: map[string][]string{"core": {binary}}})
	if e != nil || doc.Overall != "PASS" {
		t.Fatalf("init: %+v %v", doc, e)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		Run(ctx, a, platform.Request{Command: []string{"stop"}})
	})
	return a
}
func TestNativeLifecycleAndAuthentication(t *testing.T) {
	a := initializedApp(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	doc, e := Run(ctx, a, platform.Request{Command: []string{"status"}})
	if e != nil || doc.Overall != "FAIL" {
		t.Fatal(doc, e)
	}
	for _, cmd := range [][]string{{"start"}, {"health", "check"}, {"start"}, {"restart"}, {"health"}, {"stop"}, {"stop"}} {
		doc, e = Run(ctx, a, platform.Request{Command: cmd})
		if e != nil || doc.Overall != "PASS" {
			t.Fatalf("%v: %v %+v", cmd, e, doc)
		}
	}
	if _, e = os.Stat(a.Scope.RuntimeState()); !os.IsNotExist(e) {
		t.Fatal("state not cleared")
	}
}
func TestOwnershipRejectsForeignProcess(t *testing.T) {
	skipEmulatedKernel(t)
	a := initializedApp(t)
	m, e := loadManager(a)
	if e != nil {
		t.Fatal(e)
	}
	self, e := inspectIdentity(os.Getpid())
	if e != nil {
		t.Fatal(e)
	}
	s := runtimeState{1, "mihomoctl-go", a.Scope.Name, m.Core.Config, a.Scope.CoreHome(), self}
	if e = platform.WriteJSON(a.Scope.RuntimeState(), s); e != nil {
		t.Fatal(e)
	}
	_, e = Run(context.Background(), a, platform.Request{Command: []string{"stop"}})
	requireCode(t, e, "runtime-state-invalid")
	if !identityAlive(self) {
		t.Fatal("foreign process signalled")
	}
}
func TestSocketOwnershipAndPIDIdentity(t *testing.T) {
	skipEmulatedKernel(t)
	id, e := inspectIdentity(os.Getpid())
	if e != nil {
		t.Fatal(e)
	}
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	ep := endpoint{Address: "127.0.0.1", Port: l.Addr().(*net.TCPAddr).Port}
	if !ownsListener(id, ep) {
		t.Fatal("own socket not found")
	}
	id.Start = "different"
	if identityAlive(id) || ownsListener(id, ep) {
		t.Fatal("stale identity accepted")
	}
	requireCode(t, signalOwned(id, false), "runtime-identity-mismatch")
	for raw, want := range map[string]string{"0100007F": "127.0.0.1", "00000000000000000000000001000000": "::1"} {
		if got := procIP(raw); got != want {
			t.Fatalf("%s != %s", got, want)
		}
	}
}
func TestPortConflictDoesNotAdoptForeignSocket(t *testing.T) {
	a := initializedApp(t)
	if e := platform.WriteJSON(generatedPath(a), generatedConfig{Automatic: false}); e != nil {
		t.Fatal(e)
	}
	x, e := resolve(a, "")
	if e != nil {
		t.Fatal(e)
	}
	l, e := net.Listen("tcp", x.Endpoints[0].address())
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	_, e = Run(context.Background(), a, platform.Request{Command: []string{"start"}})
	requireCode(t, e, "port-conflict")
	if _, e = os.Lstat(a.Scope.RuntimeState()); !os.IsNotExist(e) {
		t.Fatal("published runtime for foreign port")
	}
}
func TestValidationIsIsolatedAndErrorsRedacted(t *testing.T) {
	a := initializedApp(t)
	x, e := resolve(a, "")
	if e != nil {
		t.Fatal(e)
	}
	marker := filepath.Join(a.Scope.ConfigRoot, "validation-marker")
	t.Setenv("RUNTIMECORE_VALIDATION_MARKER", marker)
	doc, e := Run(context.Background(), a, platform.Request{Command: []string{"config", "check"}})
	if e != nil || doc.Overall != "PASS" {
		t.Fatal(doc, e)
	}
	b, e := os.ReadFile(marker)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(b), a.Scope.CoreHome()) || strings.Contains(string(b), x.Manager.Core.Config) {
		t.Fatal("validation used live paths")
	}
	if _, e = os.Stat(strings.Split(string(b), "\n")[0]); !os.IsNotExist(e) {
		t.Fatal("staging not removed")
	}
	x.Config["helper-reject"] = true
	if e = platform.WriteYAML(x.Manager.Core.Config, x.Config); e != nil {
		t.Fatal(e)
	}
	doc, e = Run(context.Background(), a, platform.Request{Command: []string{"config", "validate"}})
	requireCode(t, e, "core-config-invalid")
	data, _ := json.Marshal(doc)
	if strings.Contains(string(data), "private URL") {
		t.Fatal("core diagnostic leaked")
	}
}
func TestLockContentionAndCancellation(t *testing.T) {
	a := initializedApp(t)
	locked := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- platform.WithLock(context.Background(), a.Scope, func() error { close(locked); <-release; return nil })
	}()
	<-locked
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	_, e := Run(ctx, a, platform.Request{Command: []string{"profile", "set-default"}, Args: []string{"default"}})
	requireCode(t, e, "lock-timeout")
	close(release)
	if e = <-done; e != nil {
		t.Fatal(e)
	}
}
func TestResetPreviewStaleAndApply(t *testing.T) {
	a := initializedApp(t)
	r := platform.Request{Command: []string{"reset"}, Options: map[string][]string{"dry-run": {}}}
	doc, e := Run(context.Background(), a, r)
	if e != nil {
		t.Fatal(e)
	}
	digest := doc.Data["plan_sha256"].(string)
	x, e := resolve(a, "")
	if e != nil {
		t.Fatal(e)
	}
	x.Config["mode"] = "direct"
	if e = platform.WriteYAML(x.Manager.Core.Config, x.Config); e != nil {
		t.Fatal(e)
	}
	r.Options = map[string][]string{"apply": {}, "plan-sha256": {digest}}
	_, e = Run(context.Background(), a, r)
	requireCode(t, e, "reset-preview-stale")
	r.Options = map[string][]string{"dry-run": {}}
	doc, e = Run(context.Background(), a, r)
	if e != nil {
		t.Fatal(e)
	}
	r.Options = map[string][]string{"apply": {}, "plan-sha256": {doc.Data["plan_sha256"].(string)}}
	doc, e = Run(context.Background(), a, r)
	if e != nil || doc.Overall != "PASS" {
		t.Fatal(doc, e)
	}
	x, e = resolve(a, "")
	if e != nil || x.Config["mode"] != "rule" {
		t.Fatal("reset failed", e)
	}
}
func TestDirectExecPreservesExitAndSignal(t *testing.T) {
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		script string
		exit   int
		signal bool
	}{{`test -z "$HTTP_PROXY" && test -z "$all_proxy" && test "$RUNTIMECORE_KEEP" = yes; exit 37`, 37, false}, {"kill -TERM $$", -1, true}} {
		cmd := exec.Command(exe, "-test.run=none")
		cmd.Env = append(os.Environ(), "RUNTIMECORE_REPLACE=direct", "RUNTIMECORE_SCRIPT="+tc.script, "HTTP_PROXY=must-clear", "all_proxy=must-clear", "RUNTIMECORE_KEEP=yes")
		e = cmd.Run()
		ee, ok := e.(*exec.ExitError)
		if !ok {
			t.Fatal(e)
		}
		status := ee.Sys().(syscall.WaitStatus)
		if tc.signal {
			if !status.Signaled() || status.Signal() != syscall.SIGTERM {
				t.Fatal(status)
			}
		} else if ee.ExitCode() != tc.exit {
			t.Fatal(ee.ExitCode())
		}
	}
}

func TestGeneratedPortCollisionRetriesOnlyPristineConfig(t *testing.T) {
	skipEmulatedKernel(t)
	a := initializedApp(t)
	x, e := resolve(a, "")
	if e != nil {
		t.Fatal(e)
	}
	l, e := net.Listen("tcp", x.Endpoints[0].address())
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	doc, e := Run(context.Background(), a, platform.Request{Command: []string{"start"}})
	if e != nil || doc.Overall != "PASS" {
		t.Fatal(doc, e)
	}
	next, e := resolve(a, "")
	if e != nil || next.Endpoints[0].Port == x.Endpoints[0].Port {
		t.Fatal("port not reassigned", e)
	}
	if ownsListener(*mustIdentity(t, a, next.Manager), x.Endpoints[0]) {
		t.Fatal("adopted foreign socket")
	}
}
func mustIdentity(t *testing.T, a platform.App, m manager) *identity {
	t.Helper()
	id, e := runningIdentity(context.Background(), a, m)
	if e != nil || id == nil {
		t.Fatal(e)
	}
	return id
}
func TestCoreAdoptionRestartsOwnedRuntime(t *testing.T) {
	a := initializedApp(t)
	if _, e := Run(context.Background(), a, platform.Request{Command: []string{"start"}}); e != nil {
		t.Fatal(e)
	}
	x, e := resolve(a, "")
	if e != nil {
		t.Fatal(e)
	}
	old := mustIdentity(t, a, x.Manager)
	b, e := os.ReadFile(x.Manager.Core.Binary)
	if e != nil {
		t.Fatal(e)
	}
	replacement := filepath.Join(filepath.Dir(x.Manager.Core.Binary), "replacement-core")
	if e = platform.AtomicWrite(replacement, b, 0700); e != nil {
		t.Fatal(e)
	}
	doc, e := Run(context.Background(), a, platform.Request{Command: []string{"core", "adopt"}, Options: map[string][]string{"path": {replacement}}})
	if e != nil || doc.Overall != "PASS" {
		t.Fatal(doc, e)
	}
	next, e := resolve(a, "")
	if e != nil {
		t.Fatal(e)
	}
	id := mustIdentity(t, a, next.Manager)
	if id.PID == old.PID || id.Exe != replacement || identityAlive(*old) {
		t.Fatal("runtime not replaced")
	}
}
func TestFailedCoreAdoptionRestoresPreviousRuntime(t *testing.T) {
	a := initializedApp(t)
	if _, e := Run(context.Background(), a, platform.Request{Command: []string{"start"}}); e != nil {
		t.Fatal(e)
	}
	m, e := loadManager(a)
	if e != nil {
		t.Fatal(e)
	}
	bad := filepath.Join(filepath.Dir(m.Core.Binary), "bad-core")
	script := "#!/bin/sh\ncase \"$1\" in\n-v) echo 'Mihomo Meta v1.19.33 linux amd64';;\n-t) exit 0;;\n*) exit 1;;\nesac\n"
	if e = platform.AtomicWrite(bad, []byte(script), 0700); e != nil {
		t.Fatal(e)
	}
	_, e = Run(context.Background(), a, platform.Request{Command: []string{"core", "adopt"}, Options: map[string][]string{"path": {bad}}})
	if e == nil {
		t.Fatal("bad core adopted")
	}
	next, e := loadManager(a)
	if e != nil || next.Core.Binary != m.Core.Binary {
		t.Fatal("manager not restored", e)
	}
	doc, e := Run(context.Background(), a, platform.Request{Command: []string{"health"}})
	if e != nil || doc.Overall != "PASS" {
		t.Fatal("old core not restored", doc, e)
	}
}
func TestResetRepairsStoppedMalformedConfig(t *testing.T) {
	a := initializedApp(t)
	m, e := loadManager(a)
	if e != nil {
		t.Fatal(e)
	}
	if e = platform.AtomicWrite(m.Core.Config, []byte("invalid: ["), 0600); e != nil {
		t.Fatal(e)
	}
	doc, e := Run(context.Background(), a, platform.Request{Command: []string{"reset"}, Options: map[string][]string{"dry-run": {}}})
	if e != nil {
		t.Fatal(e)
	}
	doc, e = Run(context.Background(), a, platform.Request{Command: []string{"reset"}, Options: map[string][]string{"apply": {}, "plan-sha256": {doc.Data["plan_sha256"].(string)}}})
	if e != nil || doc.Overall != "PASS" {
		t.Fatal(doc, e)
	}
	if _, e = resolve(a, ""); e != nil {
		t.Fatal(e)
	}
}
func TestHealthRejectsAnonymousProxyAndController(t *testing.T) {
	skipEmulatedKernel(t)
	a := testApp(t)
	id, e := inspectIdentity(os.Getpid())
	if e != nil {
		t.Fatal(e)
	}
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	server := http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })}
	defer server.Close()
	go server.Serve(l)
	ep := endpoint{Name: "insecure", Type: "http", Address: "127.0.0.1", Port: l.Addr().(*net.TCPAddr).Port, Users: []credentials{{"u", "p"}}}
	x := resolved{Name: "default", Profile: defaults(profile{}), Endpoints: []endpoint{ep}, Controller: &ep, Config: map[string]any{"secret": strings.Repeat("s", 64)}}
	doc, e := healthResolved(context.Background(), a, x, &id)
	if e != nil || doc.Overall != "FAIL" {
		t.Fatal("insecure server accepted", doc, e)
	}
	failures := map[string]bool{}
	for _, c := range doc.Checks {
		if c.Status == "FAIL" {
			failures[c.Name] = true
		}
	}
	if !failures["auth-anon-insecure"] || !failures["controller"] {
		t.Fatal(doc.Checks)
	}
}

func TestExportsWritePrivateFilesAndLogsTail(t *testing.T) {
	a := initializedApp(t)
	output := filepath.Join(a.Scope.ConfigRoot, "exports", "proxy.env")
	doc, e := Run(context.Background(), a, platform.Request{Command: []string{"env", "export"}, Options: map[string][]string{"output": {output}}})
	if e != nil || doc.Overall != "PASS" {
		t.Fatal(doc, e)
	}
	st, e := os.Stat(output)
	if e != nil || st.Mode().Perm() != 0600 {
		t.Fatal(st, e)
	}
	b, e := platform.ReadPrivate(output)
	if e != nil || !strings.Contains(string(b), "ALL_PROXY=socks5h://") {
		t.Fatal(string(b), e)
	}
	m, e := loadManager(a)
	if e != nil {
		t.Fatal(e)
	}
	m.Bindings = map[string]binding{"consumer": {Profile: "default", Adapter: "ci"}}
	if e = platform.WriteYAML(a.Scope.ManagerPath(), m); e != nil {
		t.Fatal(e)
	}
	outdir := filepath.Join(a.Scope.ConfigRoot, "exports", "ci")
	doc, e = Run(context.Background(), a, platform.Request{Command: []string{"integration", "export"}, Args: []string{"consumer"}, Options: map[string][]string{"output-dir": {outdir}}})
	if e != nil || doc.Overall != "PASS" {
		t.Fatal(doc, e)
	}
	for _, p := range doc.Data["files"].([]string) {
		st, e := os.Stat(p)
		if e != nil || st.Mode().Perm() != 0600 {
			t.Fatal(st, e)
		}
	}
	log := filepath.Join(a.Scope.StateRoot, "logs", "mihomo.log")
	if e = platform.AtomicWrite(log, []byte("line1\nline2\nline3\n"), 0600); e != nil {
		t.Fatal(e)
	}
	doc, e = Run(context.Background(), a, platform.Request{Command: []string{"logs"}, Options: map[string][]string{"lines": {"2"}}})
	if e != nil || strings.Join(doc.Data["entries"].([]string), "\n") != "line2\nline3" {
		t.Fatal(doc, e)
	}
}
func TestRejectedInitPublishesNothing(t *testing.T) {
	a := initializedApp(t)
	m, e := loadManager(a)
	if e != nil {
		t.Fatal(e)
	}
	next := testApp(t)
	src := filepath.Join(next.Scope.ConfigRoot, "input.yaml")
	if e = platform.WriteYAML(src, map[string]any{"helper-reject": true}); e != nil {
		t.Fatal(e)
	}
	_, e = Run(context.Background(), next, platform.Request{Command: []string{"init"}, Options: map[string][]string{"core": {m.Core.Binary}, "config": {src}}})
	requireCode(t, e, "core-config-invalid")
	for _, p := range []string{next.Scope.ManagerPath(), filepath.Join(next.Scope.ConfigRoot, "mihomo", "config.yaml"), filepath.Join(next.Scope.ConfigRoot, "credentials", "default.yaml")} {
		if _, e = os.Lstat(p); !os.IsNotExist(e) {
			t.Fatal("failed init published", p)
		}
	}
}
