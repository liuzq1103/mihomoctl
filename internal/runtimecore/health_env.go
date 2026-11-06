package runtimecore

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

var proxyKeys = []string{"http_proxy", "https_proxy", "all_proxy", "no_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"}

func selectedProfile(a platform.App, r platform.Request) (string, error) {
	p := r.Get("profile")
	if b := r.Get("binding"); b != "" {
		if p != "" {
			return "", platform.Usage("profile-binding-conflict")
		}
		m, e := loadManager(a)
		if e != nil {
			return "", e
		}
		binding, ok := m.Bindings[b]
		if !ok {
			return "", platform.Usage("binding-unknown")
		}
		p = binding.Profile
	}
	return p, nil
}
func proxyURL(scheme string, ep endpoint, c credentials, host string) string {
	if host == "" {
		host = ep.Address
	}
	u := url.URL{Scheme: scheme, Host: net.JoinHostPort(strings.Trim(host, "[]"), fmt.Sprint(ep.Port)), User: url.UserPassword(c.Username, c.Password)}
	return u.String()
}
func environment(x resolved, host string) (map[string]string, error) {
	httpURL, socksURL := "", ""
	for _, ep := range x.Endpoints {
		if ep.Name == x.Profile.HTTP && ep.http() {
			httpURL = proxyURL("http", ep, x.Credentials, host)
		}
		if ep.Name == x.Profile.SOCKS && ep.socks() {
			socksURL = proxyURL("socks5h", ep, x.Credentials, host)
		}
	}
	if httpURL == "" || socksURL == "" {
		return nil, platform.Usage("profile-protocol-missing")
	}
	noProxy := strings.Join(defaults(x.Profile).NoProxy, ",")
	return map[string]string{"http_proxy": httpURL, "https_proxy": httpURL, "all_proxy": socksURL, "no_proxy": noProxy, "HTTP_PROXY": httpURL, "HTTPS_PROXY": httpURL, "ALL_PROXY": socksURL, "NO_PROXY": noProxy}, nil
}
func hideURL(s string) string {
	u, e := url.Parse(s)
	if e != nil {
		return "***"
	}
	if u.User != nil {
		return u.Scheme + "://***@" + u.Host
	}
	return s
}
func redactedEnvironment(x resolved, vars map[string]string) map[string]any {
	return map[string]any{"profile": x.Name, "http_proxy": hideURL(vars["http_proxy"]), "all_proxy": hideURL(vars["all_proxy"]), "no_proxy": vars["no_proxy"]}
}
func environmentCommand(a platform.App, r platform.Request) (platform.Envelope, error) {
	doc := platform.Document(r.Name(), a.Scope.Name, nil)
	p, e := selectedProfile(a, r)
	if e != nil {
		return doc, e
	}
	x, e := resolve(a, p)
	if e != nil {
		return doc, e
	}
	vars, e := environment(x, "")
	if e != nil {
		return doc, e
	}
	if r.Name() == "env-show" {
		if r.Has("reveal") {
			for k, v := range vars {
				doc.Data[k] = v
			}
		} else {
			doc.Data = redactedEnvironment(x, vars)
		}
		return doc, nil
	}
	if r.Has("reveal") == (r.Get("output") != "") {
		return doc, platform.Usage("export-output-or-reveal-required")
	}
	if r.Has("reveal") {
		doc.Data["environment"] = vars
		return doc, nil
	}
	path := r.Get("output")
	if !absolute(path) {
		return doc, platform.Usage("output-path-invalid")
	}
	var text strings.Builder
	for _, k := range proxyKeys {
		fmt.Fprintf(&text, "%s=%s\n", k, vars[k])
	}
	if e = platform.AtomicWrite(path, []byte(text.String()), 0600); e != nil {
		return doc, e
	}
	doc.Data = map[string]any{"output": path, "mode": "0600", "keys": sortedKeys(vars)}
	return doc, nil
}
func execute(ctx context.Context, a platform.App, r platform.Request) error {
	if len(r.Child) == 0 {
		return platform.Usage("child-required")
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	var vars map[string]string
	if r.Name() == "exec" {
		p, e := selectedProfile(a, r)
		if e != nil {
			return e
		}
		x, e := resolve(a, p)
		if e != nil {
			return e
		}
		h, e := healthResolved(ctx, a, x, nil)
		if e != nil {
			return e
		}
		if h.Overall != "PASS" {
			return platform.Fail("health-blocked")
		}
		vars, e = environment(x, "")
		if e != nil {
			return e
		}
	}
	return replaceProcess(r.Child, cleanEnvironment(false, vars))
}
func health(ctx context.Context, a platform.App, r platform.Request) (platform.Envelope, error) {
	p, e := selectedProfile(a, r)
	if e != nil {
		return platform.Envelope{}, e
	}
	x, e := resolve(a, p)
	if e != nil {
		return platform.Envelope{}, e
	}
	doc, e := healthResolved(ctx, a, x, nil)
	doc.Command = r.Name()
	if e != nil {
		return doc, e
	}
	if raw := r.Get("egress-url"); raw != "" {
		u, e := url.Parse(raw)
		if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
			return doc, platform.Usage("egress-url-invalid")
		}
		vars, e := environment(x, "")
		if e != nil {
			return doc, e
		}
		proxy, _ := url.Parse(vars["http_proxy"])
		tr := &http.Transport{Proxy: http.ProxyURL(proxy)}
		defer tr.CloseIdleConnections()
		client := &http.Client{Timeout: 10 * time.Second, Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		req, e := http.NewRequestWithContext(ctx, "HEAD", u.String(), nil)
		if e != nil {
			return doc, platform.Usage("egress-url-invalid")
		}
		resp, e := client.Do(req)
		ok := e == nil
		if resp != nil {
			resp.Body.Close()
		}
		addCheck(&doc, "egress", ok, "explicit HTTPS proxy probe")
	}
	return doc, nil
}
func healthResolved(ctx context.Context, a platform.App, x resolved, known *identity) (platform.Envelope, error) {
	doc := platform.Document("health", a.Scope.Name, map[string]any{"profile": x.Name})
	addCheck(&doc, "manager-config", true, "")
	id := known
	var e error
	if id == nil {
		id, e = runningIdentity(ctx, a, x.Manager)
	}
	if e != nil {
		return doc, e
	}
	running := id != nil && identityAlive(*id)
	addCheck(&doc, "runtime", running, "process identity checked")
	if !running {
		return doc, nil
	}
	timeout := time.Duration(defaults(x.Profile).Health.Timeout) * time.Second
	// Match the original five-second read allowance. Real Mihomo may spend
	// more than three seconds producing a local authenticated HEAD response.
	if timeout > 5*time.Second {
		timeout = 5 * time.Second
	}
	for _, ep := range x.Endpoints {
		owned := ownsListener(*id, ep)
		addCheck(&doc, "listener-"+ep.Name, owned, "socket belongs to managed process")
		if !owned {
			continue
		}
		if !ep.http() && !ep.socks() {
			continue
		}
		c := credentials{}
		if len(ep.Users) > 0 {
			c = ep.Users[0]
		}
		if hasCredential(ep, x.Credentials) {
			c = x.Credentials
		}
		if e = validateCredentials(c); e != nil {
			addCheck(&doc, "auth-"+ep.Name, false, "credentials required")
			continue
		}
		if ep.http() {
			anon := probeHTTP(ctx, ep, "", false, timeout)
			auth := probeHTTP(ctx, ep, "Basic "+base64.StdEncoding.EncodeToString([]byte(c.Username+":"+c.Password)), false, timeout)
			addCheck(&doc, "auth-anon-"+ep.Name, anon == 407, "anonymous request must return 407")
			addCheck(&doc, "auth-http-"+ep.Name, auth >= 200 && auth != 407, "authenticated request accepted")
		}
		if ep.socks() {
			addCheck(&doc, "auth-socks-anon-"+ep.Name, probeSOCKS(ctx, ep, nil, timeout), "anonymous SOCKS refused")
			addCheck(&doc, "auth-socks-"+ep.Name, probeSOCKS(ctx, ep, &c, timeout), "SOCKS username/password accepted")
		}
	}
	if x.Controller != nil {
		owned := ownsListener(*id, *x.Controller)
		addCheck(&doc, "controller-ownership", owned, "socket belongs to managed process")
		if owned {
			anon := probeHTTP(ctx, *x.Controller, "", true, timeout)
			auth := probeHTTP(ctx, *x.Controller, "Bearer "+platform.String(x.Config["secret"]), true, timeout)
			addCheck(&doc, "controller", anon == 401 && auth == 200, "anonymous 401 and authenticated 200 required")
		}
	}
	return doc, nil
}
func dialProbe(ctx context.Context, ep endpoint, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	c, e := d.DialContext(ctx, "tcp", ep.address())
	if e != nil {
		return nil, e
	}
	deadline := time.Now().Add(timeout)
	if v, ok := ctx.Deadline(); ok && v.Before(deadline) {
		deadline = v
	}
	if e = c.SetDeadline(deadline); e != nil {
		c.Close()
		return nil, e
	}
	return c, nil
}
func probeHTTP(ctx context.Context, ep endpoint, auth string, controller bool, timeout time.Duration) int {
	c, e := dialProbe(ctx, ep, timeout)
	if e != nil {
		return 0
	}
	defer c.Close()
	method, target, key := "HEAD", "http://127.0.0.1:9/", "Proxy-Authorization"
	if controller {
		method = "GET"
		target = "/version"
		key = "Authorization"
	}
	header := ""
	if auth != "" {
		header = key + ": " + auth + "\r\n"
	}
	if _, e = fmt.Fprintf(c, "%s %s HTTP/1.1\r\nHost: 127.0.0.1:9\r\n%sConnection: close\r\nProxy-Connection: close\r\n\r\n", method, target, header); e != nil {
		return 0
	}
	resp, e := http.ReadResponse(bufio.NewReader(io.LimitReader(c, 64<<10)), &http.Request{Method: method})
	if e != nil {
		return 0
	}
	resp.Body.Close()
	return resp.StatusCode
}
func probeSOCKS(ctx context.Context, ep endpoint, c *credentials, timeout time.Duration) bool {
	s, e := dialProbe(ctx, ep, timeout)
	if e != nil {
		return false
	}
	defer s.Close()
	greeting := []byte{5, 1, 0}
	if c != nil {
		greeting = []byte{5, 2, 0, 2}
	}
	if _, e = s.Write(greeting); e != nil {
		return false
	}
	reply := make([]byte, 2)
	if _, e = io.ReadFull(s, reply); e != nil || reply[0] != 5 {
		return false
	}
	if c == nil {
		return reply[1] == 255 || reply[1] == 2
	}
	if reply[1] != 2 || len(c.Username) > 255 || len(c.Password) > 255 {
		return false
	}
	b := append([]byte{1, byte(len(c.Username))}, []byte(c.Username)...)
	b = append(b, byte(len(c.Password)))
	b = append(b, []byte(c.Password)...)
	if _, e = s.Write(b); e != nil {
		return false
	}
	_, e = io.ReadFull(s, reply)
	return e == nil && reply[0] == 1 && reply[1] == 0
}
