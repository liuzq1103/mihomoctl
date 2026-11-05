package routing

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"
)

// client talks to the local controller API. Requests are pinned to the
// configured loopback address, ignore every proxy environment variable,
// never follow redirects, use a fixed 8-second timeout and cap response
// bodies at 8 MiB — the original Client contract.
type client struct {
	address string
	port    int
	token   string
	http    *http.Client
	// runtime, when non-nil, is consulted by Verify so a foreign or mock
	// listener can never be treated as the managed controller.
	runtime *runtimeOwner
}

func newClient(address string, port int, token string) *client {
	transport := &http.Transport{
		// Never consult proxy variables or system proxy settings; the
		// controller is always reached directly on loopback.
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ip := net.ParseIP(host)
			if ip == nil || !(ip.IsLoopback()) {
				return nil, errors.New("controller-address-must-be-loopback")
			}
			dialer := &net.Dialer{Timeout: 8 * time.Second}
			return dialer.DialContext(ctx, network, addr)
		},
		DisableKeepAlives: true,
	}
	return &client{
		address: address,
		port:    port,
		token:   token,
		http: &http.Client{
			Transport: transport,
			Timeout:   8 * time.Second,
			// Redirects are never a capability: surface the 3xx response so
			// it fails exactly like http.client did.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (c *client) base() string {
	return "http://" + net.JoinHostPort(c.address, strconv.Itoa(c.port))
}

type requestOptions struct {
	method      string
	body        any
	anonymous   bool
	optional    bool
	statusCodes map[int]string
}

// request performs one controller API call. The returned raw map preserves
// nothing about key order (callers that need order use requestOrdered).
func (c *client) request(ctx context.Context, path string, opts requestOptions) (map[string]any, error) {
	raw, err := c.requestRaw(ctx, path, opts)
	if err != nil {
		return nil, err
	}
	value := map[string]any{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &value); err != nil {
			return nil, control("controller-response-invalid", exitUnverify)
		}
	}
	return value, nil
}

// requestOrdered returns the raw body bytes; callers decode ordered objects.
func (c *client) requestRaw(ctx context.Context, path string, opts requestOptions) ([]byte, error) {
	method := opts.method
	if method == "" {
		method = "GET"
	}
	var reader io.Reader
	if opts.body != nil {
		raw, err := json.Marshal(opts.body)
		if err != nil {
			return nil, control("controller-response-invalid", exitUnverify)
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base()+path, reader)
	if err != nil {
		return nil, control("controller-response-invalid", exitUnverify)
	}
	if !opts.anonymous {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if opts.body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, control("controller-unreachable", exitFail)
	}
	defer resp.Body.Close()
	if opts.anonymous {
		if resp.StatusCode != http.StatusUnauthorized {
			return nil, control("controller-authentication-not-enforced", exitFail)
		}
		return nil, nil
	}
	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return nil, control("controller-authentication-failed", exitFail)
	case opts.optional && (resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed || resp.StatusCode == http.StatusNotImplemented):
		return nil, control("controller-capability-unsupported", exitUnverify)
	case resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent:
		if code, ok := opts.statusCodes[resp.StatusCode]; ok {
			// The original raises every status-mapped failure with rc=1.
			return nil, control(code, exitFail)
		}
		return nil, control("controller-request-failed", exitFail)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, control("controller-response-invalid", exitUnverify)
	}
	if len(raw) > limit {
		return nil, control("controller-response-too-large", exitUnverify)
	}
	return raw, nil
}

// requestFirstLine reads exactly the first JSON line of a streaming endpoint.
func (c *client) requestFirstLine(ctx context.Context, path string, opts requestOptions) ([]byte, error) {
	opts2 := opts
	opts2.method = "GET"
	req, err := http.NewRequestWithContext(ctx, "GET", c.base()+path, nil)
	if err != nil {
		return nil, control("controller-response-invalid", exitUnverify)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, control("controller-unreachable", exitFail)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, control("controller-authentication-failed", exitFail)
	}
	if opts.optional && (resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed || resp.StatusCode == http.StatusNotImplemented) {
		return nil, control("controller-capability-unsupported", exitUnverify)
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return nil, control("controller-request-failed", exitFail)
	}
	line, err := readLineLimited(resp.Body)
	if err != nil {
		return nil, err
	}
	return line, nil
}

// readLineLimited reads one newline-terminated line capped at limit bytes.
func readLineLimited(r io.Reader) ([]byte, error) {
	var buf []byte
	scratch := make([]byte, 1)
	for {
		n, err := r.Read(scratch)
		if n > 0 {
			buf = append(buf, scratch[0])
			if scratch[0] == '\n' || len(buf) > limit {
				break
			}
		}
		if err != nil {
			if err == io.EOF && len(buf) > 0 {
				break
			}
			return nil, control("controller-response-invalid", exitUnverify)
		}
	}
	if len(buf) > limit {
		return nil, control("controller-response-too-large", exitUnverify)
	}
	return bytes.TrimRight(buf, "\r\n"), nil
}

// verify proves the controller session before any credential-bearing call:
// ownership of the loopback listener (when the runtime is observable), the
// anonymous 401 contract, then the authorized /version probe.
func (c *client) verify(ctx context.Context) error {
	if c.runtime != nil {
		if err := c.runtime.requireOwner(ctx, c.address, c.port); err != nil {
			return err
		}
	}
	if _, err := c.request(ctx, "/version", requestOptions{anonymous: true}); err != nil {
		return err
	}
	_, err := c.request(ctx, "/version", requestOptions{})
	return err
}

var _ = fmt.Sprintf
