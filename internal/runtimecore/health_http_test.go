package runtimecore

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Real Mihomo interprets proxy connection persistence independently of the
// ordinary Connection header. A short-lived local health probe must explicitly
// close both, or an authenticated HEAD can wait until the read deadline.
func TestHTTPHealthRequiresProxyConnectionClose(t *testing.T) {
	for _, controller := range []bool{false, true} {
		name := "proxy"
		if controller {
			name = "controller"
		}
		t.Run(name, func(t *testing.T) {
			listener, e := net.Listen("tcp4", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			defer listener.Close()
			host, port, _ := net.SplitHostPort(listener.Addr().String())
			number, _ := strconv.Atoi(port)
			ep := endpoint{Address: host, Port: number}
			requests := make(chan *http.Request, 2)
			done := make(chan struct{})
			go func() {
				defer close(done)
				for i := 0; i < 2; i++ {
					conn, e := listener.Accept()
					if e != nil {
						return
					}
					conn.SetDeadline(time.Now().Add(2 * time.Second))
					req, e := http.ReadRequest(bufio.NewReader(conn))
					if e != nil {
						conn.Close()
						return
					}
					requests <- req
					code := http.StatusProxyAuthRequired
					auth := req.Header.Get("Proxy-Authorization")
					if controller {
						code = http.StatusUnauthorized
						auth = req.Header.Get("Authorization")
					}
					if req.Header.Get("Connection") != "close" || req.Header.Get("Proxy-Connection") != "close" {
						code = http.StatusBadRequest
					} else if auth != "" {
						code = http.StatusBadGateway
						if controller {
							code = http.StatusOK
						}
					}
					fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", code, http.StatusText(code))
					conn.Close()
				}
			}()
			token := "Basic " + base64.StdEncoding.EncodeToString([]byte("health-user:health-password"))
			anonWant, authWant := 407, 502
			if controller {
				token = "Bearer " + strings.Repeat("s", 64)
				anonWant, authWant = 401, 200
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if got := probeHTTP(ctx, ep, "", controller, time.Second); got != anonWant {
				t.Fatalf("anonymous health status %d, want %d", got, anonWant)
			}
			if got := probeHTTP(ctx, ep, token, controller, time.Second); got != authWant {
				t.Fatalf("authenticated health status %d, want %d", got, authWant)
			}
			for i := 0; i < 2; i++ {
				select {
				case req := <-requests:
					if req.Header.Get("Proxy-Connection") != "close" {
						t.Fatal("missing proxy-specific close header")
					}
					if controller {
						if req.Method != "GET" || req.RequestURI != "/version" {
							t.Fatal("wrong controller health request")
						}
					} else if req.Method != "HEAD" || req.RequestURI != "http://127.0.0.1:9/" {
						t.Fatal("health probe must target only the local closed port")
					}
				case <-ctx.Done():
					t.Fatal("health request not observed")
				}
			}
			<-done
		})
	}
}
