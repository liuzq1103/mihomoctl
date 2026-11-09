//go:build linux

package runtimecore

import (
	"context"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

// A socket table that cannot be read leaves the endpoint state unknown. The
// health check must say so: reporting a confirmed "not listening" would be a
// confirmation nobody observed.
func TestLinuxHealthReportsUnavailableListenerState(t *testing.T) {
	a := testApp(t)
	id, e := inspectIdentity(os.Getpid())
	if e != nil {
		t.Fatal(e)
	}
	// A port nothing listens on: the ownership proof fails, so the health
	// check falls back to the socket table.
	listener, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	ep := endpoint{Name: "proxy", Type: "http", Address: "127.0.0.1", Port: port}
	x := resolved{Name: "default", Profile: defaults(profile{}), Endpoints: []endpoint{ep}, Config: map[string]any{"secret": strings.Repeat("s", 64)}}

	original := procNetSocketTable
	defer func() { procNetSocketTable = original }()
	procNetSocketTable = func(name string) ([]byte, error) { return nil, os.ErrPermission }
	doc, e := healthResolved(context.Background(), a, x, &id)
	if e != nil {
		t.Fatal(e)
	}
	evidence, detail := checkEvidence(doc, "listener-proxy")
	if evidence != "unavailable" {
		t.Fatalf("evidence = %q detail = %q, want an unavailable observation", evidence, detail)
	}
	if strings.Contains(detail, "not listening") {
		t.Fatalf("an unreadable socket table was reported as a confirmed absence: %q", detail)
	}

	// A readable table confirms the absence.
	procNetSocketTable = original
	doc, e = healthResolved(context.Background(), a, x, &id)
	if e != nil {
		t.Fatal(e)
	}
	evidence, detail = checkEvidence(doc, "listener-proxy")
	if evidence != "confirmed" || !strings.Contains(detail, "not listening") {
		t.Fatalf("evidence = %q detail = %q, want a confirmed absence", evidence, detail)
	}
}

// checkEvidence returns the evidence level and detail of one named check.
func checkEvidence(doc platform.Envelope, name string) (string, string) {
	for _, check := range doc.Checks {
		if check.Name == name {
			return check.Evidence, check.Detail
		}
	}
	return "", ""
}
