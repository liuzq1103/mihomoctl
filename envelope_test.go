package main

import (
	"bytes"
	"testing"
)

func TestLimitWriterBoundsGrowth(t *testing.T) {
	var buf bytes.Buffer
	w := &limitWriter{buf: &buf, max: 8}
	if n, err := w.Write([]byte("1234567")); err != nil || n != 7 {
		t.Fatalf("write under the cap must succeed, got %d %v", n, err)
	}
	if _, err := w.Write([]byte("89")); err == nil {
		t.Fatal("a write past the cap must error so the child is killed early")
	}
	if !w.truncated {
		t.Fatal("truncated flag must be set")
	}
	if buf.Len() != 7 {
		t.Fatalf("buffer must keep only accepted bytes, got %d", buf.Len())
	}
}

func TestLimitWriterRejectsSingleOversizedWrite(t *testing.T) {
	var buf bytes.Buffer
	w := &limitWriter{buf: &buf, max: 4}
	if _, err := w.Write([]byte("12345678")); err == nil {
		t.Fatal("a single write larger than the cap must error immediately")
	}
	if buf.Len() != 0 {
		t.Fatalf("nothing may be buffered from a rejected write, got %d bytes", buf.Len())
	}
}

// Soft mode is for diagnostic streams (stderr): it keeps draining the child
// instead of failing a run that would otherwise succeed.
func TestLimitWriterSoftModeDiscardsPastCap(t *testing.T) {
	var buf bytes.Buffer
	w := &limitWriter{buf: &buf, max: 4, soft: true}
	if n, err := w.Write([]byte("12345678")); err != nil || n != 8 {
		t.Fatalf("soft write past the cap must absorb the bytes, got %d %v", n, err)
	}
	if !w.truncated {
		t.Fatal("truncated flag must still be set")
	}
	if buf.String() != "1234" {
		t.Fatalf("only the first max bytes may be buffered, got %q", buf.String())
	}
}
