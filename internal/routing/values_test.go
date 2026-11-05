package routing

import (
	"strings"
	"testing"
)

func TestLabelContract(t *testing.T) {
	if value, err := label("Node A"); err != nil || value != "Node A" {
		t.Fatalf("label = %q err = %v", value, err)
	}
	if _, err := label(42); err == nil {
		t.Fatal("non-string label accepted")
	}
	if _, err := label(nil); err == nil {
		t.Fatal("missing label accepted")
	}
	if _, err := label("bad\x1b[31m"); err == nil {
		t.Fatal("control character accepted")
	}
	if _, err := label(strings.Repeat("x", 513)); err == nil {
		t.Fatal("overlong label accepted")
	}
	if value, err := label(strings.Repeat("x", 512)); err != nil || value != strings.Repeat("x", 512) {
		t.Fatalf("512-rune label rejected: %v", err)
	}
}

func TestNumberContract(t *testing.T) {
	if value, err := number(float64(5)); err != nil || value != 5 {
		t.Fatalf("number(5) = %v %v", value, err)
	}
	if value, err := number(float64(1.5)); err != nil || value != 1.5 {
		t.Fatalf("number(1.5) = %v %v", value, err)
	}
	for _, bad := range []any{-1, "5", nil, true} {
		if _, err := number(bad); err == nil {
			t.Fatalf("number(%v) accepted", bad)
		}
	}
}

func TestRequestLabelRedaction(t *testing.T) {
	cases := map[string]string{
		"https://user:pass@example.com/": "[redacted request]",
		"http://example.com/?token=x":    "[redacted request]",
		"secret: value":                  "[redacted request]",
		"plain node name":                "plain node name",
		"中文节点":                           "中文节点",
	}
	for input, want := range cases {
		if got := requestLabel(input); got != want {
			t.Errorf("requestLabel(%q) = %q want %q", input, got, want)
		}
	}
	if got := requestLabel(strings.Repeat("x", 513)); got != "[redacted request]" {
		t.Errorf("overlong request label = %q", got)
	}
}

func TestNodeIdentityDeterministic(t *testing.T) {
	first := nodeIdentity("Node A", nil)
	second := nodeIdentity("Node A", nil)
	other := nodeIdentity("Node A", "provider / fixture")
	if first != second {
		t.Fatal("identity is not deterministic")
	}
	if first == other {
		t.Fatal("provider identity collision")
	}
	if strings.Contains(first, "Node A") {
		t.Fatal("identity leaks the node name")
	}
}

func TestDecodeObjectPreservesOrder(t *testing.T) {
	rows, index, err := decodeObject([]byte(`{"b":1,"a":{"z":2,"y":3},"c":4}`))
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, row := range rows {
		keys = append(keys, row.Key)
	}
	if strings.Join(keys, ",") != "b,a,c" {
		t.Fatalf("order = %v", keys)
	}
	if len(index) != 3 {
		t.Fatalf("index size = %d", len(index))
	}
	if _, _, err := decodeObject([]byte(`[1,2]`)); err == nil {
		t.Fatal("non-object accepted")
	}
}
