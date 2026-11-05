package routing

import (
	"strings"
	"testing"
)

func endpointConfig(controller, secret string) map[string]any {
	return map[string]any{"external-controller": controller, "secret": secret}
}

var strongSecret = "s" + strings.Repeat("k", 39)

func TestEndpointLoopbackContract(t *testing.T) {
	host, port, token, err := endpoint(endpointConfig("127.0.0.1:19090", strongSecret))
	if err != nil || host != "127.0.0.1" || port != 19090 || token != strongSecret {
		t.Fatalf("endpoint = %q %d %q %v", host, port, token, err)
	}
	host, _, _, err = endpoint(endpointConfig("[::1]:9090", strongSecret))
	if err != nil || host != "::1" {
		t.Fatalf("ipv6 loopback = %q %v", host, err)
	}
	host, _, _, err = endpoint(endpointConfig("localhost:9090", strongSecret))
	if err != nil || host != "127.0.0.1" {
		t.Fatalf("localhost = %q %v", host, err)
	}
}

func TestEndpointRejectsUnsafeControllers(t *testing.T) {
	_, _, _, err := endpoint(endpointConfig("0.0.0.0:9090", strongSecret))
	mustCode(t, err, "controller-not-configured-as-loopback")

	_, _, _, err = endpoint(endpointConfig("127.0.0.1:90", strongSecret))
	mustCode(t, err, "controller-not-configured-as-loopback")

	_, _, _, err = endpoint(endpointConfig("127.0.0.1:99999", strongSecret))
	mustCode(t, err, "controller-not-configured-as-loopback")

	_, _, _, err = endpoint(endpointConfig("", strongSecret))
	mustCode(t, err, "controller-not-configured-as-loopback")

	_, _, _, err = endpoint(endpointConfig("127.0.0.1:9090", "short"))
	mustCode(t, err, "controller-secret-must-be-32-to-256-url-safe-characters")

	_, _, _, err = endpoint(endpointConfig("127.0.0.1:9090", "has spaces and symbols!"))
	mustCode(t, err, "controller-secret-must-be-32-to-256-url-safe-characters")

	cfg := endpointConfig("127.0.0.1:9090", strongSecret)
	cfg["external-controller-tls"] = "127.0.0.1:9443"
	_, _, _, err = endpoint(cfg)
	mustCode(t, err, "additional-controller-listeners-not-supported")

	cfg = endpointConfig("127.0.0.1:9090", strongSecret)
	cfg["external-doh-server"] = "127.0.0.1:1053"
	_, _, _, err = endpoint(cfg)
	mustCode(t, err, "additional-controller-listeners-not-supported")
}

func TestAssertSecurityEnvelope(t *testing.T) {
	before := map[string]any{
		"external-controller": "127.0.0.1:9090",
		"secret":              strongSecret,
		"rules":               []any{"MATCH,DIRECT"},
	}
	if err := assertSecurityEnvelope(before, deepCopyMap(before)); err != nil {
		t.Fatalf("identical documents rejected: %v", err)
	}

	policyOnly := deepCopyMap(before)
	policyOnly["rules"] = []any{"MATCH,Proxy"}
	if err := assertSecurityEnvelope(before, policyOnly); err != nil {
		t.Fatalf("policy change rejected: %v", err)
	}

	changedSecret := deepCopyMap(before)
	changedSecret["secret"] = strings.Repeat("x", 40)
	if err := assertSecurityEnvelope(before, changedSecret); err == nil {
		t.Fatal("secret change accepted")
	} else {
		mustCode(t, err, "policy-envelope-violation")
	}

	addedTUN := deepCopyMap(before)
	addedTUN["tun"] = map[string]any{"enable": true}
	if err := assertSecurityEnvelope(before, addedTUN); err == nil {
		t.Fatal("added TUN accepted")
	} else {
		mustCode(t, err, "policy-envelope-violation")
	}

	removed := deepCopyMap(before)
	delete(removed, "external-controller")
	if err := assertSecurityEnvelope(before, removed); err == nil {
		t.Fatal("removed controller address accepted")
	} else {
		mustCode(t, err, "policy-envelope-violation")
	}
}

func TestValidateEndpointEnvelopeUserScope(t *testing.T) {
	base := func() map[string]any {
		return map[string]any{
			"external-controller": "127.0.0.1:9090",
			"secret":              strongSecret,
			"mixed-port":          7890,
			"authentication":      []any{"user:pass"},
		}
	}
	if err := validateEndpointEnvelope(base(), false, nil); err != nil {
		t.Fatalf("authenticated loopback listener rejected: %v", err)
	}

	// Unauthenticated proxy ports are refused in user scope.
	noAuth := base()
	delete(noAuth, "authentication")
	if err := validateEndpointEnvelope(noAuth, false, nil); err == nil {
		t.Fatal("unauthenticated mixed-port accepted")
	} else {
		mustCode(t, err, "config-invalid")
	}

	for key, value := range map[string]any{
		"allow-lan":          true,
		"redir-port":         7892,
		"tproxy-port":        7893,
		"skip-auth-prefixes": []any{"127.0.0.1"},
	} {
		cfg := base()
		cfg[key] = value
		if err := validateEndpointEnvelope(cfg, false, nil); err == nil {
			t.Errorf("%s accepted in user scope", key)
		} else {
			mustCode(t, err, "config-invalid")
		}
	}

	dnsListener := base()
	dnsListener["dns"] = map[string]any{"listen": "0.0.0.0:53"}
	if err := validateEndpointEnvelope(dnsListener, false, nil); err == nil {
		t.Fatal("public DNS listener accepted")
	} else {
		mustCode(t, err, "config-invalid")
	}

	tunEnabled := base()
	tunEnabled["tun"] = map[string]any{"enable": true}
	if err := validateEndpointEnvelope(tunEnabled, false, nil); err == nil {
		t.Fatal("user-scope TUN accepted")
	} else {
		mustCode(t, err, "config-invalid")
	}
}

func TestValidateEndpointEnvelopeListeners(t *testing.T) {
	cfg := map[string]any{
		"external-controller": "127.0.0.1:9090",
		"secret":              strongSecret,
		"listeners": []any{
			map[string]any{"name": "in", "type": "mixed", "listen": "127.0.0.1", "port": 7890,
				"users": []any{map[string]any{"username": "u", "password": "p"}}},
		},
	}
	if err := validateEndpointEnvelope(cfg, false, nil); err != nil {
		t.Fatalf("authenticated loopback listener rejected: %v", err)
	}

	// Without users an inbound listener is an open proxy.
	open := deepCopyMap(cfg)
	open["listeners"] = []any{
		map[string]any{"name": "in", "type": "mixed", "listen": "127.0.0.1", "port": 7890},
	}
	if err := validateEndpointEnvelope(open, false, nil); err == nil {
		t.Fatal("unauthenticated listener accepted")
	} else {
		mustCode(t, err, "config-invalid")
	}

	// tproxy is a system-scope capability only.
	tproxy := deepCopyMap(cfg)
	tproxy["listeners"] = []any{
		map[string]any{"name": "tp", "type": "tproxy", "listen": "127.0.0.1", "port": 7893},
	}
	if err := validateEndpointEnvelope(tproxy, false, nil); err == nil {
		t.Fatal("user-scope tproxy accepted")
	} else {
		mustCode(t, err, "config-invalid")
	}

	// Duplicate bind of the same address:port.
	duplicate := deepCopyMap(cfg)
	duplicate["listeners"] = []any{
		map[string]any{"name": "a", "type": "mixed", "listen": "127.0.0.1", "port": 7890,
			"users": []any{map[string]any{"username": "u", "password": "p"}}},
		map[string]any{"name": "b", "type": "mixed", "listen": "127.0.0.1", "port": 7890,
			"users": []any{map[string]any{"username": "u", "password": "p"}}},
	}
	if err := validateEndpointEnvelope(duplicate, false, nil); err == nil {
		t.Fatal("duplicate bind accepted")
	} else {
		mustCode(t, err, "config-invalid")
	}
}

func TestValidateEndpointEnvelopeSystemScopeAllowedAddresses(t *testing.T) {
	cfg := map[string]any{
		"external-controller": "127.0.0.1:9090",
		"secret":              strongSecret,
		"listeners": []any{
			map[string]any{"name": "lan", "type": "mixed", "listen": "192.0.2.10", "port": 7890,
				"users": []any{map[string]any{"username": "u", "password": "p"}}},
		},
	}
	allowed := []string{"192.0.2.10"}
	if err := validateEndpointEnvelope(cfg, true, allowed); err != nil {
		t.Fatalf("allowed LAN bind rejected: %v", err)
	}
	if err := validateEndpointEnvelope(cfg, true, nil); err == nil {
		t.Fatal("LAN bind without allowlist accepted")
	} else {
		mustCode(t, err, "config-invalid")
	}
	if err := validateEndpointEnvelope(cfg, false, allowed); err == nil {
		t.Fatal("LAN bind accepted in user scope even with allowlist")
	} else {
		mustCode(t, err, "config-invalid")
	}
}

func TestSameValueNumericCoercion(t *testing.T) {
	if !sameValue(300, float64(300)) {
		t.Fatal("YAML int != JSON float of the same value")
	}
	if !sameValue(float64(1), int(1)) {
		t.Fatal("float/int comparison asymmetric")
	}
	if sameValue(300, float64(300.5)) {
		t.Fatal("different numeric values compared equal")
	}
	if sameValue("300", 300) {
		t.Fatal("string compared equal to number")
	}
	if sameValue(nil, 0) {
		t.Fatal("nil compared equal to zero")
	}
}
