package routing

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"unicode"
	"unicode/utf8"
)

// limit mirrors the controller response cap (8 MiB).
const limit = 8 << 20

// testURL is the fixed public HTTPS probe target.
const testURL = "https://www.gstatic.com/generate_204"

// label validates a controller-provided display string: a scalar no longer
// than 512 runes without control or format characters.
func label(value any) (string, error) {
	s, ok := value.(string)
	if !ok || utf8.RuneCountInString(s) > 512 {
		return "", control("controller-response-invalid-label", exitUnverify)
	}
	for _, r := range s {
		if unicode.Is(unicode.Cf, r) || unicode.IsControl(r) {
			return "", control("controller-response-invalid-label", exitUnverify)
		}
	}
	return s, nil
}

// number validates a numeric controller value in [0, 2^63], returning an int
// whenever the value is integral so JSON output keeps the original shape.
func number(value any) (any, error) {
	f, ok := value.(float64)
	if !ok || f < 0 || f > math.Pow(2, 63) || math.IsNaN(f) {
		return nil, control("controller-response-invalid-number", exitUnverify)
	}
	if f == math.Trunc(f) && math.Abs(f) < 1e15 {
		return int(f), nil
	}
	return f, nil
}

var (
	schemePattern    = regexp.MustCompile(`(?i)[a-z][a-z0-9+.-]*://`)
	credentialWord   = regexp.MustCompile(`(?i)(password|secret|token|uuid|key)\s*[:=]`)
	userinfoPattern  = regexp.MustCompile(`[^\s:]+:[^\s@]+@`)
	nodeIdentitySeed = func() []byte {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			panic("controller entropy unavailable")
		}
		return b
	}()
)

// requestLabel redacts a request-supplied value that may itself be a private
// URL or credential-shaped string before it can reach an error envelope.
func requestLabel(value string) string {
	if len(value) > 512 || schemePattern.MatchString(value) || credentialWord.MatchString(value) || userinfoPattern.MatchString(value) {
		return "[redacted request]"
	}
	return value
}

// nodeIdentity is a per-process correlation key only; there is no public
// verifier for redacted material (mirrors controller_types.node_identity).
func nodeIdentity(name string, provider any) string {
	payload, _ := json.Marshal([]any{provider, name})
	mac := hmac.New(sha256.New, nodeIdentitySeed)
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

// objectRow pairs a JSON object key with its raw value while decoding, so the
// controller table order (which the original preserved via dict insertion
// order) survives into the payload.
type objectRow struct {
	Key   string
	Value json.RawMessage
}

// decodeObject decodes a JSON object keeping the wire order of its keys.
func decodeObject(raw []byte) ([]objectRow, map[string]json.RawMessage, error) {
	var rows []objectRow
	index := map[string]json.RawMessage{}
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return nil, nil, err
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return nil, nil, fmt.Errorf("not an object")
	}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, nil, err
		}
		key, ok := keyTok.(string)
		if !ok {
			return nil, nil, fmt.Errorf("bad key")
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, nil, err
		}
		rows = append(rows, objectRow{key, value})
		index[key] = value
	}
	if _, err := dec.Token(); err != nil {
		return nil, nil, err
	}
	return rows, index, nil
}

// fieldString reads a string field from a decoded raw object.
func fieldString(raw json.RawMessage) (string, bool) {
	if len(raw) == 0 {
		return "", false
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return "", false
	}
	return s, true
}

// fieldBool reads a bool field, distinguishing an explicit false from absence.
func fieldBool(raw json.RawMessage) (bool, bool) {
	if len(raw) == 0 {
		return false, false
	}
	var b bool
	if json.Unmarshal(raw, &b) != nil {
		return false, false
	}
	return b, true
}

// fieldNumber reads a numeric field as float64.
func fieldNumber(raw json.RawMessage) (float64, bool) {
	if len(raw) == 0 {
		return 0, false
	}
	var f float64
	if json.Unmarshal(raw, &f) != nil {
		return 0, false
	}
	return f, true
}

// hashSHA256 hex-digests content.
func hashSHA256(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}
