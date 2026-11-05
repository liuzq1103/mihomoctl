package runtimecore

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

var logUserinfo = regexp.MustCompile(`(?i)(https?|socks5h?)://[^\s/]+@`)
var logQuery = regexp.MustCompile(`(?i)([?&](?:token|key|secret|password|auth)=)[^\s&]+`)

const maxRawLogLine = 1 << 20

type logRedactor struct{ Protected []string }

func requestJSON(r platform.Request) bool { return r.JSON || r.Has("json") }
func makeLogRedactor(cfg map[string]any) logRedactor {
	values := map[string]bool{}
	var collect func(any, bool)
	collect = func(value any, sensitive bool) {
		switch v := value.(type) {
		case map[string]any:
			for key, item := range v {
				collect(item, sensitive || member(strings.ToLower(key), "password", "secret", "uuid", "private-key", "authentication", "url", "token"))
			}
		case []any:
			for _, item := range v {
				collect(item, sensitive)
			}
		case string:
			if sensitive && v != "" {
				values[v] = true
			}
		}
	}
	collect(cfg, false)
	out := sortedKeys(values)
	sort.SliceStable(out, func(i, j int) bool { return len(out[i]) > len(out[j]) })
	return logRedactor{out}
}
func (r logRedactor) line(raw string) string {
	raw = strings.ToValidUTF8(raw, "�")
	for _, value := range r.Protected {
		raw = strings.ReplaceAll(raw, value, "[redacted]")
	}
	raw = logUserinfo.ReplaceAllString(raw, "${1}://[redacted]@")
	raw = logQuery.ReplaceAllString(raw, "${1}[redacted]")
	var result strings.Builder
	count := 0
	for _, ch := range raw {
		if count >= 4096 {
			break
		}
		if unicode.IsControl(ch) {
			result.WriteByte(' ')
		} else {
			result.WriteRune(ch)
		}
		count++
	}
	return result.String()
}
func (r logRedactor) entries(raw []byte) []string {
	if len(raw) == 0 {
		return []string{}
	}
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		out = append(out, r.line(strings.TrimSuffix(line, "\r")))
	}
	return out
}

// Never emit an incomplete line: a credential, URL userinfo or query value can
// span arbitrary writes and journal pipe reads. Oversized raw lines are dropped
// as a whole instead of exposing an unredacted prefix or suffix.
type redactedLogStream struct {
	Writer    io.Writer
	Redactor  logRedactor
	Pending   []byte
	Oversized bool
}

func (s *redactedLogStream) Write(raw []byte) (int, error) {
	n := len(raw)
	for len(raw) > 0 {
		i := strings.IndexByte(string(raw), '\n')
		if i < 0 {
			if !s.Oversized {
				if len(s.Pending)+len(raw) > maxRawLogLine {
					s.Pending = nil
					s.Oversized = true
				} else {
					s.Pending = append(s.Pending, raw...)
				}
			}
			break
		}
		piece := raw[:i]
		if !s.Oversized && len(s.Pending)+len(piece) <= maxRawLogLine {
			s.Pending = append(s.Pending, piece...)
		} else {
			s.Pending = nil
			s.Oversized = true
		}
		if e := s.emit(); e != nil {
			return 0, e
		}
		raw = raw[i+1:]
	}
	return n, nil
}
func (s *redactedLogStream) emit() error {
	text := "[redacted oversized log entry]"
	if !s.Oversized {
		text = s.Redactor.line(strings.TrimSuffix(string(s.Pending), "\r"))
	}
	s.Pending = nil
	s.Oversized = false
	_, e := io.WriteString(s.Writer, text+"\n")
	return e
}
func (s *redactedLogStream) Flush() error {
	if len(s.Pending) > 0 || s.Oversized {
		return s.emit()
	}
	return nil
}

func logs(ctx context.Context, a platform.App, r platform.Request) (platform.Envelope, error) {
	return logsWithBackend(ctx, a, r, journalLogs, verifyLogBackend)
}
func verifyLogBackend(ctx context.Context, a platform.App, m manager) error {
	if m.Core.Backend == "systemd" {
		if e := requireOwnedUnit(a, m); e != nil {
			return e
		}
	}
	_, e := runningIdentity(ctx, a, m)
	return e
}
func logsWithBackend(ctx context.Context, a platform.App, r platform.Request, read journalReader, verify func(context.Context, platform.App, manager) error) (platform.Envelope, error) {
	doc := platform.Document(r.Name(), a.Scope.Name, nil)
	if r.Has("follow") && requestJSON(r) {
		return doc, platform.Usage("logs-follow-json")
	}
	if e := ctx.Err(); e != nil {
		return doc, e
	}
	n := 50
	if raw := r.Get("lines"); raw != "" {
		if _, e := fmt.Sscanf(raw, "%d", &n); e != nil || fmt.Sprint(n) != raw || n < 1 || n > 10000 {
			return doc, platform.Usage("logs-lines-invalid")
		}
	}
	x, e := resolve(a, "")
	if e != nil {
		return doc, e
	}
	redactor := makeLogRedactor(x.Config)
	if e = verify(ctx, a, x.Manager); e != nil {
		return doc, e
	}
	if r.Has("follow") && r.Output == nil {
		return doc, platform.Usage("output-required")
	}
	if x.Manager.Core.Backend == "systemd" {
		args := journalArguments(a.Scope.System, "", "", n, r.Has("follow"))
		raw, e := read(ctx, args, r, redactor)
		if e != nil {
			return doc, e
		}
		doc.Data["entries"] = redactor.entries(raw)
		return doc, nil
	}
	path := filepath.Join(a.Scope.StateRoot, "logs", "mihomo.log")
	if e = platform.CheckPath(path); e != nil {
		return doc, e
	}
	if _, e = os.Lstat(path); os.IsNotExist(e) {
		return doc, platform.Fail("logs-unavailable")
	}
	raw, start, e := readLogWindow(path)
	if e != nil {
		return doc, e
	}
	offset := start + int64(len(raw))
	if start > 0 {
		if i := strings.IndexByte(string(raw), '\n'); i >= 0 {
			raw = raw[i+1:]
		} else {
			raw = nil
		}
		doc.Data["truncated"] = true
	}
	entries := redactor.entries(raw)
	if len(entries) > n {
		entries = entries[len(entries)-n:]
	}
	doc.Data["entries"] = entries
	doc.Data["log"] = path
	if !r.Has("follow") {
		return doc, nil
	}
	stream := &redactedLogStream{Writer: r.Output, Redactor: redactor}
	complete := raw
	if len(raw) > 0 && raw[len(raw)-1] != '\n' {
		i := strings.LastIndexByte(string(raw), '\n')
		complete = raw[:i+1]
		stream.Pending = append(stream.Pending, raw[i+1:]...)
		if len(stream.Pending) > maxRawLogLine {
			stream.Pending = nil
			stream.Oversized = true
		}
	}
	lines := redactor.entries(complete)
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	for _, line := range lines {
		if _, e = io.WriteString(r.Output, line+"\n"); e != nil {
			return doc, e
		}
	}
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return doc, ctx.Err()
		case <-tick.C:
			raw, start, e = readLogWindow(path)
			if e != nil {
				return doc, e
			}
			if start+int64(len(raw)) < offset || offset < start {
				offset = start
				stream.Pending = nil
				stream.Oversized = true
			}
			if start+int64(len(raw)) > offset {
				if _, e = stream.Write(raw[offset-start:]); e != nil {
					return doc, e
				}
				offset = start + int64(len(raw))
			}
		}
	}
}
