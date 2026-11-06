package runtimecore

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

// Journal is the private console/history API. It never queries any unit other
// than this scope's owned runtime. Process history requires parseable log
// timestamps when a time filter is requested; it never silently ignores one.
func Journal(ctx context.Context, a platform.App, since, until string, lines int) (platform.Envelope, error) {
	return journalWith(ctx, a, since, until, lines, journalLogs)
}

type journalReader func(context.Context, []string, platform.Request, logRedactor) ([]byte, error)

func journalArguments(system bool, since, until string, lines int, follow bool) []string {
	args := []string{"-u", unitName, "--no-pager", "-n", fmt.Sprint(lines)}
	if !system {
		args = append([]string{"--user"}, args...)
	}
	if since != "" {
		args = append(args, "--since="+since)
	}
	if until != "" {
		args = append(args, "--until="+until)
	}
	if follow {
		args = append(args, "-f")
	}
	return args
}

func validJournalTime(s string) bool {
	return len(s) <= 128 && utf8.ValidString(s) && !strings.ContainsFunc(s, unicode.IsControl)
}
func journalWith(ctx context.Context, a platform.App, since, until string, lines int, read journalReader) (platform.Envelope, error) {
	return journalWithBackend(ctx, a, since, until, lines, read, verifyLogBackend)
}
func journalWithBackend(ctx context.Context, a platform.App, since, until string, lines int, read journalReader, verify func(context.Context, platform.App, manager) error) (platform.Envelope, error) {
	doc := platform.Document("journal", a.Scope.Name, map[string]any{"entries": []string{}, "since": since, "until": until})
	fail := func(e error) (platform.Envelope, error) { return platform.Failure("journal", a.Scope.Name, e), e }
	if lines < 1 || lines > 10000 {
		return fail(platform.Usage("logs-lines-invalid"))
	}
	if !validJournalTime(since) || !validJournalTime(until) {
		return fail(platform.Usage("logs-time-invalid"))
	}
	if e := ctx.Err(); e != nil {
		return fail(e)
	}
	if e := pendingRecovery(a); e != nil {
		return fail(e)
	}
	x, e := resolve(a, "")
	if e != nil {
		return fail(e)
	}
	redactor, e := resolvedLogRedactor(x)
	if e != nil {
		return fail(e)
	}
	if e = verify(ctx, a, x.Manager); e != nil {
		return fail(e)
	}
	if x.Manager.Core.Backend == "systemd" {
		args := journalArguments(a.Scope.System, since, until, lines, false)
		raw, e := read(ctx, args, platform.Request{}, redactor)
		if e != nil {
			return fail(e)
		}
		doc.Data["entries"] = redactor.entries(raw)
	} else {
		path := filepath.Join(a.Scope.StateRoot, "logs", "mihomo.log")
		if _, e = os.Lstat(path); os.IsNotExist(e) {
			return fail(platform.Fail("logs-unavailable"))
		}
		raw, start, e := readLogWindow(path)
		if e != nil {
			return fail(e)
		}
		if start > 0 {
			if i := strings.IndexByte(string(raw), '\n'); i >= 0 {
				raw = raw[i+1:]
			} else {
				raw = nil
			}
			doc.Data["truncated"] = true
		}
		entries, e := filterProcessHistory(raw, since, until, lines, time.Now())
		if e != nil {
			return fail(e)
		}
		clean := make([]string, 0, len(entries))
		for _, entry := range entries {
			clean = append(clean, redactor.line(entry))
		}
		doc.Data["entries"] = clean
		doc.Data["log"] = path
	}
	if e = pendingRecovery(a); e != nil {
		return fail(e)
	}
	return doc, nil
}

var relativeLogTime = regexp.MustCompile(`^(-?\d+)\s*(s|sec|seconds?|m|min|minutes?|h|hours?|d|days?|w|weeks?)(?:\s+ago)?$`)
var embeddedLogTime = regexp.MustCompile(`(?:^|\s)time="?([^"\s]+)`)

func parseHistoryBound(s string, now time.Time) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	switch strings.ToLower(s) {
	case "now":
		return now, nil
	case "today":
		return time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location()), nil
	case "yesterday":
		return time.Date(now.Year(), now.Month(), now.Day()-1, 0, 0, 0, 0, now.Location()), nil
	}
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05", "2006-01-02"} {
		if parsed, e := time.ParseInLocation(layout, s, now.Location()); e == nil {
			return parsed, nil
		}
	}
	if match := relativeLogTime.FindStringSubmatch(strings.ToLower(strings.TrimSpace(s))); match != nil {
		count, e := strconv.ParseInt(match[1], 10, 32)
		if e != nil {
			return time.Time{}, platform.Usage("logs-time-invalid")
		}
		unit := time.Second
		switch match[2][0] {
		case 'm':
			unit = time.Minute
		case 'h':
			unit = time.Hour
		case 'd':
			unit = 24 * time.Hour
		case 'w':
			unit = 7 * 24 * time.Hour
		}
		if count > 100000 || count < -100000 {
			return time.Time{}, platform.Usage("logs-time-invalid")
		}
		delta := time.Duration(count) * unit
		if strings.HasSuffix(strings.ToLower(strings.TrimSpace(s)), "ago") && delta > 0 {
			delta = -delta
		}
		return now.Add(delta), nil
	}
	return time.Time{}, platform.Usage("logs-time-filter-unavailable")
}
func logTimestamp(line string) (time.Time, bool) {
	if match := embeddedLogTime.FindStringSubmatch(line); match != nil {
		if parsed, e := time.Parse(time.RFC3339Nano, match[1]); e == nil {
			return parsed, true
		}
	}
	fields := strings.Fields(line)
	if len(fields) > 0 {
		first := strings.Trim(fields[0], "[]")
		if parsed, e := time.Parse(time.RFC3339Nano, first); e == nil {
			return parsed, true
		}
	}
	if len(line) >= 19 {
		if parsed, e := time.ParseInLocation("2006-01-02 15:04:05", line[:19], time.Local); e == nil {
			return parsed, true
		}
	}
	return time.Time{}, false
}
func filterProcessHistory(raw []byte, since, until string, n int, now time.Time) ([]string, error) {
	lower, e := parseHistoryBound(since, now)
	if e != nil {
		return nil, e
	}
	upper, e := parseHistoryBound(until, now)
	if e != nil {
		return nil, e
	}
	if !lower.IsZero() && !upper.IsZero() && lower.After(upper) {
		return nil, platform.Usage("logs-time-invalid")
	}
	out := []string{}
	if len(raw) == 0 {
		return out, nil
	}
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if since != "" || until != "" {
			timestamp, ok := logTimestamp(line)
			if !ok {
				return nil, platform.Usage("logs-time-filter-unavailable")
			}
			if !lower.IsZero() && timestamp.Before(lower) || !upper.IsZero() && timestamp.After(upper) {
				continue
			}
		}
		out = append(out, line)
	}
	if len(out) > n {
		out = out[len(out)-n:]
	}
	return out, nil
}
