package runtimecore

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

// TestSystemdPathValueQuotesOnlyWhatNeedsIt pins the rendering of a path
// for a systemd path-list setting: a plain path stays untouched, a path that
// systemd would split on is quoted as one word, and a path that cannot be
// expressed at all is refused.
func TestSystemdPathValueQuotesOnlyWhatNeedsIt(t *testing.T) {
	plain, e := systemdPathValue("/var/lib/mihomoctl-go/cores/v1/mihomo")
	if e != nil {
		t.Fatal(e)
	}
	if plain != "/var/lib/mihomoctl-go/cores/v1/mihomo" {
		t.Fatalf("plain path = %q", plain)
	}
	spaced, e := systemdPathValue("/var/lib/mihomoctl-go/cores/reviewed core/mihomo")
	if e != nil {
		t.Fatal(e)
	}
	if spaced != `"/var/lib/mihomoctl-go/cores/reviewed core/mihomo"` {
		t.Fatalf("spaced path = %q", spaced)
	}
	if _, e = systemdPathValue("/var/lib/mihomoctl-go/cores/re\"viewed/mihomo"); e == nil {
		t.Fatal("a path with a quote was accepted")
	}
	if _, e = systemdPathValue("/var/lib/mihomoctl-go/cores/re\tviewed/mihomo"); e == nil {
		t.Fatal("a path with a tab was accepted")
	}
}

// TestSystemdUnitQuotesSpacedPaths pins the unit text for a core path that
// contains a space. systemd splits a path list on whitespace, so the
// destination has to be quoted; quoting the whole "source:destination" pair
// would hide the separator, so each side is quoted on its own.
func TestSystemdUnitQuotesSpacedPaths(t *testing.T) {
	a, m := fixture(t)
	a.Scope.System = true
	m.Core.Backend = "systemd"
	m.Core.Binary = filepath.Join(a.Scope.DataRoot, "cores", "reviewed core", "mihomo")
	unit, e := unitText(a, m)
	if e != nil {
		t.Fatal(e)
	}
	stagedPath := filepath.Join(a.Scope.DataRoot, "service-binary", "mihomo")
	staged, e := systemdPathValue(stagedPath)
	if e != nil {
		t.Fatal(e)
	}
	published, e := systemdPathValue(m.Core.Binary)
	if e != nil {
		t.Fatal(e)
	}
	want := "BindReadOnlyPaths=" + staged + ":" + published
	if !strings.Contains(unit, want) {
		t.Fatalf("unit does not carry %q:\n%s", want, unit)
	}
	if !strings.HasPrefix(published, `"`) || !strings.HasSuffix(published, `"`) {
		t.Fatalf("a path with a space was not quoted: %q", published)
	}
	// No path-list value may carry a raw space outside quotes: systemd would
	// split it and the mount would not be established.
	for _, line := range strings.Split(unit, "\n") {
		if !strings.HasPrefix(line, "BindReadOnlyPaths=") && !strings.HasPrefix(line, "BindPaths=") &&
			!strings.HasPrefix(line, "ReadWritePaths=") && !strings.HasPrefix(line, "TemporaryFileSystem=") {
			continue
		}
		quoted := false
		for _, r := range line {
			switch r {
			case '"':
				quoted = !quoted
			case ' ':
				if !quoted {
					t.Fatalf("path list value carries a raw space: %q", line)
				}
			}
		}
	}
}

// TestOwnedUnitRecognizesTheLegacyRendering pins ownership across the
// rendering change: a unit file an earlier development build of this project
// wrote — the whole "source:destination" pair quoted as one — is still ours
// for the manager it was written for, so an upgrade across development builds
// keeps managing and can uninstall the service it installed. A foreign edit
// of either rendering is still refused.
func TestOwnedUnitRecognizesTheLegacyRendering(t *testing.T) {
	a, m := fixture(t)
	a.Scope.System = true
	m.Core.Backend = "systemd"
	m.Core.Binary = filepath.Join(a.Scope.DataRoot, "cores", "reviewed core", "mihomo")
	current, e := unitText(a, m)
	if e != nil {
		t.Fatal(e)
	}
	legacy := legacyUnitText(a, m)
	if legacy == current {
		t.Fatal("the fixture renders both generations identically; the pin is vacuous")
	}
	if e := requireOwnedUnitText(a, m, current); e != nil {
		t.Fatal(e)
	}
	if e := requireOwnedUnitText(a, m, legacy); e != nil {
		t.Fatal(e)
	}
	foreign := strings.Replace(legacy, "RestartSec=3", "RestartSec=4", 1)
	if e := requireOwnedUnitText(a, m, foreign); e == nil {
		t.Fatal("a foreign edit of the legacy rendering was accepted as ours")
	}
}

// TestSystemdUnitKeepsPercentLiteralInPathLists pins the percent handling
// of the generated unit. systemd expands specifiers in the command line
// settings, and an unknown specifier makes the unit fail to load, so the
// command line escapes a percent sign as "%%". The path-list settings do not
// expand specifiers at all (verified on systemd 249 and 255: the mount source
// is the literal path), so a percent sign in a managed path stays literal
// there. Escaping it would point the mount at a directory named "%%".
func TestSystemdUnitKeepsPercentLiteralInPathLists(t *testing.T) {
	a, m := fixture(t)
	a.Scope.System = true
	m.Core.Backend = "systemd"
	m.Core.Binary = filepath.Join(a.Scope.DataRoot, "cores", "100%", "mihomo")
	unit, e := unitText(a, m)
	if e != nil {
		t.Fatal(e)
	}
	published, e := systemdPathValue(m.Core.Binary)
	if e != nil {
		t.Fatal(e)
	}
	staged, e := systemdPathValue(stagedServiceBinary(a))
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(published, "100%") {
		t.Fatalf("the rendered path lost its percent sign: %q", published)
	}
	if strings.Contains(published, "%%") {
		t.Fatalf("the rendered path escaped its percent sign: %q", published)
	}
	if !strings.Contains(unit, "BindReadOnlyPaths="+staged+":"+published) {
		t.Fatalf("unit does not carry the literal path:\n%s", unit)
	}
	// The command line expands specifiers, so the percent is escaped there.
	if !strings.Contains(unit, "ExecStart="+quoteUnit(m.Core.Binary)) {
		t.Fatalf("unit does not carry the escaped command line:\n%s", unit)
	}
}

// stagedServiceBinary is the private copy of the core the unit binds.
func stagedServiceBinary(a platform.App) string {
	return filepath.Join(a.Scope.DataRoot, "service-binary", "mihomo")
}

// TestSystemdUnitRefusesUnrepresentablePath pins the refusal of a path
// that systemd cannot express in a path list: the unit is never written
// with a path that would make the service impossible to start.
func TestSystemdUnitRefusesUnrepresentablePath(t *testing.T) {
	a, m := fixture(t)
	a.Scope.System = true
	m.Core.Backend = "systemd"
	m.Core.Binary = filepath.Join(a.Scope.DataRoot, "cores", "re\"viewed", "mihomo")
	if _, e := unitText(a, m); e == nil {
		t.Fatal("a path that cannot be expressed was accepted")
	}
}
