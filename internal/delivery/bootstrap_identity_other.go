//go:build !linux

package delivery

var bootstrapIdentity = func(p string) (bootstrapFile, error) {
	return bootstrapFile{}, usage("linux-required")
}

func publishBootstrapRoot(from, to string) error { return usage("linux-required") }

// publishRollback never fires where the exclusive rename is unavailable.
func publishRollback(e error) (string, bool) { return "", false }

// linkRollback never fires where the launcher link is unavailable.
func linkRollback(e error) (string, bool) { return "", false }

// bootstrapLink is never reached where publication itself is refused.
var bootstrapLink = func(oldname, newname string) error { return usage("linux-required") }
