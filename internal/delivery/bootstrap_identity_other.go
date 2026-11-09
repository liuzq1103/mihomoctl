//go:build !linux

package delivery

func bootstrapIdentity(p string) (bootstrapFile, error) {
	return bootstrapFile{}, usage("linux-required")
}

func publishBootstrapRoot(from, to string) error { return usage("linux-required") }

// publishRollback never fires where the exclusive rename is unavailable.
func publishRollback(e error) (string, bool) { return "", false }
