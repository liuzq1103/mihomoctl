//go:build !linux && !windows

package routing

import "io"

// writerIsTerminal has no portable probe on this platform; the token command
// refuses rather than guess. It is a variable for test injection.
var writerIsTerminal = func(w io.Writer) bool { return false }
