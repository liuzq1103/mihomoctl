//go:build !linux

package main

import (
	"errors"
	"io"
	"os"
)

// The masked input is implemented for Linux, where the terminal attributes
// can be changed without another dependency. Everywhere else the console
// falls back to a normal read: a value that cannot be hidden must still be
// readable, and the operator is told that the input was not masked.

// errMaskedUnsupported is the reason a masked read is not available.
var errMaskedUnsupported = errors.New("masked-input-unsupported")

// readMaskedLine cannot mask the input on this platform.
func readMaskedLine(reader io.Reader, file *os.File) (string, error) {
	return "", errMaskedUnsupported
}

// isTerminal cannot be answered on this platform without another
// dependency, so the console never claims to mask anything.
func isTerminal(file *os.File) bool { return false }
