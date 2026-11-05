//go:build linux

package routing

import (
	"io"
	"os"
	"syscall"
	"unsafe"
)

// writerIsTerminal reports whether the output is a character device, the
// "private terminal" the token command requires. It is a variable so tests
// can exercise the terminal path without a real pty.
var writerIsTerminal = func(w io.Writer) bool {
	file, ok := w.(*os.File)
	if !ok {
		return false
	}
	var state [64]byte
	_, _, errno := syscall.Syscall6(syscall.SYS_IOCTL, file.Fd(), syscall.TCGETS,
		uintptr(unsafe.Pointer(&state[0])), 0, 0, 0)
	return errno == 0
}
