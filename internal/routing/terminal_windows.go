//go:build windows

package routing

import (
	"io"
	"os"
	"syscall"
	"unsafe"
)

var kernel32 = syscall.NewLazyDLL("kernel32.dll")
var getConsoleMode = kernel32.NewProc("GetConsoleMode")

// writerIsTerminal reports whether the output is an interactive console. It
// is a variable so tests can exercise the terminal path without a real
// console.
var writerIsTerminal = func(w io.Writer) bool {
	file, ok := w.(*os.File)
	if !ok {
		return false
	}
	var mode uint32
	ret, _, _ := getConsoleMode.Call(file.Fd(), uintptr(unsafe.Pointer(&mode)))
	return ret != 0
}
