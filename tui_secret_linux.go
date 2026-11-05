//go:build linux

package main

import (
	"io"
	"os"
	"syscall"
	"unsafe"
)

// The masked input helpers exist for one reason: a subscription URL must not
// end up on the screen or in the scrollback.
//
// The terminal attribute is the only portable way to hide what the operator
// types; the line itself is still read from the same reader, so a value that
// was typed before the switch stays in the stream instead of being lost.

// readMaskedLine reads one line with the terminal echo switched off.
//
// The reader keeps the bytes it already read, so the masked line cannot
// swallow the input that follows it.
func readMaskedLine(reader io.Reader, file *os.File) (string, error) {
	fd := file.Fd()
	var state syscall.Termios
	if err := termiosGet(fd, &state); err != nil {
		return "", err
	}
	original := state
	state.Lflag &^= syscall.ECHO
	if err := termiosSet(fd, &state); err != nil {
		return "", err
	}
	defer func() { _ = termiosSet(fd, &original) }()
	return readLine(reader)
}

// isTerminal reports whether the file is a terminal, which is the only case
// where the echo can be switched off.
func isTerminal(file *os.File) bool {
	var state syscall.Termios
	return termiosGet(file.Fd(), &state) == nil
}

// termiosGet reads the terminal attributes.
func termiosGet(fd uintptr, state *syscall.Termios) error {
	return termiosIoctl(fd, syscall.TCGETS, state)
}

// termiosSet writes the terminal attributes.
func termiosSet(fd uintptr, state *syscall.Termios) error {
	return termiosIoctl(fd, syscall.TCSETS, state)
}

// termiosIoctl performs the terminal control call.
func termiosIoctl(fd uintptr, request uintptr, state *syscall.Termios) error {
	_, _, errno := syscall.Syscall6(syscall.SYS_IOCTL, fd, request,
		uintptr(unsafe.Pointer(state)), 0, 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}
