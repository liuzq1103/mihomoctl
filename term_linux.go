//go:build linux

package main

import (
	"os"
	"os/signal"
	"syscall"
	"unsafe"
)

// rawTerm puts stdin into cbreak/no-echo mode; the console owns the whole
// screen via the alternate buffer and per-cell diffs, so output post-processing
// and line buffering must be off.
type rawTerm struct {
	fd    int
	saved syscall.Termios
}

func enterRaw() (*rawTerm, error) {
	fd := int(os.Stdin.Fd())
	t := &rawTerm{fd: fd}
	if err := ioctlTermios(fd, syscall.TCGETS, &t.saved); err != nil {
		return nil, err
	}
	raw := t.saved
	raw.Iflag &^= syscall.IGNBRK | syscall.BRKINT | syscall.PARMRK | syscall.ISTRIP |
		syscall.INLCR | syscall.IGNCR | syscall.ICRNL | syscall.IXON
	raw.Oflag &^= syscall.OPOST
	raw.Lflag &^= syscall.ECHO | syscall.ECHONL | syscall.ICANON | syscall.ISIG | syscall.IEXTEN
	raw.Cflag &^= syscall.CSIZE | syscall.PARENB
	raw.Cflag |= syscall.CS8
	raw.Cc[syscall.VMIN] = 1
	raw.Cc[syscall.VTIME] = 0
	if err := ioctlTermios(fd, syscall.TCSETS, &raw); err != nil {
		return nil, err
	}
	return t, nil
}

func (t *rawTerm) restore() {
	_ = ioctlTermios(t.fd, syscall.TCSETS, &t.saved)
}

func ioctlTermios(fd int, req uintptr, t *syscall.Termios) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), req, uintptr(unsafe.Pointer(t)))
	if errno != 0 {
		return errno
	}
	return nil
}

type winsize struct {
	Row, Col, Xpixel, Ypixel uint16
}

func termSize() (int, int) {
	var ws winsize
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, os.Stdin.Fd(), syscall.TIOCGWINSZ,
		uintptr(unsafe.Pointer(&ws)))
	if errno != 0 || ws.Col == 0 {
		return 80, 24
	}
	return int(ws.Col), int(ws.Row)
}

// watchResize reports terminal resize events; on Linux this is SIGWINCH.
func watchResize() <-chan struct{} {
	out := make(chan struct{}, 1)
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGWINCH)
	go func() {
		for range ch {
			select {
			case out <- struct{}{}:
			default:
			}
		}
	}()
	return out
}
