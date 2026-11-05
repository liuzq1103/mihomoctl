//go:build linux

package main

import (
	"os"
	"syscall"
)

func interactiveConsole() bool {
	for _, f := range []*os.File{os.Stdin, os.Stdout, os.Stderr} {
		var t syscall.Termios
		if ioctlTermios(int(f.Fd()), syscall.TCGETS, &t) != nil {
			return false
		}
	}
	return true
}
