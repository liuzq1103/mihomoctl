//go:build linux

package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"reflect"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// The child executes the real terminal entry point with a synthetic service.
// It exercises terminal IO independently of controller/network availability;
// native controller and real-core acceptance are separate tests.
func TestConsolePTYHelper(t *testing.T) {
	if os.Getenv("MIHOMOCTL_GO_PTY_HELPER") != "1" {
		return
	}
	os.Exit(runMain([]string{"-demo"}))
}

func TestConsolePTYAllPagesResizeUTF8AndRestore(t *testing.T) {
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Fatal("PTY is required for Linux console acceptance:", err)
	}
	defer master.Close()
	var unlock int32
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, master.Fd(), 0x40045431, uintptr(unsafe.Pointer(&unlock))); e != 0 {
		t.Fatal(e)
	}
	var number uint32
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, master.Fd(), 0x80045430, uintptr(unsafe.Pointer(&number))); e != 0 {
		t.Fatal(e)
	}
	slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", number), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer slave.Close()
	var saved syscall.Termios
	if err := ioctlTermios(int(slave.Fd()), syscall.TCGETS, &saved); err != nil {
		t.Fatal(err)
	}
	resize := func(columns, rows uint16) {
		t.Helper()
		size := winsize{Row: rows, Col: columns}
		if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, slave.Fd(), syscall.TIOCSWINSZ, uintptr(unsafe.Pointer(&size))); e != 0 {
			t.Fatal(e)
		}
	}
	resize(100, 30)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestConsolePTYHelper$")
	child.Env = append(os.Environ(), "MIHOMOCTL_GO_PTY_HELPER=1")
	child.Stdin, child.Stdout, child.Stderr = slave, slave, slave
	child.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	var mu sync.Mutex
	var output bytes.Buffer
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		buffer := make([]byte, 32768)
		for {
			n, e := master.Read(buffer)
			if n > 0 {
				mu.Lock()
				if output.Len() < 8<<20 {
					output.Write(buffer[:n])
				}
				mu.Unlock()
			}
			if e != nil {
				return
			}
		}
	}()
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = child.Process.Kill() }()
	started := false
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		mu.Lock()
		started = bytes.Contains(output.Bytes(), []byte("\x1b[?1049h"))
		mu.Unlock()
		if started {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !started {
		t.Fatal("console did not enter its alternate screen")
	}
	send := func(keys string) {
		t.Helper()
		if _, err := io.WriteString(master, keys); err != nil {
			t.Fatal(err)
		}
		time.Sleep(120 * time.Millisecond)
	}
	// Every numbered page, filters with multibyte input, stream leave/return,
	// log-level restart, theme/options, modal cancellation and command input.
	for _, page := range "1234567890" {
		send(string(page))
	}
	for _, keys := range []string{"2", "/", "中文", "\x1b", "6", ":log-level debug\r", "1", "6", ":theme light\r", "o", "\x1b", "?", "\x1b", ":cancel\r"} {
		send(keys)
	}
	for _, size := range [][2]uint16{{60, 16}, {24, 7}, {120, 36}} {
		resize(size[0], size[1])
		if err := child.Process.Signal(syscall.SIGWINCH); err != nil {
			t.Fatal(err)
		}
		time.Sleep(150 * time.Millisecond)
	}
	send("q")
	if err := child.Wait(); err != nil {
		t.Fatalf("console exit: %v (deadline=%v)", err, ctx.Err())
	}
	var restored syscall.Termios
	if err := ioctlTermios(int(slave.Fd()), syscall.TCGETS, &restored); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(saved, restored) {
		t.Fatal("console did not restore terminal attributes")
	}
	_ = slave.Close()
	_ = master.Close()
	<-readDone
	mu.Lock()
	captured := append([]byte(nil), output.Bytes()...)
	mu.Unlock()
	if !bytes.Contains(captured, []byte("\x1b[?1049l")) || !bytes.Contains(captured, []byte("\x1b[?25h")) {
		t.Fatal("console did not restore the main screen and cursor")
	}
	if bytes.Contains(captured, []byte("panic:")) || len(captured) >= 8<<20 {
		t.Fatal("console panicked or produced unbounded output")
	}
}
