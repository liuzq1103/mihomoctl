// fdprobe replicates the routing fixture's listener/child arrangement and
// prints every input of the /proc ownership proof. Debug-only instrument for
// the ci-debug branch; never part of a release candidate.
package main

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

func statFields(pid int) {
	b, e := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if e != nil {
		fmt.Println("stat read error:", e)
		return
	}
	s := string(b)
	tail := strings.LastIndexByte(s, ')')
	f := strings.Fields(s[tail+1:])
	names := []string{"state", "ppid", "pgrp", "session", "tty", "tpgid", "flags", "minflt", "cminflt", "majflt", "cmajflt", "utime", "stime", "cutime", "cstime", "priority", "nice", "num_threads", "itreal", "starttime", "vsize", "rss"}
	fmt.Printf("pid=%d\n", pid)
	for i, n := range names {
		if i < len(f) {
			fmt.Printf("  %-11s = %s\n", n, f[i])
		}
	}
}

func fdInodes(pid int) map[string]bool {
	out := map[string]bool{}
	entries, e := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if e != nil {
		fmt.Println("fd read error:", e)
		return out
	}
	for _, f := range entries {
		p, e := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, f.Name()))
		if e == nil {
			fmt.Printf("  fd %s -> %s\n", f.Name(), p)
			if strings.HasPrefix(p, "socket:[") {
				out[strings.TrimSuffix(strings.TrimPrefix(p, "socket:["), "]")] = true
			}
		}
	}
	return out
}

func listenTable(pid int, inodes map[string]bool) {
	for _, file := range []string{"tcp", "tcp6"} {
		b, e := os.ReadFile(fmt.Sprintf("/proc/%d/net/%s", pid, file))
		if e != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			cols := strings.Fields(line)
			if len(cols) < 10 {
				continue
			}
			if cols[3] == "0A" || inodes[cols[9]] {
				fmt.Printf("  %s: local=%s st=%s inode=%s\n", file, cols[1], cols[3], cols[9])
			}
		}
	}
}

func main() {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		panic(err)
	}
	if err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		panic(err)
	}
	if err = syscall.Bind(fd, &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		panic(err)
	}
	sa, err := syscall.Getsockname(fd)
	if err != nil {
		panic(err)
	}
	port := sa.(*syscall.SockaddrInet4).Port
	fmt.Println("bound port:", port)
	if err = syscall.Listen(fd, 16); err != nil {
		panic(err)
	}
	if err = syscall.SetNonblock(fd, true); err != nil {
		panic(err)
	}
	file := os.NewFile(uintptr(fd), "diag-listener")
	l, err := net.FileListener(file)
	if err != nil {
		panic(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	srv.Listener = l
	srv.Start()
	defer srv.Close()
	fmt.Println("server URL:", srv.URL)

	core, err := exec.LookPath("sleep")
	if err != nil {
		panic(err)
	}
	fmt.Println("sleep path:", core)
	cmd := exec.Command(core, "3600")
	cmd.ExtraFiles = []*os.File{file}
	if err := cmd.Start(); err != nil {
		panic(err)
	}
	defer func() { _ = cmd.Process.Kill() }()
	pid := cmd.Process.Pid
	fmt.Println("child pid:", pid, "my pid:", os.Getpid(), "euid:", os.Geteuid())
	for i := 0; i < 3; i++ {
		fmt.Printf("== read %d ==\n", i)
		statFields(pid)
		exe, e := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
		fmt.Println("  exe:", exe, e)
		cl, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		fmt.Printf("  cmdline: %q\n", strings.ReplaceAll(string(cl), "\x00", "|"))
		time.Sleep(1 * time.Second)
	}
	fmt.Println("== child fds ==")
	inodes := fdInodes(pid)
	fmt.Println("== listen table (child netns) ==")
	listenTable(pid, inodes)
	fmt.Println("== my fds ==")
	mine := fdInodes(os.Getpid())
	fmt.Println("== listen table (mine) ==")
	listenTable(os.Getpid(), mine)
	resp, err := http.Get(srv.URL)
	if err != nil {
		fmt.Println("http get error:", err)
	} else {
		fmt.Println("http status:", resp.StatusCode)
		_ = resp.Body.Close()
	}
}
