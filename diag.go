package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// proxyVarKeys are the eight environment variables mihomoctl injects; process
// diagnosis reports presence only, never values.
var proxyVarKeys = []string{
	"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy",
	"ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy",
}

// inspectProcess reads /proc for a same-UID process and reports proxy
// environment presence. This is the Go port of the read-only process_reader
// surface the Textual console exposed through service.diagnose("process").
func inspectProcess(pid string, proxyPort int) ([]string, error) {
	number, err := strconv.Atoi(pid)
	if err != nil || number < 1 {
		return nil, fmt.Errorf("invalid-pid")
	}
	root := filepath.Join("/proc", pid)
	info, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("process-not-found")
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("process-not-found")
	}
	status, err := os.ReadFile(filepath.Join(root, "status"))
	if err != nil {
		return nil, fmt.Errorf("process-unreadable")
	}
	uid := ""
	for _, line := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line)
			if len(fields) > 1 {
				uid = fields[1]
			}
		}
	}
	if uid == "" || (uid != "0" && uid != fmt.Sprint(os.Getuid())) {
		return nil, fmt.Errorf("process-owned-by-another-user")
	}
	raw, err := os.ReadFile(filepath.Join(root, "environ"))
	if err != nil {
		return nil, fmt.Errorf("process-environment-unreadable")
	}
	rows := []string{"进程 " + pid + "（同 UID，只读检查）"}
	env := map[string]string{}
	for _, entry := range bytes.Split(raw, []byte{0}) {
		key, value, found := strings.Cut(string(entry), "=")
		if found {
			env[key] = value
		}
	}
	pointing := []string{}
	for _, key := range proxyVarKeys {
		value, set := env[key]
		switch {
		case !set:
			continue
		case strings.Contains(value, fmt.Sprintf("127.0.0.1:%d", proxyPort)):
			pointing = append(pointing, key+" → 本机代理")
		default:
			pointing = append(pointing, key+" → 其他地址")
		}
	}
	if len(pointing) == 0 {
		rows = append(rows, "  未设置任何代理变量：该进程不走本机代理")
	} else {
		rows = append(rows, "  代理变量：")
		rows = append(rows, pointing...)
	}
	if len(pointing) > 0 && len(env["NO_PROXY"]) == 0 && len(env["no_proxy"]) == 0 {
		rows = append(rows, "  警告：设置了代理变量但没有 NO_PROXY，localhost 流量也会被送进代理")
	}
	rows = append(rows, "  边界：环境变量只在进程创建时继承；本检查不证明任何具体请求的路径。")
	return rows, nil
}

// readJournal reads the current user's service journal via journalctl with
// JSON output, mirroring service.journal's read-only path.
func readJournal(unit string, since, until string, lines int) ([]string, error) {
	if lines < 1 || lines > 10000 {
		lines = 200
	}
	args := []string{"--user", "--unit", unit, "--no-pager", "--output=json",
		"--lines", strconv.Itoa(lines)}
	for flag, value := range map[string]string{"--since": since, "--until": until} {
		if value != "" {
			if len(value) > 128 || strings.ContainsAny(value, "\x00\n") {
				return nil, fmt.Errorf("invalid-journal-time")
			}
			args = append(args, flag, value)
		}
	}
	cmd := exec.Command("journalctl", args...)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = nil
	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("journal-unavailable")
	}
	go func() { done <- cmd.Wait() }()
	timer := time.NewTimer(8 * time.Second)
	defer timer.Stop()
	select {
	case err := <-done:
		if err != nil {
			return nil, fmt.Errorf("journal-unavailable")
		}
	case <-timer.C:
		_ = cmd.Process.Kill()
		return nil, fmt.Errorf("journal-timeout")
	}
	rows := []string{"日志来源：systemd journal · 单元 " + unit}
	for _, line := range strings.Split(stdout.String(), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var row struct {
			PRIORITY  string `json:"PRIORITY"`
			TIMESTAMP string `json:"__REALTIME_TIMESTAMP"`
			MESSAGE   string `json:"MESSAGE"`
		}
		if json.Unmarshal([]byte(line), &row) != nil {
			continue
		}
		when := ""
		if ts, err := strconv.ParseInt(row.TIMESTAMP, 10, 64); err == nil {
			when = time.Unix(ts/1_000_000, 0).Format("15:04:05")
		}
		rows = append(rows, fmt.Sprintf("  %s %s %s", when, row.PRIORITY, sanitize(row.MESSAGE)))
	}
	if len(rows) == 1 {
		rows = append(rows, "  时间窗口内无记录")
	}
	return rows, nil
}

// sanitize drops control characters like log_text does before display.
func sanitize(text string) string {
	var b strings.Builder
	for _, r := range text {
		if r < 32 || r == 127 {
			b.WriteRune(' ')
		} else {
			b.WriteRune(r)
		}
	}
	out := b.String()
	if len(out) > 400 {
		out = out[:400]
	}
	return out
}
