package main

import (
	"fmt"
	"github.com/liuzq1103/mihomoctl/internal/platform"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
)

// CtlConfig mirrors what controller_config.endpoint validates in the Python
// console: a loopback external-controller plus a 32-256 char URL-safe secret.
// Mutations and the strict YAML contract stay with the Python services; this
// scan only needs the two keys the read paths authenticate with.
type CtlConfig struct {
	Port  int
	Token string
	Path  string
	Host  string
}

var (
	addrPattern  = regexp.MustCompile(`^(?:127\.0\.0\.1|\[::1\]|localhost):([0-9]{1,5})$`)
	tokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{32,256}$`)
)

func defaultConfigPath() string {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		if home, err := os.UserHomeDir(); err == nil {
			base = filepath.Join(home, ".config")
		} else {
			base = "."
		}
	}
	return filepath.Join(base, "mihomoctl-go", "config.yaml")
}

func discoverCtl(path string) (CtlConfig, error) {
	if path == "" {
		path = defaultConfigPath()
	}
	doc, err := platform.ReadYAML(path, true)
	if err != nil {
		return CtlConfig{}, err
	}
	cfg := CtlConfig{Path: path}
	address, token := platform.String(doc["external-controller"]), platform.String(doc["secret"])
	match := addrPattern.FindStringSubmatch(address)
	if match == nil {
		return CtlConfig{}, fmt.Errorf("controller-not-configured-as-loopback")
	}
	port, err := strconv.Atoi(match[1])
	if err != nil || port < 1024 || port > 65535 {
		return CtlConfig{}, fmt.Errorf("controller-not-configured-as-loopback")
	}
	if !tokenPattern.MatchString(token) {
		return CtlConfig{}, fmt.Errorf("controller-secret-must-be-32-to-256-url-safe-characters")
	}
	cfg.Port, cfg.Token = port, token
	cfg.Host, _, _ = net.SplitHostPort(address)
	return cfg, nil
}
