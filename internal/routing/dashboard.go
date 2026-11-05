package routing

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

//go:embed dashboard.html
var bundledDashboard string

var sha256Pattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

// choosePort binds a loopback probe socket to prove a controller port is free
// before it is written into configuration.
func choosePort(requested int, hasRequested bool) (int, error) {
	if hasRequested && (requested < 1024 || requested > 65535) {
		return 0, control("controller-port-out-of-range", exitUnverify)
	}
	address := "127.0.0.1:0"
	if hasRequested {
		address = net.JoinHostPort("127.0.0.1", strconv.Itoa(requested))
	}
	probe, err := net.Listen("tcp", address)
	if err != nil {
		return 0, control("controller-port-in-use", exitFail)
	}
	defer probe.Close()
	return probe.Addr().(*net.TCPAddr).Port, nil
}

// controllerTokenURLSafe mirrors secrets.token_urlsafe(32): 43 URL-safe
// characters from 32 random bytes.
func controllerTokenURLSafe() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64URLSafeNoPad(raw), nil
}

func base64URLSafeNoPad(raw []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	encoded := make([]byte, 0, (len(raw)*8+5)/6)
	buffer, bits := 0, 0
	for _, b := range raw {
		buffer = buffer<<8 | int(b)
		bits += 8
		for bits >= 6 {
			bits -= 6
			encoded = append(encoded, alphabet[(buffer>>bits)&0x3f])
		}
	}
	if bits > 0 {
		encoded = append(encoded, alphabet[(buffer<<(6-bits))&0x3f])
	}
	return string(encoded)
}

// initializeController initializes only the local API, without installing
// dashboard assets. It is idempotent: an already configured controller keeps
// its address and secret; profile.store-selected is enforced even then.
func initializeController(ctx context.Context, a platform.App, m coreManager, configPath, homeDir string, requested int, hasRequested bool) (map[string]any, error) {
	text, data, err := readCoreConfig(configPath, a.Scope.System)
	if err != nil {
		return nil, err
	}
	if rawProfile, exists := data["profile"]; exists {
		if _, isMap := rawProfile.(map[string]any); !isMap {
			return nil, control("config-profile-invalid", exitUnverify)
		}
	}
	profile := anyMap(data["profile"])
	configured := platform.String(data["external-controller"]) != ""
	port := 0
	if configured {
		_, port, _, err = endpoint(data)
		if err != nil {
			return nil, err
		}
		if storeSelected, _ := profile["store-selected"].(bool); storeSelected {
			return map[string]any{"state": "unchanged", "endpoint": "127.0.0.1:" + strconv.Itoa(port)}, nil
		}
	} else {
		for _, key := range []string{"external-controller-tls", "external-controller-unix", "external-controller-pipe", "external-doh-server"} {
			if v, ok := data[key]; ok && v != nil && v != false && platform.String(v) != "" {
				return nil, control("additional-controller-listeners-not-supported", exitUnverify)
			}
		}
		occupied := map[int]bool{}
		for _, key := range []string{"mixed-port", "port", "socks-port", "redir-port", "tproxy-port"} {
			if n := platform.Int(data[key]); n != 0 {
				occupied[n] = true
			}
		}
		listeners := anyList(data["listeners"])
		if listeners == nil && data["listeners"] != nil {
			return nil, control("config-listeners-invalid", exitUnverify)
		}
		for _, row := range listeners {
			if entry, ok := row.(map[string]any); ok {
				if n := platform.Int(entry["port"]); n != 0 {
					occupied[n] = true
				}
			}
		}
		port, err = choosePort(requested, hasRequested)
		if err != nil {
			return nil, err
		}
		attempts := 0
		for occupied[port] {
			if hasRequested {
				return nil, control("controller-port-conflicts-with-proxy", exitUnverify)
			}
			attempts++
			if attempts >= 32 {
				return nil, control("controller-port-unavailable", exitUnverify)
			}
			port, err = choosePort(0, false)
			if err != nil {
				return nil, err
			}
		}
	}
	var changes map[string]any
	if configured {
		// Touch only the profile block: rewriting the controller address or
		// secret would churn an installation that is already correct.
		withStore := deepCopyMap(profile)
		withStore["store-selected"] = true
		changes = map[string]any{"profile": withStore}
	} else {
		token, err := controllerTokenURLSafe()
		if err != nil {
			return nil, control("controller-operation-unavailable", exitUnverify)
		}
		withStore := deepCopyMap(profile)
		withStore["store-selected"] = true
		changes = map[string]any{
			"external-controller":      "127.0.0.1:" + strconv.Itoa(port),
			"secret":                   token,
			"profile":                  withStore,
			"external-controller-cors": map[string]any{"allow-origins": []any{}, "allow-private-network": false},
		}
	}
	home := homeDir
	if home == "" {
		home = a.Scope.CoreHome()
	}
	if err := platform.PrivateDir(home); err != nil {
		return nil, controllerFileError(err)
	}
	updated, err := patchCoreConfig(text, changes)
	if err != nil {
		return nil, err
	}
	result, err := applyPolicy(ctx, a, m, configPath, home, text, updated, nil)
	if err != nil {
		return nil, err
	}
	if _, ok := result["endpoint"]; !ok {
		endpointValue := platform.String(data["external-controller"])
		if v, ok := changes["external-controller"]; ok {
			endpointValue = v.(string)
		}
		result["endpoint"] = endpointValue
	}
	return result, nil
}

// archiveUI unpacks a reviewed dashboard archive whose pinned digest was
// checked by the caller.
func archiveUI(archive, checksum, destination string) error {
	if !sha256Pattern.MatchString(checksum) {
		return control("dashboard-requires-pinned-sha256", exitUnverify)
	}
	if err := platform.CheckPath(archive); err != nil {
		return controllerFileError(err)
	}
	info, err := os.Lstat(archive)
	if err != nil {
		return controllerFileError(err)
	}
	if info.Mode()&os.ModeSymlink != 0 || info.Size() > 32*1024*1024 {
		return control("dashboard-archive-invalid", exitUnverify)
	}
	raw, err := platform.ReadPrivate(archive)
	if err != nil {
		return controllerFileError(err)
	}
	if hashSHA256(raw) != checksum {
		return control("dashboard-sha256-mismatch", exitFail)
	}
	reader, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return control("dashboard-archive-invalid", exitUnverify)
	}
	entries := reader.File
	roots := []string{}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name, "index.html") {
			roots = append(roots, entry.Name[:len(entry.Name)-len("index.html")])
		}
	}
	if len(roots) != 1 || len(entries) > 10000 {
		return control("dashboard-archive-needs-one-index-html", exitUnverify)
	}
	root := roots[0]
	used := uint64(0)
	seen := map[string]bool{}
	for _, entry := range entries {
		name := entry.Name
		mode := entry.ExternalAttrs >> 16
		kind := mode & 0xF000
		if strings.HasPrefix(name, "/") || strings.Contains(name, "\\") || strings.Contains(name, ":") ||
			zipPathHasParent(name) || (kind != 0 && kind != 0x8000 && kind != 0x4000) || seen[name] {
			return control("dashboard-archive-unsafe-path", exitUnverify)
		}
		seen[name] = true
		used += uint64(entry.UncompressedSize64)
		if used > 64*1024*1024 {
			return control("dashboard-archive-too-large", exitUnverify)
		}
		if entry.FileInfo().IsDir() || !strings.HasPrefix(name, root) {
			continue
		}
		target := filepath.Join(destination, filepath.FromSlash(name[len(root):]))
		if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			return controllerFileError(err)
		}
		source, err := entry.Open()
		if err != nil {
			return control("dashboard-archive-invalid", exitUnverify)
		}
		data, readErr := io.ReadAll(io.LimitReader(source, 64*1024*1024+1))
		source.Close()
		if readErr != nil {
			return control("dashboard-archive-invalid", exitUnverify)
		}
		if uint64(len(data)) != entry.UncompressedSize64 {
			return control("dashboard-archive-invalid-size", exitUnverify)
		}
		if err := platform.AtomicWrite(target, data, 0600); err != nil {
			return controllerFileError(err)
		}
	}
	return nil
}

func zipPathHasParent(name string) bool {
	for _, part := range strings.Split(name, "/") {
		if part == ".." {
			return true
		}
	}
	return false
}

// setupController installs dashboard assets and the controller address using
// the shared lock, validator and atomic writes. Existing controller addresses
// and secrets are preserved unless explicitly reconfigured.
func setupController(ctx context.Context, a platform.App, m coreManager, configPath, homeDir, archivePath, checksum string, requested int, hasRequested bool) (map[string]any, error) {
	if err := a.Scope.RequireMutation(); err != nil {
		return nil, control(platform.SafeError(err), exitUnverify)
	}
	text, data, err := readCoreConfig(configPath, a.Scope.System)
	if err != nil {
		return nil, err
	}
	if archivePath == "" && platform.String(data["external-ui"]) != "" {
		return nil, control("existing-dashboard-preserved-use-explicit-archive-to-replace", exitUnverify)
	}
	secret := ""
	port := 0
	if platform.String(data["external-controller"]) != "" {
		_, port, secret, err = endpoint(data)
		if err != nil {
			return nil, err
		}
	} else {
		secret, err = controllerTokenURLSafe()
		if err != nil {
			return nil, control("controller-operation-unavailable", exitUnverify)
		}
	}
	if hasRequested {
		port = requested
	} else if port == 0 {
		port, err = choosePort(0, false)
		if err != nil {
			return nil, err
		}
	}
	if port < 1024 || port > 65535 {
		return nil, control("controller-port-out-of-range", exitUnverify)
	}
	staging, err := os.MkdirTemp("", "mihomoctl-go-dashboard-")
	if err != nil {
		return nil, control("controller-operation-unavailable", exitUnverify)
	}
	defer os.RemoveAll(staging)
	identifier := make([]byte, 8)
	if _, err := rand.Read(identifier); err != nil {
		return nil, control("controller-operation-unavailable", exitUnverify)
	}
	target := filepath.Join(a.Scope.ConfigRoot, "mihomo", "dashboard-"+hex.EncodeToString(identifier))
	installed := false
	defer func() {
		if !installed {
			_ = os.RemoveAll(target)
		}
	}()
	if archivePath != "" {
		if err := archiveUI(archivePath, checksum, staging); err != nil {
			return nil, err
		}
	} else if err := platform.AtomicWrite(filepath.Join(staging, "index.html"), []byte(bundledDashboard), 0600); err != nil {
		return nil, controllerFileError(err)
	}
	changes := map[string]any{
		"external-controller":      "127.0.0.1:" + strconv.Itoa(port),
		"secret":                   secret,
		"external-ui":              target,
		"external-ui-name":         "",
		"external-ui-url":          "",
		"external-controller-cors": map[string]any{"allow-origins": []any{}, "allow-private-network": false},
	}
	updated, err := patchCoreConfig(text, changes)
	if err != nil {
		return nil, err
	}
	// The candidate is validated before any asset is committed, and the
	// configuration is re-read before the write so a concurrent edit cannot
	// reference assets that were not installed.
	if err := validateCandidateText(ctx, a, m, updated); err != nil {
		return nil, err
	}
	if err := platform.PrivateDir(target); err != nil {
		return nil, controllerFileError(err)
	}
	err = filepath.Walk(staging, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil || info.IsDir() {
			return walkErr
		}
		relative, relErr := filepath.Rel(staging, path)
		if relErr != nil {
			return relErr
		}
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		mode := os.FileMode(0600)
		if a.Scope.System {
			mode = 0640
		}
		return platform.AtomicWrite(filepath.Join(target, relative), content, mode)
	})
	if err != nil {
		return nil, controllerFileError(err)
	}
	if a.Scope.System {
		if accountUID := serviceAccountUID(); accountUID > 0 {
			// System-scope assets belong to root and the service group; the
			// dedicated directories below the config root stay group-traversable.
			_ = filepath.Walk(target, func(path string, info os.FileInfo, walkErr error) error {
				if walkErr != nil {
					return walkErr
				}
				_ = chownDashboardAsset(path)
				return nil
			})
			for parent := filepath.Dir(target); parent != a.Scope.ConfigRoot && filepath.Dir(parent) != parent; parent = filepath.Dir(parent) {
				_ = chownDashboardAsset(parent)
				_ = os.Chmod(parent, 0750)
			}
		}
	}
	current, err := platform.ReadPrivate(configPath)
	if err != nil {
		return nil, controllerFileError(err)
	}
	if string(current) != string(text) {
		return nil, control("config-changed-during-setup", exitUnverify)
	}
	mode := os.FileMode(0600)
	if a.Scope.System {
		mode = 0640
	}
	if err := platform.AtomicWrite(configPath, updated, mode); err != nil {
		return nil, control("config-write-failed-original-restored", exitUnverify)
	}
	installed = true
	ui := "bundled"
	if archivePath != "" {
		ui = "external"
	}
	return map[string]any{
		"endpoint": "127.0.0.1:" + strconv.Itoa(port),
		"state":    "restart-required",
		"service":  "unchanged",
		"ui":       ui,
	}, nil
}
