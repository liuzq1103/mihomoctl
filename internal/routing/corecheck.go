package routing

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/liuzq1103/mihomoctl/internal/platform"
	"gopkg.in/yaml.v3"
)

// cleanChildEnvironment strips proxy variables and controller-injectable
// state from a child environment, mirroring the original clean_environment().
func cleanChildEnvironment() []string {
	var out []string
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		lower := strings.ToLower(key)
		if lower == "http_proxy" || lower == "https_proxy" || lower == "all_proxy" || lower == "no_proxy" {
			continue
		}
		if strings.HasPrefix(key, "MIHOMO_") || strings.HasPrefix(key, "CLASH_") || strings.HasPrefix(key, "LD_") {
			continue
		}
		out = append(out, entry)
	}
	return out
}

// coreManager is the routing view of the manager document.
type coreManager struct {
	binary  string
	config  string
	backend string
	allowed []string
	system  bool
}

// loadCoreManager reads the private manager document for the routing scope.
func loadCoreManager(a platform.App) (coreManager, error) {
	var m coreManager
	doc, err := a.LoadManager()
	if err != nil {
		return m, err
	}
	core := platform.Map(doc["core"])
	m = coreManager{
		binary:  platform.String(core["binary"]),
		config:  platform.String(core["config"]),
		backend: platform.String(core["backend"]),
		system:  a.Scope.System,
	}
	if rows, ok := doc["allow_non_loopback"].([]any); ok {
		for _, r := range rows {
			if s, ok := r.(string); ok {
				m.allowed = append(m.allowed, s)
			}
		}
	}
	if m.binary == "" || m.config == "" {
		return m, control("config-invalid", exitUnverify)
	}
	return m, nil
}

// validateCandidateText runs the isolated core -t check over a candidate
// configuration: resources are copied into a private staging directory,
// provider paths are rewritten only inside the isolated candidate, and the
// managed security envelope is asserted before the core ever runs.
func validateCandidateText(ctx context.Context, a platform.App, m coreManager, updated []byte) error {
	cfg, err := platform.DecodeYAML(updated)
	if err != nil {
		return controllerFileError(err)
	}
	if err := validateEndpointEnvelope(cfg, m.system, m.allowed); err != nil {
		return err
	}
	if err := trustedCoreExecutable(m.binary, m.system); err != nil {
		return err
	}
	home := a.Scope.CoreHome()
	staging, err := os.MkdirTemp("", "mihomoctl-go-validate-")
	if err != nil {
		return control("validation-unavailable", exitUnverify)
	}
	defer os.RemoveAll(staging)
	for _, section := range []string{"proxy-providers", "rule-providers"} {
		if v, ok := cfg[section]; ok && v != nil {
			providers, ok := v.(map[string]any)
			if !ok {
				return control("core-config-invalid", exitUnverify)
			}
			for _, v := range providers {
				p, ok := v.(map[string]any)
				if !ok {
					return control("core-config-invalid", exitUnverify)
				}
				raw, exists := p["path"]
				if !exists {
					continue
				}
				s, ok := raw.(string)
				if !ok || s == "" || strings.ContainsAny(s, "\x00\x01\x1f") {
					return control("validation-resource-path-unsafe", exitUnverify)
				}
				source := s
				if !filepath.IsAbs(source) {
					source = filepath.Join(home, source)
				}
				cleaned := filepath.Clean(source)
				if rel, err := filepath.Rel(home, cleaned); err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || rel == "." || rel == "cache.db" {
					return control("validation-resource-path-unsafe", exitUnverify)
				}
				rel, _ := filepath.Rel(home, cleaned)
				target := filepath.Join(staging, rel)
				if _, err := os.Lstat(cleaned); err == nil {
					b, err := readValidationResource(cleaned)
					if err != nil {
						return err
					}
					if err := platform.AtomicWrite(target, b, 0600); err != nil {
						return controllerFileError(err)
					}
				} else if !os.IsNotExist(err) {
					return controllerFileError(err)
				}
				p["path"] = target
			}
		}
	}
	for _, name := range []string{"Country.mmdb", "GeoIP.dat", "GeoSite.dat", "geoip.metadb", "country.mmdb", "geoip.db", "asn.mmdb"} {
		p := filepath.Join(home, name)
		if _, err := os.Lstat(p); err == nil {
			b, err := readValidationResource(p)
			if err != nil {
				return err
			}
			if err := platform.AtomicWrite(filepath.Join(staging, name), b, 0600); err != nil {
				return controllerFileError(err)
			}
		} else if !os.IsNotExist(err) {
			return controllerFileError(err)
		}
	}
	text, err := yaml.Marshal(cfg)
	if err != nil {
		return control("core-config-invalid", exitUnverify)
	}
	candidate := filepath.Join(staging, "candidate.yaml")
	if err := platform.AtomicWrite(candidate, text, 0600); err != nil {
		return controllerFileError(err)
	}
	// Root never validates with its own identity.
	uid := -1
	if m.system {
		uid = serviceAccountUID()
		if uid <= 0 {
			return control("service-account-missing", exitUnverify)
		}
	} else if os.Geteuid() == 0 {
		uid = nobodyUID()
		if uid <= 0 {
			return control("service-account-missing", exitUnverify)
		}
	}
	if uid > 0 {
		if err := chownTree(staging, uid, uid); err != nil {
			return control("validation-unavailable", exitUnverify)
		}
	}
	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, m.binary, "-t", "-d", staging, "-f", candidate)
	cmd.Env = cleanChildEnvironment()
	validationIdentity(cmd, uid)
	// Core stderr may contain secrets: it is discarded on failure.
	if err := cmd.Run(); err != nil {
		if cctx.Err() != nil {
			return control("core-timeout", exitUnverify)
		}
		return control("core-config-invalid", exitUnverify)
	}
	return nil
}

func readValidationResource(p string) ([]byte, error) {
	if err := platform.CheckPath(p); err != nil {
		return nil, controllerFileError(err)
	}
	st, err := os.Lstat(p)
	if err != nil {
		return nil, controllerFileError(err)
	}
	if !st.Mode().IsRegular() {
		return nil, control("validation-resource-path-unsafe", exitUnverify)
	}
	if st.Size() > 256<<20 {
		return nil, control("validation-resource-path-unsafe", exitUnverify)
	}
	b, err := platform.ReadPrivate(p)
	if err != nil {
		return nil, controllerFileError(err)
	}
	return b, nil
}

var _ = fmt.Sprintf
