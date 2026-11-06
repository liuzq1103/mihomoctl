package routing

import (
	"context"
	"crypto/sha256"
	"io"
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
					b, err := readValidationResource(cleaned, m.system)
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
			b, err := readValidationResource(p, m.system)
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
	// The reviewed core may live below root-private delivery directories that
	// the dropped identity cannot traverse. Stage a verified byte-identical
	// copy inside the (about to be handed over) isolated tree and execute
	// only that copy; the original's trust proof stands and the hash binds
	// the copy to it.
	execPath := m.binary
	if uid > 0 {
		staged, err := stageValidatedCore(staging, m.binary)
		if err != nil {
			return err
		}
		execPath = staged
	}
	if uid > 0 {
		if err := chownTree(staging, uid, uid); err != nil {
			return control("validation-unavailable", exitUnverify)
		}
	}
	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, execPath, "-t", "-d", staging, "-f", candidate)
	cmd.Env = cleanChildEnvironment()
	if uid > 0 {
		cmd.Dir = staging
	}
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

// validationResourceLimit bounds a staged validation resource (geo databases
// reach tens of MiB); the platform-wide private-read cap is far smaller.
const validationResourceLimit = 256 << 20

// validationExecutableLimit bounds the staged core copy the validator runs.
const validationExecutableLimit = 256 << 20

// stageValidatedCore copies the already-trust-proven core binary into the
// isolated validation tree and proves the copy byte-identical to the original
// by hashing both sides, re-verifying the source size and modification time
// after the copy so a swap mid-validation cannot slip through.
func stageValidatedCore(staging, source string) (string, error) {
	handle, err := os.Open(source)
	if err != nil {
		return "", control("core-unavailable", exitUnverify)
	}
	defer handle.Close()
	before, err := handle.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() > validationExecutableLimit {
		return "", control("core-unavailable", exitUnverify)
	}
	directory := filepath.Join(staging, ".validator-bin")
	if err := os.Mkdir(directory, 0700); err != nil {
		return "", control("validation-unavailable", exitUnverify)
	}
	isolated := filepath.Join(directory, "core")
	out, err := os.OpenFile(isolated, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0700)
	if err != nil {
		return "", control("validation-unavailable", exitUnverify)
	}
	digest := sha256.New()
	written, err := io.Copy(out, io.TeeReader(io.LimitReader(handle, validationExecutableLimit+1), digest))
	if err == nil {
		err = out.Sync()
	}
	if closeErr := out.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return "", control("validation-unavailable", exitUnverify)
	}
	after, err := handle.Stat()
	if err != nil || written > validationExecutableLimit || before.Size() != written || before.ModTime() != after.ModTime() {
		return "", control("validation-inputs-changed", exitUnverify)
	}
	copied, err := os.ReadFile(isolated)
	if err != nil {
		return "", control("validation-unavailable", exitUnverify)
	}
	stagedSum := sha256.Sum256(copied)
	expected := digest.Sum(nil)
	for i := range stagedSum {
		if stagedSum[i] != expected[i] {
			return "", control("validation-inputs-changed", exitUnverify)
		}
	}
	return isolated, nil
}

func readValidationResource(p string, system bool) ([]byte, error) {
	if err := platform.CheckPath(p); err != nil {
		return nil, controllerFileError(err)
	}
	handle, err := platform.OpenRegular(p)
	if err != nil {
		return nil, controllerFileError(err)
	}
	defer handle.Close()
	st, err := handle.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return nil, control("validation-resource-path-unsafe", exitUnverify)
	}
	if !validationResourceOwned(st, system) {
		return nil, control("validation-resource-path-unsafe", exitUnverify)
	}
	if st.Size() > validationResourceLimit {
		return nil, control("validation-resource-path-unsafe", exitUnverify)
	}
	b, err := io.ReadAll(io.LimitReader(handle, validationResourceLimit+1))
	if err != nil {
		return nil, controllerFileError(err)
	}
	if len(b) > validationResourceLimit {
		return nil, control("validation-resource-path-unsafe", exitUnverify)
	}
	return b, nil
}
