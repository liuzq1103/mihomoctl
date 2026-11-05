package runtimecore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

const geodataLimit int64 = 128 << 20
const providerLimit int64 = 8 << 20
const executableLimit int64 = 256 << 20
const validationResourceLimit int64 = 512 << 20

var geoNames = map[string]bool{"country.mmdb": true, "geoip.db": true, "geoip.metadb": true, "geoip.dat": true, "geosite.dat": true, "asn.mmdb": true}

type resourceProof struct {
	Path  string
	Hash  string
	Limit int64
}

func resourceLimit(role string) (int64, error) {
	switch role {
	case "geodata":
		return geodataLimit, nil
	case "provider":
		return providerLimit, nil
	case "executable":
		return executableLimit, nil
	}
	return 0, platform.Usage("validation-resource-role-invalid")
}
func hashResource(ctx context.Context, a platform.App, p, role string) (string, int64, error) {
	limit, e := resourceLimit(role)
	if e != nil {
		return "", 0, e
	}
	return transferResource(ctx, a, p, "", limit)
}

// Binary resources never pass through YAML decoding or platform.ReadPrivate's
// text limit. A streaming size cap bounds both sparse and growing files.
func transferResource(ctx context.Context, a platform.App, source, target string, limit int64) (string, int64, error) {
	if e := platform.CheckPath(source); e != nil {
		return "", 0, e
	}
	f, e := openCoreResource(a, source)
	if e != nil {
		return "", 0, e
	}
	defer f.Close()
	before, e := f.Stat()
	if e != nil {
		return "", 0, e
	}
	if before.Size() > limit {
		return "", 0, platform.Usage("validation-resource-too-large")
	}
	var output *os.File
	temporary := ""
	if target != "" {
		if e = platform.PrivateDir(filepath.Dir(target)); e != nil {
			return "", 0, e
		}
		output, e = os.CreateTemp(filepath.Dir(target), ".resource-*")
		if e != nil {
			return "", 0, e
		}
		temporary = output.Name()
		defer os.Remove(temporary)
		defer output.Close()
		if e = output.Chmod(0600); e != nil {
			return "", 0, e
		}
	}
	hash := sha256.New()
	var writer io.Writer = hash
	if output != nil {
		writer = io.MultiWriter(output, hash)
	}
	reader := &contextReader{ctx: ctx, reader: io.LimitReader(f, limit+1)}
	size, e := io.CopyBuffer(writer, reader, make([]byte, 64<<10))
	if e != nil {
		return "", 0, e
	}
	if size > limit {
		return "", 0, platform.Usage("validation-resource-too-large")
	}
	after, e := f.Stat()
	if e != nil {
		return "", 0, e
	}
	current, e := os.Lstat(source)
	if e != nil || !os.SameFile(before, after) || !os.SameFile(before, current) || before.Size() != after.Size() || before.ModTime() != after.ModTime() || before.Mode() != after.Mode() {
		return "", 0, platform.Usage("validation-inputs-changed")
	}
	if output != nil {
		if e = output.Sync(); e != nil {
			return "", 0, e
		}
		if e = output.Close(); e != nil {
			return "", 0, e
		}
		if e = os.Rename(temporary, target); e != nil {
			return "", 0, e
		}
	}
	return hex.EncodeToString(hash.Sum(nil)), size, nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *contextReader) Read(b []byte) (int, error) {
	if e := r.ctx.Err(); e != nil {
		return 0, e
	}
	return r.reader.Read(b)
}
func stageResources(ctx context.Context, a platform.App, cfg map[string]any, staging string) ([]resourceProof, error) {
	return stageResourcesBudget(ctx, a, cfg, staging, validationResourceLimit)
}
func stageResourcesBudget(ctx context.Context, a platform.App, cfg map[string]any, staging string, budget int64) ([]resourceProof, error) {
	proofs := []resourceProof{}
	var total int64
	copyFile := func(source, target, role string) error {
		limit, e := resourceLimit(role)
		if e != nil {
			return e
		}
		if limit > budget-total {
			limit = budget - total
		}
		hash, size, e := transferResource(ctx, a, source, target, limit)
		if e != nil {
			return e
		}
		total += size
		proofs = append(proofs, resourceProof{source, hash, limit})
		return nil
	}
	home := a.Scope.CoreHome()
	if e := platform.CheckPath(home); e != nil {
		return nil, e
	}
	entries, e := os.ReadDir(home)
	if e != nil && !os.IsNotExist(e) {
		return nil, e
	}
	for _, entry := range entries {
		if geoNames[strings.ToLower(entry.Name())] {
			if e = copyFile(filepath.Join(home, entry.Name()), filepath.Join(staging, entry.Name()), "geodata"); e != nil {
				return nil, e
			}
		}
	}
	for _, section := range []string{"proxy-providers", "rule-providers"} {
		value, exists := cfg[section]
		if !exists {
			continue
		}
		providers, ok := value.(map[string]any)
		if !ok {
			return nil, invalid()
		}
		for _, value := range providers {
			provider, ok := value.(map[string]any)
			if !ok {
				return nil, invalid()
			}
			raw, exists := provider["path"]
			if !exists {
				continue
			}
			path, ok := raw.(string)
			if !ok || !cleanString(path) {
				return nil, platform.Usage("validation-resource-path-unsafe")
			}
			for _, segment := range strings.Split(filepath.ToSlash(path), "/") {
				if segment == ".." {
					return nil, platform.Usage("validation-resource-path-unsafe")
				}
			}
			source := path
			if !filepath.IsAbs(source) {
				source = filepath.Join(home, source)
			}
			if !within(home, source) {
				return nil, platform.Usage("validation-resource-path-unsafe")
			}
			rel, e := filepath.Rel(home, source)
			if e != nil || rel == "." {
				return nil, platform.Usage("validation-resource-path-unsafe")
			}
			parts := strings.Split(filepath.ToSlash(rel), "/")
			if geoNames[strings.ToLower(parts[0])] || member(filepath.Base(rel), "cache.db", ".cache", "candidate.yaml") {
				return nil, platform.Usage("validation-resource-path-unsafe")
			}
			target := filepath.Join(staging, rel)
			if e = platform.CheckPath(source); e != nil {
				return nil, e
			}
			if _, e = os.Lstat(source); e == nil {
				if e = copyFile(source, target, "provider"); e != nil {
					return nil, e
				}
			} else if !os.IsNotExist(e) {
				return nil, e
			}
			provider["path"] = target
		}
	}
	return proofs, nil
}
func verifyResources(ctx context.Context, a platform.App, proofs []resourceProof) error {
	for _, proof := range proofs {
		hash, _, e := transferResource(ctx, a, proof.Path, "", proof.Limit)
		if e != nil {
			return e
		}
		if hash != proof.Hash {
			return platform.Usage("validation-inputs-changed")
		}
	}
	return nil
}
