package runtimecore

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/liuzq1103/mihomoctl/internal/platform"
)

func integrationPaths(a platform.App, n string, b binding) (string, string) {
	root := "/etc/systemd/system"
	if !a.Scope.System {
		root = filepath.Join(filepath.Dir(a.Scope.ConfigRoot), "systemd", "user")
	}
	return filepath.Join(a.Scope.ConfigRoot, "integrations", n+".env"), filepath.Join(root, b.Target+".d", "50-mihomoctl-go-"+n+".conf")
}
func integrationPathAllowed(a platform.App, p string) bool {
	root := filepath.Dir(unitPath(a))
	rel, e := filepath.Rel(root, p)
	if e != nil {
		return false
	}
	parts := strings.Split(rel, string(filepath.Separator))
	if len(parts) != 2 || !strings.HasSuffix(parts[0], ".service.d") || !unitPattern.MatchString(strings.TrimSuffix(parts[0], ".d")) {
		return false
	}
	leaf := parts[1]
	if !strings.HasPrefix(leaf, "50-mihomoctl-go-") || !strings.HasSuffix(leaf, ".conf") {
		return false
	}
	return namePattern.MatchString(strings.TrimSuffix(strings.TrimPrefix(leaf, "50-mihomoctl-go-"), ".conf"))
}
func integrationArtifacts(a platform.App, n string, b binding, vars map[string]string) map[string][]byte {
	env, drop := integrationPaths(a, n, b)
	var text strings.Builder
	text.WriteString(unitMarker + "\n")
	for _, k := range proxyKeys {
		fmt.Fprintf(&text, "%s=%s\n", k, quoteEnvironment(vars[k]))
	}
	return map[string][]byte{env: []byte(text.String()), drop: []byte(unitMarker + "\n[Service]\nEnvironmentFile=" + environmentFilePath(env) + "\n")}
}
func environmentFilePath(s string) string {
	var out strings.Builder
	for _, r := range s {
		if strings.ContainsRune("\\*?[]", r) {
			out.WriteByte('\\')
		}
		if r == '%' {
			out.WriteByte('%')
		}
		out.WriteRune(r)
	}
	return out.String()
}

type integrationReceipt struct {
	Format    int               `json:"format"`
	Binding   string            `json:"binding"`
	Target    string            `json:"target"`
	Artifacts map[string]string `json:"artifacts"`
}

func integrationReceiptPath(a platform.App, n string) string {
	return filepath.Join(a.Scope.ConfigRoot, "integrations", n+".receipt.json")
}
func ownedIntegration(a platform.App, n string, b binding) (bool, error) {
	env, drop := integrationPaths(a, n, b)
	p := integrationReceiptPath(a, n)
	if e := platform.CheckPath(p); e != nil {
		return false, e
	}
	if _, e := os.Lstat(p); os.IsNotExist(e) {
		for _, path := range []string{env, drop} {
			if _, e := os.Lstat(path); e == nil {
				return false, platform.Usage("integration-file-not-managed")
			} else if !os.IsNotExist(e) {
				return false, e
			}
		}
		return false, nil
	}
	raw, e := platform.ReadPrivate(p)
	if e != nil {
		return false, e
	}
	var receipt integrationReceipt
	if json.Unmarshal(raw, &receipt) != nil || receipt.Format != 1 || receipt.Binding != n || len(receipt.Artifacts) != 2 {
		return false, platform.Usage("integration-receipt-invalid")
	}
	if receipt.Target != b.Target {
		return false, platform.Usage("integration-target-drifted")
	}
	for _, p := range []string{env, drop} {
		raw, e := platform.ReadPrivate(p)
		if e != nil {
			return false, e
		}
		if platform.Hash(raw) != receipt.Artifacts[p] {
			return false, platform.Usage("integration-artifact-drifted")
		}
	}
	return true, nil
}
func removeIntegration(ctx context.Context, a platform.App, r platform.Request, n string, b binding) (platform.Envelope, error) {
	doc := platform.Document(r.Name(), a.Scope.Name, map[string]any{"binding": n, "target": b.Target, "removed": []string{}})
	if b.Adapter != "systemd" || b.Target == "" {
		return doc, platform.Usage("integration-unsupported")
	}
	owned, e := ownedIntegration(a, n, b)
	if e != nil {
		return doc, e
	}
	if !owned {
		return doc, nil
	}
	env, drop := integrationPaths(a, n, b)
	paths := []string{env, drop, integrationReceiptPath(a, n)}
	before := map[string][]byte{}
	files := map[string][]byte{}
	for _, p := range paths {
		before[p], e = platform.ReadPrivate(p)
		if e != nil {
			return doc, e
		}
		files[p] = nil
	}
	if e = applyFiles(a, files); e != nil {
		return doc, e
	}
	if _, e = systemctl(ctx, a, "daemon-reload"); e != nil {
		if re := applyFiles(a, before); re != nil {
			return doc, platform.Fail("rollback-failed")
		}
		if _, re := systemctl(ctx, a, "daemon-reload"); re != nil {
			return doc, platform.Fail("rollback-failed")
		}
		return doc, e
	}
	doc.Data["removed"] = paths
	return doc, nil
}
func quoteEnvironment(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	return "\"" + s + "\""
}
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
func integration(ctx context.Context, a platform.App, r platform.Request) (platform.Envelope, error) {
	doc := platform.Document(r.Name(), a.Scope.Name, nil)
	m, e := loadManager(a)
	if e != nil {
		return doc, e
	}
	if member(r.Name(), "integration", "integration-list") {
		rows := []map[string]any{}
		for _, n := range sortedKeys(m.Bindings) {
			rows = append(rows, bindingDoc(n, m.Bindings[n]))
		}
		doc.Data["bindings"] = rows
		return doc, nil
	}
	n := r.Arg(0)
	b, ok := m.Bindings[n]
	if !ok {
		return doc, platform.Usage("binding-unknown")
	}
	if r.Name() == "integration-show" {
		doc.Data = bindingDoc(n, b)
		return doc, nil
	}
	if r.Name() == "integration-remove" {
		return removeIntegration(ctx, a, r, n, b)
	}
	x, e := resolve(a, b.Profile)
	if e != nil {
		return doc, e
	}
	vars, e := environment(x, "")
	if e != nil {
		return doc, e
	}
	if r.Name() == "integration-export" {
		files, e := renderExport(a, n, b, vars)
		if e != nil {
			return doc, e
		}
		paths := []string{}
		if directory := r.Get("output-dir"); directory != "" {
			out, e := expandOutputPath(directory)
			if e != nil {
				return doc, e
			}
			if e = platform.PrivateDir(out); e != nil {
				return doc, e
			}
			for _, name := range sortedKeys(files) {
				path := filepath.Join(out, name)
				if e = platform.AtomicWrite(path, []byte(files[name]), 0600); e != nil {
					return doc, e
				}
				paths = append(paths, path)
			}
		}
		shown := files
		if !r.Has("reveal") {
			redacted, e := redactProxyVariables(vars)
			if e != nil {
				return doc, e
			}
			shown, e = renderExport(a, n, b, redacted)
			if e != nil {
				return doc, e
			}
		}
		doc.Data = map[string]any{"binding": n, "adapter": b.Adapter, "artifacts": shown, "written": paths, "files": paths, "mode": "0600", "deployed": false, "note": "artifacts are never deployed automatically"}
		return doc, nil
	}
	if r.Name() == "integration-check" && b.Adapter != "systemd" {
		env, _ := integrationPaths(a, n, b)
		expected := integrationArtifacts(a, n, b, vars)[env]
		state := "missing"
		if _, e = os.Lstat(env); e == nil {
			raw, e := platform.ReadPrivate(env)
			if e != nil {
				return doc, e
			}
			state = "drifted"
			if bytesEqual(raw, expected) {
				state = "current"
			}
		} else if !os.IsNotExist(e) {
			return doc, e
		}
		doc.Data = map[string]any{"binding": n, "target": b.Target, "artifacts": []map[string]any{{"path": env, "state": state}}, "target_state": "unavailable", "live_environment": "UNVERIFIED", "note": "environment inheritance does not prove actual proxy use"}
		if state != "current" {
			doc.Overall = "FAIL"
		}
		return doc, nil
	}
	if b.Adapter != "systemd" || b.Target == "" {
		return doc, platform.Usage("integration-unsupported")
	}
	files := integrationArtifacts(a, n, b, vars)
	rows := []map[string]any{}
	for _, p := range sortedKeys(files) {
		state := "missing"
		if _, e = os.Lstat(p); e == nil {
			current, e := platform.ReadPrivate(p)
			if e != nil {
				return doc, e
			}
			state = "stale"
			if bytesEqual(current, files[p]) {
				state = "current"
			}
			if !strings.HasPrefix(string(current), unitMarker+"\n") {
				state = "foreign"
			}
		} else if !os.IsNotExist(e) {
			return doc, e
		}
		rows = append(rows, map[string]any{"path": p, "state": state})
	}
	if r.Name() == "integration-check" {
		doc.Data["artifacts"] = rows
		doc.Data["binding"] = n
		doc.Data["target"] = b.Target
		doc.Data["live_environment"] = "UNVERIFIED"
		doc.Data["target_state"] = "unavailable"
		doc.Data["note"] = "environment inheritance does not prove actual proxy use"
		for _, row := range rows {
			if row["state"] != "current" {
				doc.Overall = "FAIL"
			}
		}
		return doc, nil
	}
	if _, e = ownedIntegration(a, n, b); e != nil {
		return doc, e
	}
	hashes := map[string]string{}
	for p, v := range files {
		hashes[p] = platform.Hash(v)
	}
	receipt, e := json.Marshal(integrationReceipt{1, n, b.Target, hashes})
	if e != nil {
		return doc, e
	}
	receiptPath := integrationReceiptPath(a, n)
	files[receiptPath] = receipt
	before := map[string][]byte{}
	if _, e = os.Lstat(receiptPath); e == nil {
		before[receiptPath], e = platform.ReadPrivate(receiptPath)
		if e != nil {
			return doc, e
		}
	} else if os.IsNotExist(e) {
		before[receiptPath] = nil
	} else {
		return doc, e
	}
	for _, row := range rows {
		p := row["path"].(string)
		if row["state"] == "foreign" {
			return doc, platform.Usage("integration-artifact-unowned")
		}
		if row["state"] != "missing" {
			before[p], e = platform.ReadPrivate(p)
			if e != nil {
				return doc, e
			}
		} else {
			before[p] = nil
		}
		if r.Name() == "integration-remove" {
			files[p] = nil
		}
	}
	if e = applyFiles(a, files); e != nil {
		return doc, e
	}
	if _, e = systemctl(ctx, a, "daemon-reload"); e != nil {
		if re := applyFiles(a, before); re != nil {
			return doc, platform.Fail("rollback-failed")
		}
		if _, re := systemctl(ctx, a, "daemon-reload"); re != nil {
			return doc, platform.Fail("rollback-failed")
		}
		return doc, e
	}
	doc.Data = map[string]any{"binding": n, "installed": r.Name() == "integration-install", "target": b.Target, "restarted": false}
	return doc, nil
}
func renderExport(a platform.App, n string, b binding, vars map[string]string) (map[string]string, error) {
	if !builtinAdapter(b.Adapter) {
		return customExport(a, n, b, vars)
	}
	if member(b.Adapter, "docker", "kubernetes") {
		if b.ConnectHost == "" {
			return nil, platform.Usage("export-requires-connect-host")
		}
		var e error
		vars, e = rehostEnvironment(vars, b.ConnectHost)
		if e != nil {
			return nil, e
		}
	}
	files := map[string]string{}
	var env, shell, ci strings.Builder
	for _, k := range proxyKeys {
		fmt.Fprintf(&env, "%s=%s\n", k, vars[k])
		fmt.Fprintf(&shell, "export %s=%s\n", k, shellQuote(vars[k]))
		v, _ := json.Marshal(vars[k])
		fmt.Fprintf(&ci, "%s: %s\n", k, v)
	}
	switch b.Adapter {
	case "exec":
		files["exec.sh"] = shell.String()
	case "systemd":
		for p, v := range integrationArtifacts(a, n, b, vars) {
			files[filepath.Base(p)] = string(v)
		}
	case "docker":
		files["connect_host"] = b.ConnectHost
		files["docker.env"] = env.String()
		files["compose-fragment.yaml"] = "services:\n  " + n + ":\n    env_file:\n      - ./docker.env\n"
	case "kubernetes":
		files["connect_host"] = b.ConnectHost
		data := map[string]string{}
		for k, v := range vars {
			data[k] = base64.StdEncoding.EncodeToString([]byte(v))
		}
		manifest := map[string]any{"apiVersion": "v1", "kind": "Secret", "metadata": map[string]any{"name": "mihomoctl-go-" + n}, "type": "Opaque", "data": data}
		v, e := marshalYAML(manifest)
		if e != nil {
			return nil, e
		}
		files["k8s-secret.yaml"] = string(v)
		files["deployment-fragment.yaml"] = "envFrom:\n  - secretRef:\n      name: mihomoctl-go-" + n + "\n"
	case "supervisor":
		pairs := []string{}
		for _, k := range proxyKeys {
			value := strings.ReplaceAll(vars[k], "%", "%%")
			value = strings.ReplaceAll(value, "\"", "\\\"")
			pairs = append(pairs, k+"=\""+value+"\"")
		}
		files["supervisor.ini"] = "[program:" + n + "]\nenvironment=" + strings.Join(pairs, ",") + "\n"
	case "pm2":
		v, e := json.Marshal(map[string]any{"apps": []any{map[string]any{"name": n, "env": vars}}})
		if e != nil {
			return nil, e
		}
		files["ecosystem.config.js"] = "module.exports = " + string(v) + ";\n"
	case "ci":
		files["ci-env.yaml"] = ci.String()
		files["ci-env.sh"] = shell.String()
	default:
		return nil, platform.Usage("adapter-unknown")
	}
	return files, nil
}
