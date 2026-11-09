package routing

import (
	"context"
	"encoding/json"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

var dnsNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$`)

// proxyRow is one sanitized identity of the core proxy table. The map keys
// mirror the original payload field names exactly.
type proxyRow struct {
	fields  map[string]any
	members bool
}

// directory is the sanitized node directory: global table rows, provider
// targets and the provider capability state, with stable /proxies order.
type directory struct {
	rows        map[string]*proxyRow
	rowOrder    []string
	targets     []map[string]any
	capability  string
	globalOrder []string
}

func (d *directory) appendRow(name string, row *proxyRow) {
	if _, exists := d.rows[name]; !exists {
		d.rows[name] = row
		d.rowOrder = append(d.rowOrder, name)
	}
}

func (d *directory) row(name string) *proxyRow { return d.rows[name] }

// arrayField reads a JSON array field distinguishing absent, null (invalid)
// and present, mirroring the original isinstance checks.
func arrayField(m map[string]any, key string) ([]any, bool) {
	v, present := m[key]
	if !present {
		return nil, true
	}
	if v == nil {
		return nil, false
	}
	arr, ok := v.([]any)
	return arr, ok
}

// globalProxies fetches and sanitizes /proxies keeping wire order.
func globalProxies(ctx context.Context, c *client) (*directory, error) {
	raw, err := c.requestRaw(ctx, "/proxies", requestOptions{optional: true})
	if err != nil {
		return nil, err
	}
	var doc struct {
		Proxies json.RawMessage `json:"proxies"`
	}
	if json.Unmarshal(raw, &doc) != nil || len(doc.Proxies) == 0 {
		return nil, control("controller-response-invalid", exitUnverify)
	}
	rows, _, err := decodeObject(doc.Proxies)
	if err != nil {
		return nil, control("controller-proxies-invalid", exitUnverify)
	}
	dir := &directory{rows: map[string]*proxyRow{}, capability: "supported"}
	for _, entry := range rows {
		var item map[string]any
		if json.Unmarshal(entry.Value, &item) != nil {
			return nil, control("controller-proxies-invalid", exitUnverify)
		}
		name, err := label(entry.Key)
		if err != nil {
			return nil, err
		}
		typeName, err := label(stringField(item, "type", "unknown"))
		if err != nil {
			return nil, err
		}
		row := &proxyRow{fields: map[string]any{"name": name, "type": typeName}}
		if alive, ok := boolField(item, "alive"); ok {
			row.fields["alive"] = alive
		}
		history, valid := arrayField(item, "history")
		if !valid {
			return nil, control("controller-proxies-invalid", exitUnverify)
		}
		row.fields["probe_observed"] = observedProbe(history)
		if extra, ok := item["extra"].(map[string]any); ok {
			states := map[string]any{}
			for k, v := range extra {
				states[k] = v
			}
			row.fields["_probe_states"] = states
		}
		if testURL, ok := item["testUrl"].(string); ok {
			row.fields["_test_url"] = testURL
		}
		if fixed, ok := item["fixed"].(string); ok {
			fixed, err := label(fixed)
			if err != nil {
				return nil, err
			}
			row.fields["fixed"] = fixed
		}
		if all, present := item["all"]; present {
			members, ok := all.([]any)
			if !ok || all == nil {
				return nil, control("controller-proxies-invalid", exitUnverify)
			}
			names := make([]any, 0, len(members))
			for _, m := range members {
				lm, err := label(m)
				if err != nil {
					return nil, err
				}
				names = append(names, lm)
			}
			row.fields["members"] = names
			row.members = true
			if now, ok := item["now"].(string); ok && now != "" {
				ln, err := label(now)
				if err != nil {
					return nil, err
				}
				row.fields["selected"] = ln
			} else {
				row.fields["selected"] = nil
			}
			row.fields["selectable"] = typeName == "Selector"
		}
		dir.appendRow(name, row)
		dir.globalOrder = append(dir.globalOrder, name)
	}
	return dir, nil
}

func stringField(m map[string]any, key, fallback string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return fallback
}

func boolField(m map[string]any, key string) (bool, bool) {
	if v, ok := m[key].(bool); ok {
		return v, true
	}
	return false, false
}

// observedProbe: the last history entry carries an integral delay in range.
func observedProbe(history []any) bool {
	if len(history) == 0 {
		return false
	}
	last, ok := history[len(history)-1].(map[string]any)
	if !ok {
		return false
	}
	delay, ok := last["delay"].(float64)
	return ok && delay == float64(int(delay)) && delay >= 0 && delay <= 65535
}

// nodeDirectory builds the sanitized identity list; duplicate names never
// overwrite provider entries.
func nodeDirectory(ctx context.Context, c *client) (*directory, error) {
	dir, err := globalProxies(ctx, c)
	if err != nil {
		return nil, err
	}
	for _, name := range dir.globalOrder {
		row := dir.row(name)
		if row.members {
			continue
		}
		stripped := map[string]any{}
		for k, v := range row.fields {
			if !strings.HasPrefix(k, "_") {
				stripped[k] = v
			}
		}
		stripped["provider"] = nil
		dir.targets = append(dir.targets, stripped)
	}
	raw, err := c.requestRaw(ctx, "/providers/proxies", requestOptions{optional: true})
	if err != nil {
		if ce, ok := err.(*controlError); ok && ce.code == "controller-capability-unsupported" {
			dir.capability = "unsupported"
			return dir, nil
		}
		return nil, err
	}
	var doc struct {
		Providers json.RawMessage `json:"providers"`
	}
	if json.Unmarshal(raw, &doc) != nil {
		return nil, control("controller-proxies-invalid", exitUnverify)
	}
	if len(doc.Providers) == 0 {
		return dir, nil
	}
	providerRows, _, err := decodeObject(doc.Providers)
	if err != nil {
		return nil, control("controller-providers-invalid", exitUnverify)
	}
	for _, prow := range providerRows {
		if _, err := label(prow.Key); err != nil {
			return nil, err
		}
		var data map[string]any
		if json.Unmarshal(prow.Value, &data) != nil {
			return nil, control("controller-providers-invalid", exitUnverify)
		}
		proxies, valid := arrayField(data, "proxies")
		if !valid {
			return nil, control("controller-providers-invalid", exitUnverify)
		}
		if stringField(data, "vehicleType", "") == "Compatible" {
			continue
		}
		seen := map[string]bool{}
		for _, item := range proxies {
			entry, ok := item.(map[string]any)
			if !ok {
				return nil, control("controller-providers-invalid", exitUnverify)
			}
			name, err := label(entry["name"])
			if err != nil {
				return nil, err
			}
			if seen[name] {
				return nil, control("controller-provider-node-ambiguous", exitUnverify)
			}
			seen[name] = true
			typeName, err := label(stringField(entry, "type", "unknown"))
			if err != nil {
				return nil, err
			}
			row := map[string]any{"name": name, "provider": prow.Key, "type": typeName}
			history, valid := arrayField(entry, "history")
			if !valid {
				return nil, control("controller-providers-invalid", exitUnverify)
			}
			row["probe_observed"] = observedProbe(history)
			if alive, ok := boolField(entry, "alive"); ok {
				row["alive"] = alive
			}
			dir.targets = append(dir.targets, row)
		}
	}
	return dir, nil
}

// proxiesTable merges the directory into the full annotated table.
func proxiesTable(ctx context.Context, c *client) ([]*proxyRow, *directory, error) {
	dir, err := nodeDirectory(ctx, c)
	if err != nil {
		return nil, nil, err
	}
	nameTargets := map[string][]map[string]any{}
	for _, t := range dir.targets {
		name, _ := t["name"].(string)
		nameTargets[name] = append(nameTargets[name], t)
	}
	for _, t := range dir.targets {
		name, _ := t["name"].(string)
		matches := nameTargets[name]
		if row := dir.row(name); row == nil {
			fields := map[string]any{}
			for k, v := range t {
				fields[k] = v
			}
			fields["ambiguous"] = len(matches) > 1
			dir.appendRow(name, &proxyRow{fields: fields})
		} else if !row.members && len(matches) > 1 {
			row.fields["ambiguous"] = true
		}
	}
	for _, name := range dir.rowOrder {
		row := dir.row(name)
		if !row.members {
			continue
		}
		memberTargets := []map[string]any{}
		index := map[string]int{}
		addTarget := func(entry map[string]any) {
			k := targetKey(entry)
			if i, ok := index[k]; ok {
				memberTargets[i] = entry
				return
			}
			index[k] = len(memberTargets)
			memberTargets = append(memberTargets, entry)
		}
		members, _ := row.fields["members"].([]any)
		for _, m := range members {
			memberName, _ := m.(string)
			var candidates []map[string]any
			if groupRow := dir.row(memberName); groupRow != nil && groupRow.members {
				candidates = []map[string]any{{"name": groupRow.fields["name"], "provider": nil}}
			} else {
				for _, t := range dir.targets {
					if n, _ := t["name"].(string); n == memberName {
						candidates = append(candidates, t)
					}
				}
				if len(candidates) == 0 {
					candidates = []map[string]any{{"name": memberName}}
				}
			}
			for _, cand := range candidates {
				entry := map[string]any{"name": cand["name"]}
				if p, ok := cand["provider"]; ok {
					entry["provider"] = p
				} else {
					entry["provider"] = nil
				}
				addTarget(entry)
			}
		}
		row.fields["member_targets"] = memberTargets
		row.fields["provider_capability"] = dir.capability
	}
	annotateRows(dir)
	rows := make([]*proxyRow, 0, len(dir.rowOrder))
	for _, name := range dir.rowOrder {
		row := dir.row(name)
		delete(row.fields, "_probe_states")
		delete(row.fields, "_test_url")
		rows = append(rows, row)
	}
	return rows, dir, nil
}

func targetKey(t map[string]any) string {
	p, _ := t["provider"].(string)
	n, _ := t["name"].(string)
	return p + "\x00" + n
}

func platformString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// annotateRows computes chain evidence, automatic candidates and warnings for
// every group row (controller_health.annotate).
func annotateRows(dir *directory) {
	groupNames := func() []string {
		var names []string
		for _, name := range dir.rowOrder {
			if dir.row(name).members {
				names = append(names, name)
			}
		}
		return names
	}
	for _, name := range groupNames() {
		row := dir.row(name)
		chain, state := selectedChain(dir, name)
		candidates := automaticCandidates(dir, name)
		automatic := []any{}
		for _, n := range chain {
			if s, ok := n.(string); ok {
				if r := dir.row(s); r != nil {
					if t, _ := r.fields["type"].(string); t == "URLTest" || t == "Fallback" {
						automatic = append(automatic, s)
					}
				}
			}
		}
		warnings := []any{}
		if state != "complete" {
			warnings = append(warnings, state)
		}
		members, _ := row.fields["members"].([]any)
		missing := []any{}
		for _, m := range members {
			memberName, _ := m.(string)
			if dir.row(memberName) == nil {
				missing = append(missing, memberName)
			}
		}
		missingCount := len(missing)
		if len(missing) > 5 {
			missing = missing[:5]
		}
		row.fields["missing_members"] = missing
		row.fields["missing_member_count"] = missingCount
		if missingCount > 0 {
			warnings = append(warnings, "missing-member-references")
		}
		selectable, _ := row.fields["selectable"].(bool)
		if selectable && len(automatic) == 0 && state == "complete" {
			if len(candidates) > 0 {
				warnings = append(warnings, "manual-path-bypasses-automatic")
			} else {
				warnings = append(warnings, "manual-path-no-automatic-candidate")
			}
		}
		if _, hasFixed := row.fields["fixed"]; hasFixed {
			warnings = append(warnings, "automatic-fixed-selection")
		}
		health := "unknown"
		if t, _ := row.fields["type"].(string); t == "URLTest" || t == "Fallback" {
			var memberRows []map[string]any
			testURL, hasURL := row.fields["_test_url"].(string)
			for _, m := range members {
				memberName, _ := m.(string)
				mr := dir.row(memberName)
				if mr == nil {
					memberRows = append(memberRows, map[string]any{})
					continue
				}
				if hasURL {
					states, _ := mr.fields["_probe_states"].(map[string]any)
					var stateRow map[string]any
					if states != nil {
						if s, ok := states[testURL].(map[string]any); ok {
							stateRow = s
						}
					}
					if stateRow == nil {
						memberRows = append(memberRows, map[string]any{})
						continue
					}
					alive, _ := stateRow["alive"].(bool)
					history, _ := stateRow["history"].([]any)
					memberRows = append(memberRows, map[string]any{"alive": alive, "probe_observed": observedProbe(history)})
				} else {
					memberRows = append(memberRows, mr.fields)
				}
			}
			var tested []map[string]any
			for _, mr := range memberRows {
				if observed, _ := mr["probe_observed"].(bool); observed {
					tested = append(tested, mr)
				}
			}
			if len(tested) == 0 {
				warnings = append(warnings, "no-probe-records")
			} else if len(memberRows) > 0 && len(tested) == len(memberRows) {
				allFailed := true
				for _, mr := range tested {
					if alive, ok := mr["alive"].(bool); !ok || alive {
						allFailed = false
					}
				}
				if allFailed {
					health = "all-observed-failed"
					warnings = append(warnings, health)
				}
			}
			if health != "all-observed-failed" {
				for _, mr := range tested {
					if alive, ok := mr["alive"].(bool); ok && alive {
						health = "observed-success"
						break
					}
				}
			}
		}
		row.fields["selection_chain"] = chain
		row.fields["chain_state"] = state
		row.fields["automatic_groups"] = automatic
		row.fields["automatic_candidates"] = candidates
		row.fields["affected_groups"] = affectedGroups(dir, name)
		row.fields["probe_state"] = health
		row.fields["warnings"] = warnings
	}
	for _, name := range groupNames() {
		row := dir.row(name)
		evidence := []any{}
		automatic, _ := row.fields["automatic_groups"].([]any)
		for _, n := range automatic {
			groupName, ok := n.(string)
			if !ok {
				continue
			}
			if g := dir.row(groupName); g != nil {
				evidence = append(evidence, map[string]any{
					"group":       groupName,
					"probe_state": g.fields["probe_state"],
					"warnings":    g.fields["warnings"],
				})
			}
		}
		row.fields["automatic_evidence"] = evidence
	}
}

// selectedChain walks the current selection (controller_health.selected_chain).
func selectedChain(dir *directory, start string) ([]any, string) {
	chain := []any{}
	seen := map[string]bool{}
	name := start
	for {
		if seen[name] {
			return append(chain, name), "cycle"
		}
		seen[name] = true
		chain = append(chain, name)
		row := dir.row(name)
		if row == nil {
			return chain, "missing-reference"
		}
		if ambiguous, _ := row.fields["ambiguous"].(bool); ambiguous {
			return chain, "ambiguous-reference"
		}
		if !row.members {
			return chain, "complete"
		}
		selected, _ := row.fields["selected"].(string)
		if selected == "" {
			return chain, "unknown-selection"
		}
		members, _ := row.fields["members"].([]any)
		inMembers := false
		for _, m := range members {
			if s, ok := m.(string); ok && s == selected {
				inMembers = true
			}
		}
		if !inMembers {
			return append(chain, selected), "selection-not-in-members"
		}
		name = selected
	}
}

// automaticCandidates finds one shortest existing path per automatic group.
func automaticCandidates(dir *directory, start string) []map[string]any {
	type queued struct {
		name string
		path []any
	}
	queue := []queued{{start, []any{start}}}
	seen := map[string]bool{start: true}
	// Non-nil even when empty: the parity contract renders this field as
	// [], never null.
	result := []map[string]any{}
	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]
		row := dir.row(item.name)
		var rowType string
		if row != nil {
			rowType, _ = row.fields["type"].(string)
		}
		if rowType == "URLTest" || rowType == "Fallback" {
			result = append(result, map[string]any{"group": item.name, "path": item.path})
			continue
		}
		if row == nil {
			continue
		}
		if selectable, _ := row.fields["selectable"].(bool); selectable {
			members, _ := row.fields["members"].([]any)
			for _, m := range members {
				memberName, ok := m.(string)
				if !ok || seen[memberName] {
					continue
				}
				seen[memberName] = true
				path := make([]any, 0, len(item.path)+1)
				path = append(path, item.path...)
				path = append(path, memberName)
				queue = append(queue, queued{memberName, path})
			}
		}
	}
	return result
}

// affectedGroups: groups whose current chain passes through the named group.
// Returns []any for payload uniformity, non-nil so the field renders as []
// rather than null.
func affectedGroups(dir *directory, group string) []any {
	names := []any{}
	for _, name := range dir.rowOrder {
		if name == group {
			continue
		}
		row := dir.row(name)
		if !row.members {
			continue
		}
		chain, _ := selectedChain(dir, name)
		for i, n := range chain {
			if i == 0 {
				continue
			}
			if s, ok := n.(string); ok && s == group {
				names = append(names, name)
				break
			}
		}
	}
	sort.Slice(names, func(i, j int) bool {
		a, _ := names[i].(string)
		b, _ := names[j].(string)
		return a < b
	})
	return names
}

// crossLevelSelection: a direct leaf choice in an aggregate group skips its
// subgroup layer.
func crossLevelSelection(dir *directory, group, node string) (bool, error) {
	row := dir.row(group)
	target := dir.row(node)
	if target == nil {
		return false, control("selection-target-unverified", exitUnverify)
	}
	if target.members || platformString(target.fields["type"]) == "Direct" {
		return false, nil
	}
	var members []any
	if row != nil {
		members, _ = row.fields["members"].([]any)
	}
	for _, m := range members {
		memberName, _ := m.(string)
		if mr := dir.row(memberName); mr != nil && mr.members {
			return true, nil
		}
	}
	return false, nil
}

// selectNode applies and read-back-verifies one Selector choice.
func selectNode(ctx context.Context, c *client, dir *directory, group, node string, allowCrossLevel bool) (map[string]any, error) {
	if dir == nil {
		var err error
		_, dir, err = proxiesTable(ctx, c)
		if err != nil {
			return nil, err
		}
	}
	groupRow := dir.row(group)
	if groupRow == nil || groupRow.fields["selectable"] != true {
		return nil, control("selection-requires-Selector-group", exitFail)
	}
	members, _ := groupRow.fields["members"].([]any)
	inGroup := false
	for _, m := range members {
		if s, ok := m.(string); ok && s == node {
			inGroup = true
		}
	}
	if !inGroup {
		return nil, control("node-not-in-group", exitFail)
	}
	count := 0
	if targets, ok := groupRow.fields["member_targets"].([]map[string]any); ok {
		for _, t := range targets {
			if n, _ := t["name"].(string); n == node {
				count++
			}
		}
	}
	if count > 1 {
		return nil, control("ambiguous-node", exitFail)
	}
	cross, err := crossLevelSelection(dir, group, node)
	if err != nil {
		return nil, err
	}
	if cross && !allowCrossLevel {
		return nil, control("cross-level-selection-refused", exitUnverify)
	}
	if _, err := c.request(ctx, "/proxies/"+url.PathEscape(group), requestOptions{method: "PUT", body: map[string]any{"name": node}, optional: true}); err != nil {
		return nil, err
	}
	_, fresh, err := proxiesTable(ctx, c)
	if err != nil {
		return nil, err
	}
	var selected any
	if row := fresh.row(group); row != nil {
		selected = row.fields["selected"]
	}
	if s, _ := selected.(string); s != node {
		return nil, control("selection-not-confirmed", exitFail)
	}
	return map[string]any{
		"group":                group,
		"selected":             node,
		"existing_connections": "unchanged",
		"affected_groups":      affectedGroups(fresh, group),
	}, nil
}

var delayErrorCodes = map[int]string{
	404: "node-not-in-core",
	405: "controller-capability-unsupported",
	501: "controller-capability-unsupported",
	503: "node-unreachable",
	504: "delay-timeout",
}

// measureDelay probes one exact node identity against the public target.
func measureDelay(ctx context.Context, c *client, node string, provider *string) (map[string]any, error) {
	prefix := "/proxies/"
	if provider != nil {
		prefix = "/providers/proxies/" + url.PathEscape(*provider) + "/"
	}
	path := prefix + url.PathEscape(node)
	if provider != nil {
		path += "/healthcheck"
	} else {
		path += "/delay"
	}
	query := url.Values{"timeout": {"5000"}, "url": {testURL}}
	raw, err := c.requestRaw(ctx, path+"?"+query.Encode(), requestOptions{statusCodes: delayErrorCodes})
	if err != nil {
		return nil, err
	}
	_, fields, err := decodeObject(raw)
	if err != nil {
		return nil, control("controller-response-invalid", exitUnverify)
	}
	delay := any(nil)
	if value, present := fields["delay"]; present {
		var decoded any
		if json.Unmarshal(value, &decoded) != nil {
			return nil, control("controller-response-invalid", exitUnverify)
		}
		delay, err = number(decoded)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, control("controller-response-invalid-number", exitUnverify)
	}
	var providerField any
	if provider != nil {
		providerField = *provider
	}
	return map[string]any{
		"name":          node,
		"provider":      providerField,
		"delay_ms":      delay,
		"target":        testURL,
		"model_request": "UNVERIFIED",
		"sampled_at":    float64(time.Now().UnixNano()) / 1e9,
	}, nil
}

// numberField reads a numeric field from a raw JSON object; a missing or null
// field fails the number contract (the original number(None) behavior).
func numberField(fields map[string]json.RawMessage, key string) (any, error) {
	value, present := fields[key]
	if !present || len(value) == 0 || string(value) == "null" {
		return nil, control("controller-response-invalid-number", exitUnverify)
	}
	var decoded any
	if json.Unmarshal(value, &decoded) != nil {
		return nil, control("controller-response-invalid", exitUnverify)
	}
	return number(decoded)
}

// numberFieldDefault treats a missing field as zero; an explicit null still
// fails the number contract (number(None) in the original).
func numberFieldDefault(fields map[string]json.RawMessage, key string) (any, error) {
	value, present := fields[key]
	if !present {
		return 0, nil
	}
	if len(value) == 0 || string(value) == "null" {
		return nil, control("controller-response-invalid-number", exitUnverify)
	}
	var decoded any
	if json.Unmarshal(value, &decoded) != nil {
		return nil, control("controller-response-invalid", exitUnverify)
	}
	return number(decoded)
}

// nodeTarget resolves a node query or qualified identity against the
// directory exactly like _node_target.
func nodeTarget(dir *directory, node string, provider *string, qualified bool) (map[string]any, error) {
	if provider != nil {
		if _, err := label(*provider); err != nil {
			return nil, err
		}
	}
	var choices []map[string]any
	for _, t := range dir.targets {
		name, _ := t["name"].(string)
		if name != node {
			continue
		}
		if !qualified {
			choices = append(choices, t)
			continue
		}
		tp, _ := t["provider"].(string)
		if provider != nil {
			if tp == *provider {
				choices = append(choices, t)
			}
		} else if t["provider"] == nil {
			choices = append(choices, t)
		}
	}
	if provider == nil {
		if row := dir.row(node); row != nil && row.members {
			choices = append(choices, map[string]any{"name": node, "provider": nil})
		}
	}
	if len(choices) == 0 {
		if provider != nil && dir.capability == "unsupported" {
			return nil, control("controller-capability-unsupported", exitUnverify)
		}
		safe := requestLabel(node)
		detail := safe
		if safe == node {
			detail = "'" + node + "'"
		}
		return nil, controlDetail("unknown-node", detail, exitFail)
	}
	if len(choices) != 1 {
		return nil, control("ambiguous-node", exitFail)
	}
	return choices[0], nil
}

// latencyTarget resolves and probes one node, refining provider 404s.
func latencyTarget(ctx context.Context, c *client, node string, provider *string, qualified bool, pre *directory) (map[string]any, error) {
	dir := pre
	if dir == nil {
		var err error
		dir, err = nodeDirectory(ctx, c)
		if err != nil {
			return nil, err
		}
	}
	chosen, err := nodeTarget(dir, node, provider, qualified)
	if err != nil {
		return nil, err
	}
	name, _ := chosen["name"].(string)
	var chosenProvider *string
	if p, ok := chosen["provider"].(string); ok {
		chosenProvider = &p
	}
	result, err := measureDelay(ctx, c, name, chosenProvider)
	if err == nil {
		return result, nil
	}
	ce, ok := err.(*controlError)
	if !ok || ce.code != "node-not-in-core" || chosenProvider == nil {
		return nil, err
	}
	fresh, freshErr := nodeDirectory(ctx, c)
	if freshErr != nil {
		return nil, err
	}
	exists := false
	for _, t := range fresh.targets {
		n, _ := t["name"].(string)
		p, _ := t["provider"].(string)
		if n == name && p == *chosenProvider {
			exists = true
		}
	}
	if exists || fresh.capability == "unsupported" {
		return nil, control("controller-capability-unsupported", exitUnverify)
	}
	return nil, control("node-disappeared", exitFail)
}

// snapshot serves the nodes/groups/connections/traffic CLI reads.
func snapshot(ctx context.Context, c *client, command string, details bool) (map[string]any, error) {
	switch command {
	case "nodes":
		dir, err := nodeDirectory(ctx, c)
		if err != nil {
			return nil, err
		}
		nodes := make([]any, 0, len(dir.targets))
		for _, t := range dir.targets {
			nodes = append(nodes, t)
		}
		return map[string]any{"nodes": nodes}, nil
	case "groups":
		rows, _, err := proxiesTable(ctx, c)
		if err != nil {
			return nil, err
		}
		groups := []any{}
		for _, r := range rows {
			if r.members {
				groups = append(groups, r.fields)
			}
		}
		return map[string]any{"groups": groups}, nil
	case "traffic":
		raw, err := c.requestFirstLine(ctx, "/traffic", requestOptions{optional: true})
		if err != nil {
			return nil, err
		}
		_, fields, err := decodeObject(raw)
		if err != nil && len(raw) > 0 {
			return nil, control("controller-response-invalid", exitUnverify)
		}
		out := map[string]any{}
		for _, k := range []string{"up", "down", "upTotal", "downTotal"} {
			n, err := numberFieldDefault(fields, k)
			if err != nil {
				return nil, err
			}
			out[k] = n
		}
		return out, nil
	case "connections":
		rawMap, err := c.request(ctx, "/connections", requestOptions{optional: true})
		if err != nil {
			return nil, err
		}
		connections, ok := rawMap["connections"].([]any)
		if rawMap["connections"] != nil && !ok {
			return nil, control("controller-connections-invalid", exitUnverify)
		}
		rows := []any{}
		for _, item := range connections {
			entry, ok := item.(map[string]any)
			if !ok {
				return nil, control("controller-connections-invalid", exitUnverify)
			}
			chains, valid := arrayField(entry, "chains")
			if !valid {
				return nil, control("controller-connections-invalid", exitUnverify)
			}
			chainNames := []any{}
			for _, n := range chains {
				ln, err := label(n)
				if err != nil {
					return nil, err
				}
				chainNames = append(chainNames, ln)
			}
			rule, err := label(stringField(entry, "rule", ""))
			if err != nil {
				return nil, err
			}
			upload, err := numberFieldDefault(entryNumbers(entry), "upload")
			if err != nil {
				return nil, err
			}
			download, err := numberFieldDefault(entryNumbers(entry), "download")
			if err != nil {
				return nil, err
			}
			row := map[string]any{
				"chains":   chainNames,
				"rule":     rule,
				"upload":   upload,
				"download": download,
			}
			if details {
				metadata, _ := entry["metadata"].(map[string]any)
				if entry["metadata"] != nil && metadata == nil {
					return nil, control("controller-connections-invalid", exitUnverify)
				}
				host := ""
				if metadata != nil {
					host = stringField(metadata, "host", "")
				}
				lh, err := label(host)
				if err != nil {
					return nil, err
				}
				row["host"] = lh
				rulePayload, err := label(stringField(entry, "rulePayload", ""))
				if err != nil {
					return nil, err
				}
				row["rule_payload"] = rulePayload
			}
			rows = append(rows, row)
		}
		uploadTotal, err := numberFieldDefault(entryNumbers(rawMap), "uploadTotal")
		if err != nil {
			return nil, err
		}
		downloadTotal, err := numberFieldDefault(entryNumbers(rawMap), "downloadTotal")
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"connections":   rows,
			"uploadTotal":   uploadTotal,
			"downloadTotal": downloadTotal,
		}, nil
	}
	return nil, control("invalid-options", exitUnverify)
}

func entryNumbers(m map[string]any) map[string]json.RawMessage {
	out := map[string]json.RawMessage{}
	for k, v := range m {
		raw, err := json.Marshal(v)
		if err == nil {
			out[k] = raw
		}
	}
	return out
}

// modeCommand changes the running core routing mode.
func modeCommand(ctx context.Context, c *client, mode string) (map[string]any, error) {
	if mode != "rule" && mode != "global" && mode != "direct" {
		return nil, control("invalid-core-mode", exitFail)
	}
	if _, err := c.request(ctx, "/configs", requestOptions{method: "PATCH", body: map[string]any{"mode": mode}, optional: true}); err != nil {
		return nil, err
	}
	raw, err := c.request(ctx, "/configs", requestOptions{optional: true})
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(platformString(raw["mode"]), mode) {
		return nil, control("mode-not-confirmed", exitFail)
	}
	return map[string]any{"mode": mode, "scope": "runtime-only", "shell": "unchanged", "config": "unchanged"}, nil
}

// dnsCommand queries DNS through the controller.
func dnsCommand(ctx context.Context, c *client, name, record string) (map[string]any, error) {
	if !dnsNamePattern.MatchString(name) {
		return nil, control("invalid-dns-query", exitFail)
	}
	switch record {
	case "A", "AAAA", "CNAME", "TXT", "MX":
	default:
		return nil, control("invalid-dns-query", exitFail)
	}
	query := url.Values{"name": {name}, "type": {record}}
	raw, err := c.request(ctx, "/dns/query?"+query.Encode(), requestOptions{optional: true})
	if err != nil {
		return nil, err
	}
	answer, ok := raw["Answer"].([]any)
	if raw["Answer"] != nil && !ok {
		return nil, control("controller-dns-invalid", exitUnverify)
	}
	answers := []any{}
	for _, item := range answer {
		row, ok := item.(map[string]any)
		if !ok {
			continue
		}
		numbers := entryNumbers(row)
		qtype, err := numberFieldDefault(numbers, "type")
		if err != nil {
			return nil, err
		}
		ttl, err := numberFieldDefault(numbers, "TTL")
		if err != nil {
			return nil, err
		}
		data, err := label(stringField(row, "data", ""))
		if err != nil {
			return nil, err
		}
		answers = append(answers, map[string]any{"type": qtype, "ttl": ttl, "data": data})
	}
	return map[string]any{"query": name, "record": record, "answers": answers, "system_dns": "unchanged"}, nil
}

// providerRows lists proxy providers and their state.
func providerRows(ctx context.Context, c *client) ([]map[string]any, error) {
	raw, err := c.requestRaw(ctx, "/providers/proxies", requestOptions{optional: true})
	if err != nil {
		return nil, err
	}
	var doc struct {
		Providers json.RawMessage `json:"providers"`
	}
	if json.Unmarshal(raw, &doc) != nil {
		return nil, control("controller-proxies-invalid", exitUnverify)
	}
	result := []map[string]any{}
	if len(doc.Providers) == 0 {
		return result, nil
	}
	rows, _, err := decodeObject(doc.Providers)
	if err != nil {
		return nil, control("controller-proxies-invalid", exitUnverify)
	}
	for _, prow := range rows {
		var data map[string]any
		if json.Unmarshal(prow.Value, &data) != nil {
			return nil, control("controller-providers-invalid", exitUnverify)
		}
		proxies, valid := arrayField(data, "proxies")
		if !valid {
			return nil, control("controller-providers-invalid", exitUnverify)
		}
		vehicle, err := label(stringField(data, "vehicleType", "unknown"))
		if err != nil {
			return nil, err
		}
		updated, err := label(stringField(data, "updatedAt", "unknown"))
		if err != nil {
			return nil, err
		}
		result = append(result, map[string]any{
			"name":    prow.Key,
			"type":    vehicle,
			"nodes":   len(proxies),
			"updated": updated,
		})
	}
	return result, nil
}

// providerRefresh requests one provider refresh.
func providerRefresh(ctx context.Context, c *client, name string) (map[string]any, error) {
	if _, err := label(name); err != nil {
		return nil, err
	}
	rows, err := providerRows(ctx, c)
	if err != nil {
		return nil, err
	}
	found := false
	for _, row := range rows {
		if row["name"] == name {
			found = true
		}
	}
	if !found {
		return nil, control("unknown-provider", exitFail)
	}
	if _, err := c.request(ctx, "/providers/proxies/"+url.PathEscape(name), requestOptions{method: "PUT", optional: true}); err != nil {
		return nil, err
	}
	return map[string]any{"provider": name, "state": "refresh-requested"}, nil
}
