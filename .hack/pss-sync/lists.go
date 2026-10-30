package main

import (
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

const wrapWidth = 90

var (
	listLiteral = regexp.MustCompile(`\[([^\[\]]*)\]`)
	quotedItems = regexp.MustCompile(`^\s*'[^'\\]*'(\s*,\s*'[^'\\]*')*\s*$`)
	quotedItem  = regexp.MustCompile(`'([^'\\]*)'`)
)

// ListChange is the result of one list rule.
type ListChange struct {
	Rule    ListRule
	Path    string
	Old     []string
	New     []string
	Added   []string
	Removed []string
}

func parseItems(s string) ([]string, bool) {
	if !quotedItems.MatchString(s) {
		return nil, false
	}
	var items []string
	for _, m := range quotedItem.FindAllStringSubmatch(s, -1) {
		items = append(items, m[1])
	}
	return items, true
}

func walkStrings(v any, fn func(string)) {
	switch t := v.(type) {
	case string:
		fn(t)
	case map[string]any:
		for _, x := range t {
			walkStrings(x, fn)
		}
	case []any:
		for _, x := range t {
			walkStrings(x, fn)
		}
	}
}

func sameSet(a, b []string) bool {
	x, y := slices.Clone(a), slices.Clone(b)
	sort.Strings(x)
	sort.Strings(y)
	return slices.Equal(slices.Compact(x), slices.Compact(y))
}

// chartList returns the chart list literal that contains rule.Anchor, without ignored values.
// Every list literal with the anchor must hold the same values.
func chartList(r Rendered, rule ListRule) ([]string, error) {
	var found [][]string
	walkStrings(r.Doc["spec"], func(s string) {
		for _, m := range listLiteral.FindAllStringSubmatch(s, -1) {
			if items, ok := parseItems(m[1]); ok && slices.Contains(items, rule.Anchor) {
				found = append(found, items)
			}
		}
	})
	if len(found) == 0 {
		return nil, fmt.Errorf("chart policy %s has no list with %q", rule.Policy, rule.Anchor)
	}
	for _, f := range found[1:] {
		if !sameSet(found[0], f) {
			return nil, fmt.Errorf("chart policy %s has different lists with %q", rule.Policy, rule.Anchor)
		}
	}
	var out []string
	for _, v := range found[0] {
		if !slices.Contains(rule.Ignore, v) && !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out, nil
}

// mergeList orders the chart values for the standalone policy.
func mergeList(old, chart []string, order string) []string {
	var out []string
	if order == "sorted" {
		out = slices.Clone(chart)
		sort.Strings(out)
		return out
	}
	for _, v := range old {
		if slices.Contains(chart, v) {
			out = append(out, v)
		}
	}
	for _, v := range chart {
		if !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}

func diff(a, b []string) []string {
	var out []string
	for _, v := range a {
		if !slices.Contains(b, v) {
			out = append(out, v)
		}
	}
	return out
}

// phrase writes values the way a message lists them, for example "a, b, and c".
func phrase(items []string, conjunction string) string {
	if conjunction == "" || len(items) < 2 {
		return strings.Join(items, ", ")
	}
	if len(items) == 2 {
		return items[0] + " " + conjunction + " " + items[1]
	}
	return strings.Join(items[:len(items)-1], ", ") + ", " + conjunction + " " + items[len(items)-1]
}

func normalize(s string) string { return strings.Join(strings.Fields(s), " ") }

func mapValue(m *yaml.Node, key string) (*yaml.Node, *yaml.Node) {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil, nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i], m.Content[i+1]
		}
	}
	return nil, nil
}

func specNode(root *yaml.Node) *yaml.Node {
	if root.Kind != yaml.DocumentNode || len(root.Content) == 0 {
		return nil
	}
	_, spec := mapValue(root.Content[0], "spec")
	return spec
}

func findVariable(root *yaml.Node, name string) (*yaml.Node, *yaml.Node, error) {
	_, vars := mapValue(specNode(root), "variables")
	if vars == nil || vars.Kind != yaml.SequenceNode {
		return nil, nil, fmt.Errorf("no spec.variables")
	}
	var key, val *yaml.Node
	for _, v := range vars.Content {
		if _, n := mapValue(v, "name"); n != nil && n.Value == name {
			if key != nil {
				return nil, nil, fmt.Errorf("variable %s is defined twice", name)
			}
			key, val = mapValue(v, "expression")
		}
	}
	if key == nil {
		return nil, nil, fmt.Errorf("no variable %s", name)
	}
	return key, val, nil
}

func findMessage(root *yaml.Node, index int) (*yaml.Node, *yaml.Node, error) {
	_, vals := mapValue(specNode(root), "validations")
	if vals == nil || vals.Kind != yaml.SequenceNode || index >= len(vals.Content) {
		return nil, nil, fmt.Errorf("no spec.validations[%d]", index)
	}
	key, val := mapValue(vals.Content[index], "message")
	if key == nil {
		return nil, nil, fmt.Errorf("spec.validations[%d] has no message", index)
	}
	return key, val, nil
}

// edit replaces the lines of one key and its value.
type edit struct {
	start, end int // 0-based, inclusive
	lines      []string
}

func indentOf(l string) int { return len(l) - len(strings.TrimLeft(l, " ")) }

// blockRange returns the lines of the key at key.Line and its value.
func blockRange(lines []string, key *yaml.Node) (int, int) {
	start, indent := key.Line-1, key.Column-1
	end := start
	for i := start + 1; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == "" {
			continue
		}
		if indentOf(lines[i]) <= indent {
			break
		}
		end = i
	}
	return start, end
}

// wrap fills tokens into lines no wider than wrapWidth. Continuation lines get extra indent.
func wrap(pad, extra string, tokens []string, sep string) []string {
	var lines []string
	line := pad
	for _, t := range tokens {
		switch {
		case line == pad || line == pad+extra:
			line += t
		case len(line)+len(sep)+len(t) > wrapWidth:
			lines = append(lines, line)
			line = pad + extra + t
		default:
			line += sep + t
		}
	}
	return append(lines, line)
}

func listEdit(lines []string, key, val *yaml.Node, items []string) (edit, error) {
	start, end := blockRange(lines, key)
	pad := strings.Repeat(" ", key.Column-1)
	sep := ","
	if strings.Contains(val.Value, "', '") {
		sep = ", "
	}
	quoted := make([]string, len(items))
	for i, v := range items {
		quoted[i] = "'" + v + "'"
	}
	literal := "[" + strings.Join(quoted, sep) + "]"
	switch val.Style {
	case yaml.DoubleQuotedStyle:
		return edit{start, end, []string{pad + "expression: \"" + literal + "\""}}, nil
	case yaml.FoldedStyle, yaml.LiteralStyle:
		header := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(lines[start]), "expression:"))
		out := []string{pad + "expression: " + header}
		content := pad + "  "
		if strings.Count(strings.TrimSpace(val.Value), "\n") == 0 {
			return edit{start, end, append(out, content+literal)}, nil
		}
		// Keep the existing layout: "[" on the first line, continuation lines one space deeper.
		tokens := make([]string, len(quoted))
		for i, q := range quoted {
			tokens[i] = q + ","
		}
		tokens[0] = "[" + tokens[0]
		tokens[len(tokens)-1] = strings.TrimSuffix(tokens[len(tokens)-1], ",") + "]"
		return edit{start, end, append(out, wrap(content, " ", tokens, strings.TrimPrefix(sep, ","))...)}, nil
	}
	return edit{}, fmt.Errorf("unsupported YAML style for the expression of %s", key.Value)
}

func messageEdit(lines []string, key, val *yaml.Node, text string) (edit, error) {
	if val.Style != yaml.FoldedStyle {
		return edit{}, fmt.Errorf("the message must be a folded (>-) string")
	}
	start, end := blockRange(lines, key)
	pad := strings.Repeat(" ", key.Column-1)
	header := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(lines[start]), "message:"))
	out := []string{pad + "message: " + header}
	return edit{start, end, append(out, wrap(pad+"  ", "", strings.Fields(text), " ")...)}, nil
}

// syncList computes the new text of one policy file for one rule. It returns the old text
// unchanged when the list already matches the chart.
func syncList(text string, chart []string, rule ListRule) (string, *ListChange, error) {
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(text), &root); err != nil {
		return "", nil, err
	}
	key, val, err := findVariable(&root, rule.Variable)
	if err != nil {
		return "", nil, err
	}
	old, ok := parseItems(strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(val.Value), "["), "]"))
	if !ok || !strings.HasPrefix(strings.TrimSpace(val.Value), "[") || !strings.HasSuffix(strings.TrimSpace(val.Value), "]") {
		return "", nil, fmt.Errorf("variable %s is not a list of quoted strings", rule.Variable)
	}
	change := &ListChange{Rule: rule, Old: old, Added: diff(chart, old), Removed: diff(old, chart)}
	if len(change.Added) == 0 && len(change.Removed) == 0 {
		change.New = old
		return text, change, nil
	}
	change.New = mergeList(old, chart, rule.Order)

	eol := "\n"
	if strings.Contains(text, "\r\n") {
		eol = "\r\n"
	}
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	e, err := listEdit(lines, key, val, change.New)
	if err != nil {
		return "", nil, err
	}
	edits := []edit{e}
	var wantMessage string
	if rule.Message != nil {
		mkey, mval, err := findMessage(&root, rule.Message.Validation)
		if err != nil {
			return "", nil, err
		}
		msg, oldPhrase := normalize(mval.Value), phrase(old, rule.Message.Conjunction)
		if n := strings.Count(msg, oldPhrase); n != 1 {
			return "", nil, fmt.Errorf("the message of validation %d lists the values %d times, want exactly once: %q", rule.Message.Validation, n, oldPhrase)
		}
		wantMessage = strings.Replace(msg, oldPhrase, phrase(change.New, rule.Message.Conjunction), 1)
		me, err := messageEdit(lines, mkey, mval, wantMessage)
		if err != nil {
			return "", nil, err
		}
		edits = append(edits, me)
	}
	sort.Slice(edits, func(i, j int) bool { return edits[i].start > edits[j].start })
	for i := 1; i < len(edits); i++ {
		if edits[i].end >= edits[i-1].start {
			return "", nil, fmt.Errorf("the list and the message overlap")
		}
	}
	for _, e := range edits {
		lines = append(lines[:e.start], append(slices.Clone(e.lines), lines[e.end+1:]...)...)
	}
	out := strings.Join(lines, "\n")
	if eol != "\n" {
		out = strings.ReplaceAll(out, "\n", eol)
	}
	if err := verifyEdit(text, out, rule, change.New, wantMessage); err != nil {
		return "", nil, fmt.Errorf("value check failed, nothing was written: %w", err)
	}
	return out, change, nil
}

// verifyEdit parses both texts and checks that only the list and the message changed.
func verifyEdit(before, after string, rule ListRule, items []string, message string) error {
	var a, b yaml.Node
	if err := yaml.Unmarshal([]byte(before), &a); err != nil {
		return err
	}
	if err := yaml.Unmarshal([]byte(after), &b); err != nil {
		return err
	}
	_, val, err := findVariable(&b, rule.Variable)
	if err != nil {
		return err
	}
	got, ok := parseItems(strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(val.Value), "["), "]"))
	if !ok || !slices.Equal(got, items) {
		return fmt.Errorf("variable %s is %q, want %q", rule.Variable, got, items)
	}
	_, oldVal, _ := findVariable(&a, rule.Variable)
	oldVal.Value, val.Value = "", ""
	if rule.Message != nil {
		_, mval, err := findMessage(&b, rule.Message.Validation)
		if err != nil {
			return err
		}
		if normalize(mval.Value) != message || strings.Contains(mval.Value, "\n") {
			return fmt.Errorf("message is %q, want %q", mval.Value, message)
		}
		_, oldMsg, _ := findMessage(&a, rule.Message.Validation)
		oldMsg.Value, mval.Value = "", ""
	}
	var x, y any
	if err := a.Decode(&x); err != nil {
		return err
	}
	if err := b.Decode(&y); err != nil {
		return err
	}
	if !reflect.DeepEqual(x, y) {
		return fmt.Errorf("fields other than %s and its message changed", rule.Variable)
	}
	return nil
}
