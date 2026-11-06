// Command pss-sync keeps pod-security-vpol aligned with the Pod Security Standards policies of
// the kyverno-policies Helm chart. sync.sh runs it; see README.md.
//
//	pss-sync compare  --config FILE --render DIR --policies DIR [--write] --report FILE --chart-out FILE --pods-out FILE
//	pss-sync expected --config FILE --set chart|pod-security-vpol --version 1.x --resources FILE --policy FILE...
//
// compare exits 0 when the allow-lists match the chart, 3 when they differ, and 1 on an error.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: pss-sync compare|expected [flags]")
		os.Exit(1)
	}
	var code int
	var err error
	switch os.Args[1] {
	case "compare":
		code, err = compare(os.Args[2:])
	case "expected":
		err = expected(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "pss-sync:", err)
		os.Exit(1)
	}
	os.Exit(code)
}

func compare(args []string) (int, error) {
	fs := flag.NewFlagSet("compare", flag.ContinueOnError)
	configPath := fs.String("config", "", "config.yaml")
	renderDir := fs.String("render", "", "directory with baseline.yaml and restricted.yaml from helm template")
	root := fs.String("policies", "", "kyverno/policies root to read and, with --write, update")
	write := fs.Bool("write", false, "write the updated allow-lists")
	reportPath := fs.String("report", "", "Markdown report to write")
	chartOut := fs.String("chart-out", "", "file to write the selected chart policies to")
	podsOut := fs.String("pods-out", "", "file to write the boundary Pods and the fixture Pods to")
	if err := fs.Parse(args); err != nil {
		return 1, err
	}
	cfg, err := loadConfig(*configPath)
	if err != nil {
		return 1, err
	}
	render, err := loadRender(*renderDir)
	if err != nil {
		return 1, err
	}
	local, err := standalone(*root)
	if err != nil {
		return 1, err
	}
	var report strings.Builder
	defer func() {
		if *reportPath != "" {
			_ = os.WriteFile(*reportPath, []byte(report.String()), 0o644)
		}
	}()
	if problems := comparePolicySets(cfg, render, local); len(problems) > 0 {
		report.WriteString("### Policies that can't be synced automatically\n\n")
		for _, p := range problems {
			report.WriteString("- " + p + "\n")
		}
		return 1, fmt.Errorf("the chart and pod-security-vpol have different policies, see the report")
	}

	files := map[string]string{} // path -> new text
	var changes []*ListChange
	values := map[string][]string{}
	var failures []string
	for _, rule := range cfg.Lists {
		r := render[rule.Policy]
		chart, err := chartList(r, rule)
		if err != nil {
			failures = append(failures, fmt.Sprintf("`%s`: %v", rule.Policy, err))
			continue
		}
		path := policyFile(*root, local[rule.Policy], rule.Policy)
		text, ok := files[path]
		if !ok {
			data, err := os.ReadFile(path)
			if err != nil {
				return 1, err
			}
			text = string(data)
		}
		updated, change, err := syncList(text, chart, rule)
		if err != nil {
			failures = append(failures, fmt.Sprintf("`%s`: %v", rule.Policy, err))
			continue
		}
		// A second run on the result must change nothing.
		if again, _, err := syncList(updated, chart, rule); err != nil || again != updated {
			failures = append(failures, fmt.Sprintf("`%s`: a second update changes the file again (%v)", rule.Policy, err))
			continue
		}
		files[path] = updated
		change.Path = path
		changes = append(changes, change)
		values[rule.Policy] = mergeList(change.Old, chart, "keep")
	}
	if len(failures) > 0 {
		report.WriteString("### Allow-lists that can't be updated automatically\n\n")
		for _, f := range failures {
			report.WriteString("- " + f + "\n")
		}
		return 1, fmt.Errorf("some allow-lists can't be updated, see the report")
	}

	changed := slices.DeleteFunc(slices.Clone(changes), func(c *ListChange) bool { return len(c.Added)+len(c.Removed) == 0 })
	if len(changed) == 0 {
		report.WriteString("### Allow-lists\n\nAll allow-lists match the chart.\n")
	} else {
		report.WriteString("### Allow-lists\n\n| Policy | Variable | Added | Removed |\n|---|---|---|---|\n")
		for _, c := range changed {
			fmt.Fprintf(&report, "| `%s` | `%s` | %s | %s |\n", c.Rule.Policy, c.Rule.Variable, codeList(c.Added), codeList(c.Removed))
		}
	}
	if len(cfg.KnownDifferences) > 0 {
		report.WriteString("\n### Known differences\n\nThe behavior check skips these pairs, from `.hack/pss-sync/config.yaml`.\n\n" +
			"| Policy | Pod | Skipped in | Reason |\n|---|---|---|---|\n")
		for _, d := range cfg.KnownDifferences {
			in := d.In
			if in == "" {
				in = "both"
			}
			fmt.Fprintf(&report, "| `%s` | `%s` | %s | %s |\n", d.Policy, d.Pod, in, normalize(d.Reason))
		}
	}
	if *write {
		for _, c := range changed {
			if err := os.WriteFile(c.Path, []byte(files[c.Path]), 0o644); err != nil {
				return 1, err
			}
		}
	}
	if *chartOut != "" {
		var names []string
		for n := range render {
			names = append(names, n)
		}
		sort.Strings(names)
		var docs []string
		for _, n := range names {
			docs = append(docs, render[n].Raw)
		}
		if err := os.WriteFile(*chartOut, []byte(strings.Join(docs, "\n---\n")+"\n"), 0o644); err != nil {
			return 1, err
		}
	}
	if *podsOut != "" {
		fixtures, err := fixturePods(*root, local)
		if err != nil {
			return 1, err
		}
		if err := os.WriteFile(*podsOut, []byte(boundaryPods(cfg.Lists, values)+"---\n"+fixtures), 0o644); err != nil {
			return 1, err
		}
	}
	if len(changed) > 0 {
		return 3, nil
	}
	return 0, nil
}

func codeList(items []string) string {
	if len(items) == 0 {
		return "none"
	}
	return "`" + strings.Join(items, "`, `") + "`"
}

func expected(args []string) error {
	fs := flag.NewFlagSet("expected", flag.ContinueOnError)
	configPath := fs.String("config", "", "config.yaml")
	version := fs.String("version", "", "PSA version, 1.x")
	resources := fs.String("resources", "", "resources file, relative to the test file")
	set := fs.String("set", "", "chart or pod-security-vpol, for known differences")
	var policyFiles multi
	fs.Var(&policyFiles, "policy", "policy file, relative to the test file (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadConfig(*configPath)
	if err != nil {
		return err
	}
	if *set != "chart" && *set != "pod-security-vpol" {
		return fmt.Errorf("--set must be chart or pod-security-vpol")
	}
	minor, err := parseMinor(*version)
	if err != nil {
		return err
	}
	pods, err := readPods(*resources)
	if err != nil {
		return err
	}
	out, err := expectedTest(cfg, *set, minor, filepath.Base(*resources), policyFiles, pods)
	if err != nil {
		return err
	}
	fmt.Print(out)
	return nil
}
