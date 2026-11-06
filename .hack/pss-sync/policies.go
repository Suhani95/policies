package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

var profiles = []string{"baseline", "restricted"}

var docSeparator = regexp.MustCompile(`(?m)^---[ \t]*\r?$`)

// Rendered is one chart policy from a helm template render.
type Rendered struct {
	Profile string
	Raw     string
	Doc     map[string]any
}

func bytesReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }

func category(profile string) string {
	return "Pod Security Standards (" + strings.ToUpper(profile[:1]) + profile[1:] + ")"
}

// loadRender reads <dir>/baseline.yaml and <dir>/restricted.yaml. Baseline policies come
// from the Baseline render, Restricted policies from the Restricted render.
func loadRender(dir string) (map[string]Rendered, error) {
	out := map[string]Rendered{}
	for _, profile := range profiles {
		path := filepath.Join(dir, profile+".yaml")
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		for _, raw := range docSeparator.Split(string(data), -1) {
			var doc map[string]any
			if err := yaml.Unmarshal([]byte(raw), &doc); err != nil {
				return nil, fmt.Errorf("%s: %w", path, err)
			}
			if doc == nil {
				continue
			}
			meta, _ := doc["metadata"].(map[string]any)
			name, _ := meta["name"].(string)
			annotations, _ := meta["annotations"].(map[string]any)
			cat, _ := annotations["policies.kyverno.io/category"].(string)
			if doc["kind"] != "ValidatingPolicy" {
				return nil, fmt.Errorf("%s: %s is a %v, want ValidatingPolicy", path, name, doc["kind"])
			}
			if v := doc["apiVersion"]; v != "policies.kyverno.io/v1" && v != "policies.kyverno.io/v1beta1" {
				return nil, fmt.Errorf("%s: %s has unknown apiVersion %v", path, name, v)
			}
			if cat != category(profile) {
				if profile == "restricted" && cat == category("baseline") {
					continue
				}
				return nil, fmt.Errorf("%s: %s has category %q, want %q", path, name, cat, category(profile))
			}
			if _, dup := out[name]; dup {
				return nil, fmt.Errorf("%s: duplicate policy %s", path, name)
			}
			out[name] = Rendered{Profile: profile, Raw: strings.TrimSpace(raw), Doc: doc}
		}
	}
	return out, nil
}

// standalone returns the profile of each policy directory in pod-security-vpol.
func standalone(root string) (map[string]string, error) {
	out := map[string]string{}
	for _, profile := range profiles {
		entries, err := os.ReadDir(filepath.Join(root, "pod-security-vpol", profile))
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			if _, err := os.Stat(policyFile(root, profile, e.Name())); err != nil {
				return nil, fmt.Errorf("pod-security-vpol/%s/%s has no %s.yaml", profile, e.Name(), e.Name())
			}
			out[e.Name()] = profile
		}
	}
	return out, nil
}

func policyFile(root, profile, name string) string {
	return filepath.Join(root, "pod-security-vpol", profile, name, name+".yaml")
}

// fixturePods returns the Pods of every .kyverno-test fixture, renamed to <policy>-<name> so
// they don't collide.
func fixturePods(root string, local map[string]string) (string, error) {
	var names []string
	for n := range local {
		names = append(names, n)
	}
	sort.Strings(names)
	var docs []string
	for _, name := range names {
		dir := filepath.Join(root, "pod-security-vpol", local[name], name, ".kyverno-test")
		files, err := filepath.Glob(filepath.Join(dir, "*.y*ml"))
		if err != nil {
			return "", err
		}
		sort.Strings(files)
		for _, f := range files {
			if base := filepath.Base(f); base == "kyverno-test.yaml" || base == "kyverno-test.yml" {
				continue
			}
			data, err := os.ReadFile(f)
			if err != nil {
				return "", err
			}
			for _, raw := range docSeparator.Split(string(data), -1) {
				var doc map[string]any
				if err := yaml.Unmarshal([]byte(raw), &doc); err != nil {
					return "", fmt.Errorf("%s: %w", f, err)
				}
				if doc["kind"] != "Pod" {
					continue
				}
				meta, _ := doc["metadata"].(map[string]any)
				if meta == nil {
					continue
				}
				meta["name"] = name + "-" + fmt.Sprint(meta["name"])
				out, err := yaml.Marshal(doc)
				if err != nil {
					return "", err
				}
				docs = append(docs, string(out))
			}
		}
	}
	return strings.Join(docs, "---\n"), nil
}

// comparePolicySets lists policies that can't be synced automatically.
func comparePolicySets(cfg *Config, render map[string]Rendered, local map[string]string) []string {
	var problems []string
	for name, r := range render {
		switch p, ok := local[name]; {
		case !ok:
			problems = append(problems, fmt.Sprintf("`%s` (%s) is in the chart but not in pod-security-vpol.", name, r.Profile))
		case p != r.Profile:
			problems = append(problems, fmt.Sprintf("`%s` is %s in the chart but %s in pod-security-vpol.", name, r.Profile, p))
		}
		if _, ok := cfg.Checks[name]; !ok {
			problems = append(problems, fmt.Sprintf("`%s` has no PSA check in config.yaml.", name))
		}
	}
	for name, p := range local {
		if _, ok := render[name]; !ok {
			problems = append(problems, fmt.Sprintf("`%s` (%s) is in pod-security-vpol but not in the chart.", name, p))
		}
	}
	sort.Strings(problems)
	return problems
}
