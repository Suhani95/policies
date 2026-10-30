package main

import (
	"fmt"
	"os"

	"go.yaml.in/yaml/v3"
)

// Config is config.yaml: how the chart policies map to pod-security-vpol and to PSA.
type Config struct {
	// Checks maps each policy name to the PSA check it implements.
	Checks map[string]string `yaml:"checks"`
	// Lists are the allow-list variables the sync updates from the chart.
	Lists []ListRule `yaml:"lists"`
	// KnownDifferences are policy and Pod pairs the behavior check skips.
	KnownDifferences []KnownDifference `yaml:"knownDifferences"`
}

type ListRule struct {
	Policy   string `yaml:"policy"`
	Variable string `yaml:"variable"`
	// Anchor selects the chart list literal that contains this value.
	Anchor string `yaml:"anchor"`
	// Ignore lists chart values the standalone policy handles outside the list.
	Ignore []string `yaml:"ignore"`
	// Order is "sorted", or "keep" to keep existing values in place and append new ones.
	Order   string       `yaml:"order"`
	Message *MessageRule `yaml:"message"`
	Probe   Probe        `yaml:"probe"`
}

// MessageRule names the validation whose message lists the values.
type MessageRule struct {
	Validation int `yaml:"validation"`
	// Conjunction joins the last value, for example "and" or "or". Empty means commas only.
	Conjunction string `yaml:"conjunction"`
}

// Probe says how to build a boundary Pod for one value.
type Probe struct {
	Field   string `yaml:"field"`
	Outside string `yaml:"outside"`
}

type KnownDifference struct {
	Policy string `yaml:"policy"`
	Pod    string `yaml:"pod"`
	// In limits the entry to "chart" or "pod-security-vpol". Empty means both.
	In     string `yaml:"in"`
	Reason string `yaml:"reason"`
}

var probeFields = map[string]bool{"sysctl": true, "seLinuxType": true, "capability": true}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	dec := yaml.NewDecoder(bytesReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	for _, l := range c.Lists {
		if _, ok := c.Checks[l.Policy]; !ok {
			return nil, fmt.Errorf("%s: list rule for unknown policy %q", path, l.Policy)
		}
		if l.Variable == "" || l.Anchor == "" {
			return nil, fmt.Errorf("%s: list rule for %s needs variable and anchor", path, l.Policy)
		}
		if l.Order != "sorted" && l.Order != "keep" {
			return nil, fmt.Errorf("%s: list rule for %s: order must be sorted or keep", path, l.Policy)
		}
		if !probeFields[l.Probe.Field] || l.Probe.Outside == "" {
			return nil, fmt.Errorf("%s: list rule for %s: probe needs a known field and an outside value", path, l.Policy)
		}
	}
	for _, d := range c.KnownDifferences {
		if d.Policy == "" || d.Pod == "" || d.Reason == "" {
			return nil, fmt.Errorf("%s: each known difference needs policy, pod, and reason", path)
		}
		if d.In != "" && d.In != "chart" && d.In != "pod-security-vpol" {
			return nil, fmt.Errorf("%s: known difference in must be chart or pod-security-vpol", path)
		}
	}
	return &c, nil
}
