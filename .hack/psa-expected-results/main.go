// Prints the expected kyverno test results of the version-aware pod-security-vpol policies at
// one Pod Security Admission minor version, computed by upstream k8s.io/pod-security-admission.
// A policy whose PSA check does not exist yet at that version passes every Pod.
//
// .hack/update-psa-version-tests.sh runs it. Usage: go run . <resources.yaml> <minor> <policy file>...
package main

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/pod-security-admission/api"
	"k8s.io/pod-security-admission/policy"
	"sigs.k8s.io/yaml"
)

var checks = map[string]policy.CheckID{
	"restrict-sysctls":             "sysctls",
	"disallow-selinux":             "seLinuxOptions",
	"disallow-host-probes":         "hostProbesAndHostLifecycle",
	"disallow-proc-mount":          "procMount",
	"disallow-proc-mount-strict":   "procMount_restricted",
	"require-run-as-nonroot":       "runAsNonRoot",
	"require-run-as-non-root-user": "runAsUser",
}

func main() {
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	minor, err := strconv.Atoi(os.Args[2])
	if err != nil {
		panic(err)
	}
	var names []string
	pods := map[string]*corev1.Pod{}
	for _, doc := range regexp.MustCompile(`(?m)^---\s*$`).Split(strings.ReplaceAll(string(data), "\r", ""), -1) {
		if strings.TrimSpace(strings.Join(nonComment(doc), "")) == "" {
			continue
		}
		var pod corev1.Pod
		if err := yaml.UnmarshalStrict([]byte(doc), &pod); err != nil {
			panic(err)
		}
		if _, dup := pods[pod.Name]; dup {
			panic("duplicate Pod " + pod.Name)
		}
		pods[pod.Name] = &pod
		names = append(names, pod.Name)
	}
	sort.Strings(names)
	byID := map[policy.CheckID]policy.Check{}
	for _, c := range policy.DefaultChecks() {
		byID[c.ID] = c
	}
	want := api.MajorMinorVersion(1, minor)
	var b strings.Builder
	fmt.Fprintf(&b, "apiVersion: cli.kyverno.io/v1alpha1\nkind: Test\nmetadata:\n  name: psa-v1-%d\npolicies:\n", minor)
	for _, p := range os.Args[3:] {
		fmt.Fprintf(&b, "- %s\n", p)
	}
	b.WriteString("resources:\n- ../resources.yaml\nresults:\n")
	var policies []string
	for p := range checks {
		policies = append(policies, p)
	}
	sort.Strings(policies)
	for _, p := range policies {
		c, ok := byID[checks[p]]
		if !ok {
			panic("no PSA check " + checks[p])
		}
		var fn policy.CheckPodFn
		for _, v := range c.Versions {
			if !want.Older(v.MinimumVersion) {
				fn = v.CheckPod
			}
		}
		for _, result := range []string{"fail", "pass"} {
			var rs []string
			for _, n := range names {
				allowed := fn == nil || fn(&pods[n].ObjectMeta, &pods[n].Spec).Allowed
				if (result == "pass") == allowed {
					rs = append(rs, n)
				}
			}
			if len(rs) == 0 {
				continue
			}
			fmt.Fprintf(&b, "- isValidatingPolicy: true\n  kind: Pod\n  policy: %s\n  resources:\n", p)
			for _, n := range rs {
				fmt.Fprintf(&b, "  - %s\n", n)
			}
			fmt.Fprintf(&b, "  result: %s\n", result)
		}
	}
	fmt.Print(b.String())
}

func nonComment(doc string) []string {
	var out []string
	for _, l := range strings.Split(doc, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(l), "#") {
			out = append(out, l)
		}
	}
	return out
}
