# Pod Security Standards ValidatingPolicies

These policies implement the Kubernetes [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
Baseline and Restricted profiles. By default, they match the newest Kubernetes Pod Security
Admission (PSA) version they support, v1.37.

## Pin a Pod Security Admission version

PSA changes some checks between Kubernetes versions, and you can pin a namespace to one version
with the `pod-security.kubernetes.io/enforce-version` label. To make these policies match an
earlier PSA version, set the `psaMinor` variable in each version-aware policy to the minor
version you want, for example `30` for v1.30:

```yaml
spec:
  variables:
    - name: psaMinor
      expression: "30"
```

The supported range is `25` to `37`. A value above `37` behaves like `37`, and a value below `25`
behaves like `25`.

Only these policies change between versions. The others behave the same at every supported
version.

| PSA version | Policy | Change |
|---|---|---|
| v1.27, v1.29, v1.32, v1.37 | `baseline/restrict-sysctls` | Allows the sysctls PSA added in that version. |
| v1.31 | `baseline/disallow-selinux` | Allows the `container_engine_t` SELinux type. |
| v1.34 | `baseline/disallow-host-probes` | Checks the `host` field of probes and lifecycle handlers. Below v1.34, every Pod passes. |
| v1.35 | `baseline/disallow-proc-mount`, `restricted/require-run-as-nonroot`, `restricted/require-run-as-non-root-user` | Exempts Pods that set `spec.hostUsers` to `false`. |
| v1.35 | `restricted/disallow-proc-mount-strict` | Checks `procMount` with no user namespace exemption. Below v1.35, every Pod passes. |

Below v1.34, you can leave out `disallow-host-probes`, and below v1.35, you can leave out
`disallow-proc-mount-strict`. Those PSA checks don't exist yet at those versions, so the
policies only add passing results to policy reports.

To pin a version with Kustomize, patch each version-aware policy. For example:

```yaml
resources:
  - https://github.com/kyverno/policies//pod-security-vpol/baseline?ref=main
patches:
  - target:
      kind: ValidatingPolicy
      name: restrict-sysctls|disallow-selinux|disallow-host-probes|disallow-proc-mount
    patch: |-
      - op: replace
        path: /spec/variables/0/expression
        value: "30"
```

`psaMinor` is the first variable in every version-aware policy, so the same patch applies to each
one.

## Change a version-aware policy

The tests in `.psa-version-tests` run each version-aware policy against the same Pods at every
PSA version where a policy changes. `kyverno test` can't override a variable, so each version
directory holds a generated copy of the policies with `psaMinor` set to that version. The
expected results come from upstream `k8s.io/pod-security-admission`, through the Go program
in `.hack/psa-expected-results`.

After you change a version-aware policy, the test Pods, or the PSA version in
`.hack/psa-expected-results/go.mod`, regenerate the tests. You need Go installed.

```shell
./.hack/update-psa-version-tests.sh
```

CI runs the same script and fails if the tests are out of date.
