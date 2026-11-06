# Pod Security Standards sync

The sync keeps the policies in `pod-security-vpol/` aligned with the Pod Security Standards (PSS) policies of
the `kyverno-policies` Helm chart in [kyverno/kyverno](https://github.com/kyverno/kyverno). `pod-security-vpol/`
holds one static policy set for the newest Pod Security Admission (PSA) version that the chart implements.

The [Sync PSS policies from the chart](../../.github/workflows/sync-pss-from-chart.yaml) workflow runs the sync.
When the chart changes an allow-list, the workflow opens or updates a pull request. When the chart changes anything
the sync can't translate safely, the workflow fails and reports it in a tracking issue.

## How a run works

1. `sync.sh` reads `psaMaxVersion` from the chart's `_helpers.tpl` and renders the chart once for each profile, with
   `podSecurityVersion=v<psaMaxVersion>` and `podSecurityUserNamespaces=true`.
2. It checks that the chart and `pod-security-vpol/` have the same policies, in the same profiles.
3. For each rule in the `lists` section of `config.yaml`, it compares the chart's list with the policy's variable.
   When they differ, it rewrites only that variable and the message that lists the values.
4. It builds a set of test Pods:
   - one Pod for each value of each list, plus one value outside the list;
   - the chart's PSA boundary Pods from `test/cli/test-validating-policy/pss-psa-version` in kyverno/kyverno;
   - the Pods from each policy's `.kyverno-test` fixtures, renamed `<policy>-<pod>`.
5. It computes the expected result for each policy and Pod with the upstream `k8s.io/pod-security-admission`
   library, then runs `kyverno test` with those results against the chart and against the updated policies. Both
   must agree with PSA.
6. It runs the existing `pod-security-vpol` tests on the updated policies.
7. With `--write`, it copies the updated policies into the checkout, refreshes their Artifact Hub digests with
   `.hack/update-artifacthub-pkg.sh`, and checks that only policy files and `artifacthub-pkg.yml` files changed.

Steps 2 to 6 work on a copy of `pod-security-vpol/`, so a failed run changes nothing.

## What the sync updates

| Chart change | Result |
|---|---|
| A value is added to or removed from a list in the `lists` section of `config.yaml` | Updated automatically |
| Any other behavior change, such as new logic or a new field check | The behavior check fails. Update the policy by hand. |
| A new, removed, renamed, or moved policy | The run fails. Add, remove, or move the policy by hand, with its tests and Artifact Hub files. |
| A new PSA version that the PSA library in `go.mod` doesn't know yet | The run fails. Update `k8s.io/pod-security-admission` in `go.mod`. Dependabot proposes this weekly. |

## Run the sync locally

Prerequisites:

- Go, Helm, and Bash.
- A kyverno/kyverno checkout of `main`.
- The Kyverno CLI, built from that checkout:

  ```bash
  go -C ../kyverno build -o "$PWD/kyverno" ./cmd/cli/kubectl-kyverno
  ```

To check whether `pod-security-vpol/` matches the chart, run this from the root of this repository:

```bash
KYVERNO=./kyverno .hack/pss-sync/sync.sh --kyverno-dir ../kyverno --report report.md
```

To also update the policies, commit or stash any changes in `pod-security-vpol/`, then add `--write`:

```bash
KYVERNO=./kyverno .hack/pss-sync/sync.sh --kyverno-dir ../kyverno --write --report report.md
```

`report.md` lists the allow-list changes, the known differences, and the behavior results.

| Exit code | Meaning |
|---|---|
| `0` | In sync. With `--write`, the policies were updated if they needed it. |
| `3` | The allow-lists differ from the chart, and the update passes every check. Check mode only. |
| `1` | An error, or a difference that needs a manual update. Nothing was written. |

Set `PSS_SYNC_KEEP_TMP=1` to keep the working files, including the generated `kyverno-test.yaml` files.

## Configuration

`config.yaml` has three sections.

`checks` maps each policy to the PSA check it implements. Every chart policy needs an entry.

`lists` defines the allow-lists that the sync updates:

| Field | Meaning |
|---|---|
| `policy` | The policy name. |
| `variable` | The `spec.variables` entry that holds the list. Its expression must be a list of quoted strings. |
| `anchor` | A value that identifies the list in the chart policy. |
| `ignore` | Chart values that the policy handles outside the list. Optional. |
| `order` | `sorted`, or `keep` to keep existing values in place and add new ones at the end. |
| `message.validation` | The index of the validation whose message lists the values. Optional. |
| `message.conjunction` | The word before the last value in the message, such as `and` or `or`. Empty means commas only. |
| `probe.field` | Where the test Pod sets a value: `sysctl`, `seLinuxType`, or `capability`. |
| `probe.outside` | A value outside the list, for a Pod that must fail. |

When the message doesn't list the current values exactly once, the sync fails instead of guessing.

`knownDifferences` lists policy and Pod pairs that the behavior check skips. Set `in` to `chart` or
`pod-security-vpol` to skip a pair for one side only. Each entry needs a `reason`, and the report lists every
entry.

## Workflow

| Trigger | Runs |
|---|---|
| Daily schedule | In kyverno/policies only |
| `repository_dispatch` with type `pss-chart-changed` | When kyverno/kyverno sends the event after a chart change |
| Manual run | In any repository. Set `publish` to open the pull request and update the tracking issue. |

A scheduled or dispatched run opens a pull request only when the repository variable `PSS_SYNC_PUBLISH` is
`true`. Otherwise, it reports available updates in the tracking issue.

The pull request comes from the `automation/sync-pss-from-chart` branch. The workflow updates that branch only
when every commit on it is from the bot. If someone else pushes a commit to the branch, the workflow leaves the
branch alone and reports it in the tracking issue until the pull request is merged or the branch is deleted.

The tracking issue is created by `github-actions[bot]` and stays open until a run finds the policies in sync, or
updates the sync pull request.

### Permissions

| Credential | Used for | Needs |
|---|---|---|
| `GITHUB_TOKEN` | Reading the repository and managing the tracking issue | `contents: read`, `issues: write` |
| `PR_UPDATE_TOKEN` secret | Pushing the bot branch and opening the pull request | Contents and pull requests write on kyverno/policies |

Pull requests opened with `GITHUB_TOKEN` don't start other workflows, so the required checks wouldn't run. That's
why the pull request uses `PR_UPDATE_TOKEN`.

## When a run fails

| Report shows | What to do |
|---|---|
| Policies that can't be synced automatically | Add, remove, or move the policy in `pod-security-vpol/` by hand, then add it to `checks`. |
| Allow-lists that can't be updated automatically | The chart list or the policy variable or message has an unexpected shape. Fix the policy by hand, or update the rule in `config.yaml`. |
| `kyverno-policies chart` fails the behavior check | The chart disagrees with PSA. Report it in kyverno/kyverno. If the difference doesn't affect `pod-security-vpol`, add a known difference with `in: chart`. |
| `pod-security-vpol` fails the behavior check | The chart changed behavior that the sync can't translate. Update the policy by hand. |
| `pod-security-vpol tests` fail | An allow-list change breaks an existing test. Update the tests and the policy by hand. |
| `update .hack/pss-sync/go.mod` | Update `k8s.io/pod-security-admission` and `k8s.io/api` to the PSA version in the report. |
