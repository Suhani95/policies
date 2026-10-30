#!/usr/bin/env bash
# Compares pod-security-vpol with the Pod Security Standards policies of the kyverno-policies
# chart at the newest PSA version the chart implements. With --write, it updates the allow-lists
# the chart changed and refreshes their Artifact Hub digests. See README.md.
#
# Usage: .hack/pss-sync/sync.sh --kyverno-dir DIR [--write] [--report FILE]
#
# Environment: HELM (default helm), KYVERNO (default kyverno, the Kyverno CLI), and
# PSS_SYNC_KEEP_TMP=1 to keep the working files.
# Exit codes: 0 in sync, or updated with --write; 3 allow-lists differ (check mode); 1 error.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HACK="${ROOT}/.hack/pss-sync"
HELM="${HELM:-helm}"
KYVERNO="${KYVERNO:-kyverno}"
KYVERNO_DIR=""
WRITE=false
REPORT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --kyverno-dir) KYVERNO_DIR="$2"; shift 2 ;;
    --write) WRITE=true; shift ;;
    --report) REPORT="$2"; shift 2 ;;
    -h | --help) sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument $1" >&2; exit 1 ;;
  esac
done
[[ -n "${KYVERNO_DIR}" ]] || { echo "--kyverno-dir is required" >&2; exit 1; }
KYVERNO_DIR="$(cd "${KYVERNO_DIR}" && pwd)"

TMP="$(mktemp -d)"
# Set PSS_SYNC_KEEP_TMP=1 to keep the working files for debugging.
if [[ "${PSS_SYNC_KEEP_TMP:-}" == 1 ]]; then echo "[pss-sync] working files: ${TMP}" >&2; else trap 'rm -rf "${TMP}"' EXIT; fi
REPORT="${REPORT:-${TMP}/report.md}"
CHART="${KYVERNO_DIR}/charts/kyverno-policies"
# Boundary Pods that kyverno/kyverno keeps for the chart's PSA version tests.
CHART_PODS="${KYVERNO_DIR}/test/cli/test-validating-policy/pss-psa-version/resources.yaml"

log() { echo "[pss-sync] $*" >&2; }
fail() {
  log "ERROR: $*"
  printf '\n**Error:** %s\n' "$*" >> "${REPORT}"
  exit 1
}
# allowed succeeds for the only files the sync may change: a policy file and its Artifact Hub package.
allowed() {
  [[ "$1" =~ ^pod-security-vpol/(baseline|restricted)/([a-z0-9-]+)/([^/]+)$ ]] || return 1
  [[ "${BASH_REMATCH[3]}" == "${BASH_REMATCH[2]}.yaml" || "${BASH_REMATCH[3]}" == artifacthub-pkg.yml ]]
}
# native converts a path for native Windows tools under Git Bash. It's a no-op elsewhere.
native() { if command -v cygpath > /dev/null; then cygpath -m "$1"; else echo "$1"; fi; }

# tool runs the sync tool and keeps its error output for the report.
tool() {
  local rc=0
  "${TOOL}" "$@" 2> "${TMP}/tool.err" || rc=$?
  cat "${TMP}/tool.err" >&2
  return "${rc}"
}
last_error() { sed 's/^pss-sync: //' "$1" | tail -n 1; }

# Append the log of a failed kyverno test to the report.
append_log() {
  { echo; echo "<details><summary>$1</summary>"; echo; echo '```text'; tail -n 200 "$2"; echo '```'; echo; echo "</details>"; } >> "${REPORT}"
}

PSA="$(sed -n 's/.*define "kyverno-policies.psaMaxVersion" -}}\([0-9.]*\){{-.*/\1/p' "${CHART}/templates/_helpers.tpl")"
[[ "${PSA}" =~ ^1\.[0-9]+$ ]] || { echo "can't read psaMaxVersion from ${CHART}/templates/_helpers.tpl" >&2; exit 1; }
SOURCE="$(git -C "${KYVERNO_DIR}" rev-parse HEAD 2> /dev/null || echo unknown)"

cat > "${REPORT}" << EOF
## Pod Security Standards sync report

- Source: kyverno/kyverno \`${SOURCE}\`
- PSA version: v${PSA}
- Chart render: \`podSecurityVersion=v${PSA}\`, \`podSecurityUserNamespaces=true\`, \`--kube-version ${PSA}.0\`
- Helm: \`$("${HELM}" version --short 2> /dev/null || echo unknown)\`

EOF

if [[ "${WRITE}" == true && -n "$(git -C "${ROOT}" status --porcelain -- pod-security-vpol)" ]]; then
  fail "pod-security-vpol has uncommitted changes. Commit or stash them before --write."
fi

log "building the sync tool"
TOOL="${TMP}/pss-sync$(go env GOEXE)"
go -C "${HACK}" build -o "$(native "${TOOL}")" . || fail "can't build .hack/pss-sync"

log "rendering the chart at PSA v${PSA}"
mkdir -p "${TMP}/render"
for profile in baseline restricted; do
  "${HELM}" template kyverno-policies "$(native "${CHART}")" \
    --kube-version "${PSA}.0" \
    --set podSecurityStandard="${profile}" \
    --set podSecurityVersion="v${PSA}" \
    --set podSecurityUserNamespaces=true > "${TMP}/render/${profile}.yaml" 2> "${TMP}/helm.err" ||
    fail "helm template failed for ${profile}: $(last_error "${TMP}/helm.err")"
done

# Work on a copy, so nothing in the checkout changes unless every check passes.
mkdir -p "${TMP}/stage" "${TMP}/chart-test" "${TMP}/vpol-test/policies"
cp -R "${ROOT}/pod-security-vpol" "${TMP}/stage/"

log "comparing the allow-lists"
rc=0
tool compare \
  --config "$(native "${HACK}/config.yaml")" \
  --render "$(native "${TMP}/render")" \
  --policies "$(native "${TMP}/stage")" \
  --write \
  --report "$(native "${TMP}/compare.md")" \
  --chart-out "$(native "${TMP}/chart-test/policies.yaml")" \
  --pods-out "$(native "${TMP}/pods.yaml")" || rc=$?
cat "${TMP}/compare.md" >> "${REPORT}" 2> /dev/null || true
case "${rc}" in
  0 | 3) ;;
  *) fail "the allow-list comparison failed: $(last_error "${TMP}/tool.err")" ;;
esac
LISTS_RC="${rc}"

log "checking behavior against upstream PSA v${PSA}"
[[ -f "${CHART_PODS}" ]] || fail "missing ${CHART_PODS}"
{ cat "${TMP}/pods.yaml"; echo "---"; cat "${CHART_PODS}"; } > "${TMP}/chart-test/resources.yaml"
cp "${TMP}/chart-test/resources.yaml" "${TMP}/vpol-test/resources.yaml"
vpol_policies=()
for file in "${TMP}"/stage/pod-security-vpol/*/*/; do
  name="$(basename "${file}")"
  cp "${file}${name}.yaml" "${TMP}/vpol-test/policies/"
  vpol_policies+=(--policy "policies/${name}.yaml")
done
tool expected --config "$(native "${HACK}/config.yaml")" --set chart --version "${PSA}" \
  --resources "$(native "${TMP}/chart-test/resources.yaml")" --policy policies.yaml > "${TMP}/chart-test/kyverno-test.yaml" ||
  fail "can't compute the expected PSA results: $(last_error "${TMP}/tool.err")"
tool expected --config "$(native "${HACK}/config.yaml")" --set pod-security-vpol --version "${PSA}" \
  --resources "$(native "${TMP}/vpol-test/resources.yaml")" "${vpol_policies[@]}" > "${TMP}/vpol-test/kyverno-test.yaml" ||
  fail "can't compute the expected PSA results: $(last_error "${TMP}/tool.err")"

behavior_ok=true
printf '\n### Behavior\n\n| Policies | Result against PSA v%s |\n|---|---|\n' "${PSA}" >> "${REPORT}"
for set in chart vpol; do
  label="kyverno-policies chart"
  [[ "${set}" == vpol ]] && label="pod-security-vpol, after the update"
  if "${KYVERNO}" test "$(native "${TMP}/${set}-test")" --fail-only --remove-color > "${TMP}/${set}.log" 2>&1; then
    echo "| ${label} | Pass |" >> "${REPORT}"
  else
    echo "| ${label} | **Fail** |" >> "${REPORT}"
    behavior_ok=false
  fi
done
[[ "${behavior_ok}" == true ]] || {
  for set in chart vpol; do append_log "kyverno test output: ${set}" "${TMP}/${set}.log"; done
  fail "the policies don't match upstream PSA v${PSA}. This change needs a manual update."
}

log "running the pod-security-vpol tests"
if ! "${KYVERNO}" test "$(native "${TMP}/stage/pod-security-vpol")" --fail-only --remove-color > "${TMP}/tests.log" 2>&1; then
  append_log "kyverno test output: pod-security-vpol" "${TMP}/tests.log"
  fail "the pod-security-vpol tests fail after the update"
fi
echo "| pod-security-vpol tests | Pass |" >> "${REPORT}"

if [[ "${WRITE}" != true ]]; then
  log "done (check mode)"
  [[ "${LISTS_RC}" == 3 ]] && exit 3
  exit 0
fi
[[ "${LISTS_RC}" == 3 ]] || { log "done, nothing to update"; exit 0; }

log "writing the updated policies"
while IFS= read -r file; do
  rel="${file#"${TMP}/stage/"}"
  allowed "${rel}" || fail "unexpected change to ${rel}"
  cp "${file}" "${ROOT}/${rel}"
done < <(cd "${TMP}/stage" && find pod-security-vpol -type f -name '*.yaml' | while read -r f; do
  cmp -s "${f}" "${ROOT}/${f}" || echo "${TMP}/stage/${f}"
done)
(cd "${ROOT}" && ./.hack/update-artifacthub-pkg.sh > /dev/null)

while IFS= read -r path; do
  allowed "${path}" || fail "unexpected change to ${path}"
done < <(git -C "${ROOT}" status --porcelain | cut -c4-)

rc=0
"${TOOL}" compare --config "$(native "${HACK}/config.yaml")" --render "$(native "${TMP}/render")" \
  --policies "$(native "${ROOT}")" || rc=$?
[[ "${rc}" == 0 ]] || fail "a second comparison still finds differences"
log "done, pod-security-vpol updated"
