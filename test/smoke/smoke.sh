#!/usr/bin/env bash
# End-to-end smoke test of the built image with the REAL scanners against the
# mock OneQueue API. Needs network access (Trivy DB, Semgrep rules).
#
#   IMAGE=onequeue-action:local test/smoke/smoke.sh
#   SCANNERS=semgrep,gitleaks test/smoke/smoke.sh   # skip Trivy (its DB needs ~1 GB of disk)
#
# Checks:
#   1. upload mode: exit 0, findings from all three scanners are uploaded, and
#      neither the planted secret nor any source line appears in the payload.
#   2. gate mode with a verdict of pass: exit 1 because of the local Gitleaks rule.
#   3. gate mode with an empty api-key: no request is made, exit 1 (Gitleaks rule).
set -euo pipefail

IMAGE="${IMAGE:-onequeue-action:local}"
NODE_IMAGE="${NODE_IMAGE:-node:24-bookworm-slim}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="$(mktemp -d)"
PORT="${PORT:-18787}"
SCANNERS="${SCANNERS:-trivy,semgrep,gitleaks}"
MOCK_NAME="oq-mock-$$"
trap 'docker rm -f "$MOCK_NAME" >/dev/null 2>&1 || true; rm -rf "$WORK"' EXIT

cp -r "$ROOT/test/smoke/repo" "$WORK/ws"
# Random fake GitHub token, generated now so nothing secret-shaped is committed.
SECRET="ghp_$(head -c 200 /dev/urandom | LC_ALL=C tr -dc 'A-Za-z0-9' | head -c 36)"
printf 'GITHUB_TOKEN = "%s"\n' "$SECRET" > "$WORK/ws/app/settings.py"

start_mock() {
  docker rm -f "$MOCK_NAME" >/dev/null 2>&1 || true
  : > "$WORK/requests.jsonl"
  docker run -d --name "$MOCK_NAME" --network host -u "$(id -u):$(id -g)" \
    -v "$ROOT/test:/test:ro" -v "$WORK:/work" "$NODE_IMAGE" \
    node /test/mock-server.ts --scenario "$1" --port "$PORT" --record /work/requests.jsonl >/dev/null
  for _ in $(seq 1 50); do
    if docker logs "$MOCK_NAME" 2>&1 | grep -q listening; then return 0; fi
    sleep 0.2
  done
  docker logs "$MOCK_NAME"; echo "mock server did not start" >&2; exit 1
}

run_action() { # mode api-key
  : > "$WORK/summary.md"; : > "$WORK/output.txt"
  set +e
  docker run --rm --network host \
    -v "$WORK/ws:/github/workspace" -v "$WORK:/github/file_commands" \
    -e GITHUB_WORKSPACE=/github/workspace \
    -e GITHUB_REPOSITORY=acme/smoke -e GITHUB_SHA="$(printf 'a%.0s' {1..40})" \
    -e GITHUB_REF=refs/heads/main -e GITHUB_EVENT_NAME=push \
    -e GITHUB_RUN_ID=1 -e GITHUB_RUN_ATTEMPT=1 -e GITHUB_SERVER_URL=https://github.com \
    -e GITHUB_STEP_SUMMARY=/github/file_commands/summary.md \
    -e GITHUB_OUTPUT=/github/file_commands/output.txt \
    -e "INPUT_API-KEY=$2" -e "INPUT_API-URL=http://127.0.0.1:$PORT" \
    -e "INPUT_MODE=$1" -e "INPUT_GATE-TIMEOUT=10" -e "INPUT_SCANNERS=$SCANNERS" \
    -e "SMOKE_ENV_SECRET=$SECRET" \
    "$IMAGE" > "$WORK/log.txt" 2>&1
  CODE=$?
  set -e
}

fail() {
  echo "SMOKE FAIL: $*" >&2
  echo "--- action log"; cat "$WORK/log.txt"
  echo "--- mock server"; docker ps -a --filter "name=$MOCK_NAME" --format "{{.Status}}"; docker logs "$MOCK_NAME" 2>&1 | tail -20
  exit 1
}

check_no_leak() {
  grep -qF "$SECRET" "$WORK/requests.jsonl" && fail "planted secret found in upload payload"
  grep -qF "$SECRET" "$WORK/log.txt" && fail "planted secret printed in log"
  grep -qF "SELECT * FROM users" "$WORK/requests.jsonl" && fail "source code found in upload payload"
  # The ::add-mask:: line must contain the key; GitHub hides it. Nothing else may.
  grep -v "^::add-mask::" "$WORK/log.txt" | grep -qF "smoke-api-key-0123456789" && fail "api key printed in log"
  return 0
}

echo "== 1. upload mode"
start_mock accepted
run_action upload smoke-api-key-0123456789
[ "$CODE" = 0 ] || fail "upload mode exited $CODE"
grep -q '"POST"' "$WORK/requests.jsonl" || fail "no upload received"
check_no_leak
for tool in ${SCANNERS//,/ }; do
  grep -q "\\\\\"$tool\\\\\":{\\\\\"status\\\\\":\\\\\"ok\\\\\"" "$WORK/requests.jsonl" || fail "$tool did not run ok"
done
if [[ "$SCANNERS" == *trivy* ]]; then
  grep -q 'CVE-2021-23337' "$WORK/requests.jsonl" || fail "expected Trivy lodash finding"
fi
grep -qi 'sql' "$WORK/requests.jsonl" || fail "expected a Semgrep SQL finding"
grep -q 'github-pat' "$WORK/requests.jsonl" || fail "expected a Gitleaks finding"
cp "$WORK/requests.jsonl" "$WORK/upload-payload.jsonl"
cat "$WORK/summary.md"

echo "== 2. gate mode, server verdict pass, local Gitleaks rule must fail"
start_mock pass
run_action gate smoke-api-key-0123456789
[ "$CODE" = 1 ] || fail "gate mode exited $CODE, expected 1"
grep -q 'Gitleaks found' "$WORK/log.txt" || fail "missing Gitleaks gate message"
check_no_leak

echo "== 3. gate mode, empty api-key (fork PR)"
start_mock accepted
run_action gate ""
[ "$CODE" = 1 ] || fail "empty-key gate exited $CODE, expected 1"
[ -s "$WORK/requests.jsonl" ] && fail "requests were made without an api key"
grep -q 'api-key is empty' "$WORK/log.txt" || fail "missing empty-key warning"
check_no_leak

echo "SMOKE OK"
if [ -n "${SMOKE_PAYLOAD_OUT:-}" ]; then cp "$WORK/upload-payload.jsonl" "$SMOKE_PAYLOAD_OUT"; fi
