# OneQueue Scan

**OneQueue by Keytrion Labs.** A GitHub Action that runs Trivy, Semgrep and
Gitleaks inside your own pipeline and uploads only **redacted findings** to
OneQueue.

**Your source code never leaves the runner.** Scanning happens in your job.
What is uploaded is a small, rebuilt SARIF document made of rule IDs, file
paths, line numbers and rule text. It never contains code snippets, secret
values or environment variables. Scoring, de-duplication and policy run on
the OneQueue servers; none of that logic is in this repository.

This action is public so you can review exactly what it sends. It is not open
source; see [LICENSE](LICENSE).

## Quick start

```yaml
# .github/workflows/onequeue.yml
name: OneQueue

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false

      - uses: onequeuedev/onequeue@<full-commit-sha> # v1.0.0
        with:
          api-key: ${{ secrets.ONEQUEUE_API_KEY }}
```

Replace `<full-commit-sha>` with the 40-character commit SHA of the release
tag you want (shown on the release page). Pinning by SHA means a moved tag
can't change the code that runs in your pipeline.

Do not use `pull_request_target` with this action. Plain `pull_request` is
safe: pull requests from forks get no secrets, so `api-key` is empty. The
action then prints a warning, uploads nothing, and exits successfully. It
still runs Gitleaks locally (see [Forked pull requests](#forked-pull-requests)).

### Gate mode

```yaml
      - uses: onequeuedev/onequeue@<full-commit-sha> # v1.0.0
        with:
          api-key: ${{ secrets.ONEQUEUE_API_KEY }}
          mode: gate
          fail-on: high        # critical (default), high or none
          gate-timeout: 60     # seconds to wait for the verdict
          on-timeout: pass     # pass (warn only, default) or fail
```

## Requirements

- Linux runners only (`ubuntu-*` or self-hosted Linux with Docker). This is a
  Docker container action, published for `linux/amd64` and `linux/arm64`.
- Outbound HTTPS to the OneQueue API. Scanners also need to download data:
  Trivy downloads its vulnerability database, and Semgrep downloads its
  rules from the Semgrep Registry. No code is sent to either.

## Inputs

| Input | Default | Description |
| --- | --- | --- |
| `api-key` | (required) | OneQueue API key. Use the secret `ONEQUEUE_API_KEY`. Masked with `::add-mask::` and never logged. |
| `api-url` | `https://api.keytrionlabs.com` | API base URL. Must be `https://`; `http://` is allowed only for `localhost`. |
| `scanners` | `trivy,semgrep,gitleaks` | Comma-separated list. Only these scanners run. |
| `mode` | `upload` | `upload` or `gate`. |
| `fail-on` | `critical` | Gate mode: `critical`, `high` or `none`. Sent to the server, which computes the verdict. |
| `gate-timeout` | `30` | Gate mode: seconds to wait for the verdict (1–3600). |
| `on-timeout` | `pass` | Gate mode: `pass` (warn) or `fail` when there is no verdict in time or the upload fails. |
| `semgrep-config` | `p/default` | Comma-separated Semgrep configs: registry rulesets or paths in your repo (for example `p/owasp-top-ten,.semgrep/`). |
| `gitleaks-history` | `false` | Scan git history instead of only current files. Needs `fetch-depth: 0` on checkout. |

## Outputs

| Output | Description |
| --- | --- |
| `upload-id` | OneQueue upload ID, empty if nothing was uploaded. |
| `findings` | Number of redacted findings. |
| `verdict` | `pass`, `fail`, `warn` or `n/a`. |

## Behaviour

1. Each enabled scanner runs against `$GITHUB_WORKSPACE` and writes SARIF to
   a private temp directory, which is deleted at the end of the step. If a
   scanner crashes, the action prints a warning and continues with the others.
2. Every SARIF file is redacted (see below).
3. The redacted findings are uploaded as gzip JSON to
   `POST {api-url}/v1/uploads`, with a `Bearer` token and an
   `Idempotency-Key`. Network errors, `408`, `429` and `5xx` are retried up
   to 3 times with exponential backoff (1 s, 2 s, 4 s). The same
   `Idempotency-Key` is used on every retry, so a retry can't create a
   duplicate upload. Redirects are never followed.
4. **Upload mode** finishes as soon as the upload is done and **never fails
   the build**, not even when the upload fails. Problems are printed as
   warnings.
5. **Gate mode** then polls `GET {api-url}/v1/uploads/{id}/verdict` every 2
   seconds, for up to `gate-timeout` seconds:
   - verdict `fail`: the step fails and prints the server's reason;
   - verdict `pass`: the step passes;
   - no verdict in time, upload failed, or verdict unavailable: `on-timeout`
     decides.

   **Local hard rule:** in gate mode, any Gitleaks finding fails the build.
   This does not depend on the server, `fail-on`, or `api-key`.
6. A short summary is written to the job summary: scanners run, findings
   uploaded, upload ID and gate result.

### Forked pull requests

Pull requests from forks cannot read repository secrets, so `api-key` is
empty. The action then:

- prints a warning and **uploads nothing**,
- still runs **Gitleaks locally** (the other scanners are skipped),
- in `upload` mode, warns about Gitleaks findings and exits 0,
- in `gate` mode, fails the build if Gitleaks finds a secret, and otherwise
  exits 0.

## What is sent, and what is removed

The redactor does **not** edit your SARIF files. It builds a new document
from scratch and copies across only the fields listed here. Any field not on
this list, including fields that future scanner versions add, is dropped.

### Sent

| Data | Source |
| --- | --- |
| Tool name and version | SARIF `tool.driver` and the image's pinned versions |
| Rule ID | `result.ruleId` |
| Rule name, short description | `rule.name`, `rule.shortDescription` (scrubbed, max 256/512 chars) |
| Rule help link | `rule.helpUri` (`https://` only) |
| Severity | `result.level`, `rule.properties["security-severity"]` (number) |
| File path | repository-relative path only |
| Line range | `startLine`, `endLine` |
| Message | rebuilt per scanner (see below), scrubbed, max 1000 chars |
| Fixed version | Trivy's `Fixed Version`, as `result.properties.fixedVersion` |
| Run metadata | repository, commit SHA, ref, event name, PR number (and head SHA and branch names), run ID, run attempt, run URL, action version, scanner versions, status and finding counts, `mode`, `fail-on` |

### Removed

- **Source code:** `region.snippet`, `contextRegion`, `artifactContent`,
  `run.artifacts` (contents and hashes), `fixes`, `codeFlows`,
  `relatedLocations`, `stacks`, `attachments`, `graphs`.
- **Secrets:** the Gitleaks `Secret` and `Match` values, snippets,
  `fingerprints` / `partialFingerprints` (including the Gitleaks fingerprint,
  which embeds the secret), and the matched code that Semgrep interpolates
  into its messages.
- **Commit author data:** commit SHA of the leak, author, email, date and
  commit message (Gitleaks history mode).
- **Environment:** `invocations` (command line, environment variables,
  working directory, machine, account), `originalUriBaseIds` (absolute runner
  paths), and every `properties` bag apart from the two keys listed above.
  Environment variables are never read into the payload.
- **Paths outside the workspace:** a finding whose path is absolute outside
  `$GITHUB_WORKSPACE`, contains `..`, or is a non-file URI keeps its rule and
  message but loses its location.

### Per-scanner rules

| Scanner | Command | Message sent |
| --- | --- | --- |
| Trivy | `trivy fs --scanners vuln,misconfig --disable-telemetry` | Rebuilt from the `Package`, `Installed Version`, `Vulnerability`, `Severity`, `Fixed Version`, `Artifact`, `Type`, `Message` and `Link` lines only. Trivy's secret scanner is off, and any Trivy result tagged `secret` is dropped. |
| Semgrep | `semgrep scan --metrics=off` | The rule's static description. The result message is never used, because Semgrep inserts matched code into it. |
| Gitleaks | `gitleaks dir` (or `gitleaks git` with `gitleaks-history: true`) | Generated by the action: `<rule-id>: secret detected`. |

### Extra safeguards

- **Scrubbing.** All text that is kept is scanned for secret patterns (cloud
  keys, tokens, JWTs, private keys, `password=...`, credentials in URLs, long
  random strings), which are replaced with `[REDACTED]`.
- **Tripwire.** Before uploading, the action checks the final payload for
  every secret value Gitleaks found on the runner, in raw, JSON-escaped,
  URL-encoded and base64 form. If one is found, the upload is aborted.
- **Logs.** Scanner stdout is discarded. On a crash, the tail of stderr is
  printed with workflow commands disabled, and the API key and Gitleaks
  secret values are replaced with `***`.

The unit tests plant fake secrets in every one of these fields, plus
randomly generated extra fields, and check that the secrets never appear in
the gzip payload ([test/redact.test.ts](test/redact.test.ts),
[test/run.test.ts](test/run.test.ts)).

### Sample payload

An example of the decompressed body of `POST /v1/uploads`, trimmed to one
finding per scanner. The scanned repository contained `lodash@4.17.20`, a SQL
query built with string formatting, and a hard-coded GitHub token. The
Semgrep and Gitleaks entries are copied from the smoke test's real output.
The metadata values are illustrative.

```json
{
  "schemaVersion": 1,
  "mode": "gate",
  "failOn": "critical",
  "metadata": {
    "repository": "acme/app",
    "sha": "9f2c1e0d4b7a8c6e5f3d2b1a0c9e8d7f6a5b4c3d",
    "ref": "refs/pull/42/merge",
    "eventName": "pull_request",
    "pullRequest": { "number": 42, "headSha": "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b", "headRef": "feature/login", "baseRef": "main" },
    "runId": "11873465",
    "runAttempt": "1",
    "runUrl": "https://github.com/acme/app/actions/runs/11873465",
    "actionVersion": "1.0.0",
    "scanners": {
      "trivy": { "status": "ok", "findings": 1, "version": "0.76.1" },
      "semgrep": { "status": "ok", "findings": 1, "version": "1.182.1" },
      "gitleaks": { "status": "ok", "findings": 1, "version": "8.30.1" }
    }
  },
  "sarif": {
    "version": "2.1.0",
    "runs": [
      {
        "tool": {
          "driver": {
            "name": "Trivy",
            "version": "0.76.1",
            "rules": [
              {
                "id": "CVE-2021-23337",
                "name": "LanguageSpecificPackageVulnerability",
                "shortDescription": { "text": "nodejs-lodash: command injection via template" },
                "helpUri": "https://avd.aquasec.com/nvd/cve-2021-23337",
                "properties": { "security-severity": "7.2" }
              }
            ]
          }
        },
        "results": [
          {
            "ruleId": "CVE-2021-23337",
            "level": "error",
            "message": {
              "text": "Package: lodash\nInstalled Version: 4.17.20\nVulnerability: CVE-2021-23337\nSeverity: HIGH\nFixed Version: 4.17.21\nLink: [CVE-2021-23337](https://avd.aquasec.com/nvd/cve-2021-23337)"
            },
            "locations": [
              { "physicalLocation": { "artifactLocation": { "uri": "package-lock.json" }, "region": { "startLine": 1, "endLine": 1 } } }
            ],
            "properties": { "fixedVersion": "4.17.21" }
          }
        ]
      },
      {
        "tool": {
          "driver": {
            "name": "Semgrep OSS",
            "version": "1.182.1",
            "rules": [
              {
                "id": "python.lang.security.audit.formatted-sql-query.formatted-sql-query",
                "name": "python.lang.security.audit.formatted-sql-query.formatted-sql-query",
                "shortDescription": { "text": "Semgrep Finding: python.lang.security.audit.formatted-sql-query.formatted-sql-query" },
                "helpUri": "https://semgrep.dev/r/python.lang.security.audit.formatted-sql-query.formatted-sql-query"
              }
            ]
          }
        },
        "results": [
          {
            "ruleId": "python.lang.security.audit.formatted-sql-query.formatted-sql-query",
            "level": "warning",
            "message": { "text": "Detected possible formatted SQL query. Use parameterized queries instead." },
            "locations": [
              { "physicalLocation": { "artifactLocation": { "uri": "app/db.py" }, "region": { "startLine": 6, "endLine": 6 } } }
            ]
          }
        ]
      },
      {
        "tool": { "driver": { "name": "gitleaks", "version": "8.30.1", "rules": [{ "id": "github-pat" }] } },
        "results": [
          {
            "ruleId": "github-pat",
            "level": "error",
            "message": { "text": "github-pat: secret detected" },
            "locations": [
              { "physicalLocation": { "artifactLocation": { "uri": "app/settings.py" }, "region": { "startLine": 1, "endLine": 1 } } }
            ]
          }
        ]
      }
    ]
  }
}
```

Request headers: `Authorization: Bearer <api-key>`, `Content-Type:
application/json`, `Content-Encoding: gzip`, `Idempotency-Key: <uuid>`,
`User-Agent: onequeue-action/<version>`.

The full API contract is in [docs/openapi.yaml](docs/openapi.yaml).

## Supply chain

- The image is pinned by digest in [action.yml](action.yml) and built by
  [.github/workflows/release.yml](.github/workflows/release.yml), with SBOM
  and build provenance attestations. You can verify it with
  `gh attestation verify oci://ghcr.io/onequeuedev/onequeue@<digest> --owner onequeuedev`.
- Base images are pinned by digest. Trivy and Gitleaks release tarballs are
  checked against pinned SHA256 values. Semgrep is installed from a
  hash-locked requirements file (`pip --require-hashes --only-binary=:all:`).
- Every action used in this repository's workflows is pinned by commit SHA.
  Dependabot keeps npm packages, actions, base images and Semgrep up to date.

## Development

Requires Node.js 24.

```sh
npm ci
npm run typecheck
npm test                 # unit and integration tests against the mock API
npm run build            # bundles to dist/main.js (inside the image only)
docker build -t onequeue-action:local .
test/smoke/smoke.sh      # real scanners + mock API (needs network, ~2 GB disk)
```

`src/lib/` holds the scanner runner, redactor, API client and gate logic,
with no GitHub Actions dependencies, so it can be reused by a CLI later.
`src/run.ts` is the Actions-specific glue.

## Security

To report a vulnerability, email security@keytrionlabs.com. See
[SECURITY.md](SECURITY.md).

## License

Proprietary. See [LICENSE](LICENSE) and
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for the third-party
scanners included in the image.
