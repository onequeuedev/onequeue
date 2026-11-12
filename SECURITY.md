# Security policy

OneQueue Scan is the GitHub Action for OneQueue.

## Reporting a vulnerability

Email **security@onequeue.dev**. Please do not open a public GitHub issue
for security problems.

Include, where you can:

- a description of the issue and its impact,
- steps to reproduce or a proof of concept,
- the action version or image digest you used.

We aim to acknowledge reports within 2 business days and to keep you updated
until the issue is resolved. We ask that you give us reasonable time to fix
the issue before disclosing it publicly.

## In scope

- Data leaving the runner that the README says is removed (source code,
  snippets, secret values, environment variables, commit author data).
- Leaks of the OneQueue API key (logs, redirects, outputs).
- Supply-chain issues in this repository, its workflows or the published
  image `ghcr.io/onequeuedev/onequeue`.

Vulnerabilities in Trivy, Semgrep or Gitleaks themselves should be reported
to those projects. If one affects this action, please tell us as well.

## Supported versions

Only the latest release of the action receives security fixes.
