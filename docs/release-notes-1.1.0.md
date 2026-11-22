## OneQueue Scan 1.1.0

Everything that changed since v1.0.1, in plain English.

**New**
- **The default address is now `https://api.onequeue.dev`.** You no longer need to set `api-url`; older workflows that set it keep working.
- **Daily scans.** The example workflow now also runs every day at 03:00 UTC. A vulnerability can be published against a package you already use without any change in your code; the daily run finds it. Scheduled runs are uploaded like pushes to your default branch.
- **The default branch is sent with every upload**, read from the GitHub event. OneQueue no longer has to guess which branch is your main one.
- **Coverage gaps.** Each upload now says what the run did not cover: a scanner that failed, a scanner you turned off, and the base images named in your Dockerfiles (`FROM node:24-slim`) that were not scanned. Only names and short reasons are sent, never file paths or code. The dashboard shows them under Coverage.
- **The image moved to Docker Hub as `onequeuedev/onequeue`**, built for both amd64 and arm64. Earlier releases keep working: they point at the old image by digest.

**Changed**
- **A paused plan is a warning, not a failure.** If OneQueue answers an upload with "payment required" (trial over, or uploads paused), the step warns, uploads nothing and passes.
- **Secrets are no longer waved through when there is no verdict.** With an API key but no answer from OneQueue (upload failed, plan paused, timeout), a secret on a line your pull request added now fails the check. Older secrets only produce a warning.
- **Security reports go to security@onequeue.dev** (GitHub private reporting still works).

**Privacy and fixes**
- Every string that is kept is now scrubbed, including rule ids (a result whose id would be altered by the scrubber is dropped), documentation links (query strings and fragments removed) and branch names. Semgrep's own message text is still never used, and Semgrep runs with `--metrics=off`.
- `.gitleaksignore` entries now match. Gitleaks builds its fingerprints from the path it scans; the action passed the runner's absolute path, so the repository-relative entries in your `.gitleaksignore` did not match. It now scans from the repository root.
- Since v1.0.1: in gate mode with an API key the OneQueue verdict decides about secrets (your baseline, triage and build rules apply), without a key only secrets on lines a pull request changed fail, and `.gitleaksignore` is honored.

**Already in place (unchanged)**: Trivy, Semgrep and Gitleaks binaries are pinned by checksum; the image is pinned by digest; every GitHub Action used here is pinned by commit SHA.
