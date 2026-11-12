# Releasing

`action.yml` references the image by digest, so a release has two steps.

1. **Build and push the image.** Run the *Release image* workflow
   (`.github/workflows/release.yml`) from `main` with the version, for example
   `1.2.0`. It runs the tests, builds `linux/amd64` and `linux/arm64`, pushes
   `ghcr.io/keytrionlabs/onequeue-action:1.2.0` with SBOM and provenance
   attestations, and prints the digest in the job summary.
2. **Pin the digest and tag.** Open a PR that sets
   `runs.image` in `action.yml` to
   `docker://ghcr.io/keytrionlabs/onequeue-action@sha256:<digest>`.
   After it merges, tag that commit `v1.2.0` and create a GitHub release.
   Customers pin the commit SHA of that tag.

The ghcr.io package must be public so that customer runners can pull it
without credentials.

## Updating scanners

- **Semgrep**: Dependabot updates `docker/semgrep-requirements.txt`. To do it
  by hand, edit `docker/semgrep-requirements.in`, then run
  `pip-compile --generate-hashes --allow-unsafe --strip-extras -o docker/semgrep-requirements.txt docker/semgrep-requirements.in`
  and update `SEMGREP_VERSION` in the Dockerfile and
  `THIRD_PARTY_NOTICES.md`.
- **Trivy and Gitleaks** are not tracked by Dependabot. Update
  `TRIVY_VERSION` / `GITLEAKS_VERSION` and the per-architecture `*_SHA256`
  build args in the Dockerfile from the project's published
  `*_checksums.txt` for that release, and update `THIRD_PARTY_NOTICES.md`.
  Prefer releases that are at least two weeks old.
