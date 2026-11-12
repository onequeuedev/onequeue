# Releasing

`action.yml` references the image by digest, so a release has two steps.

## One-time setup (Docker Hub)

1. In the Docker Hub account `rhysha`, create the **public** repository
   `onequeuedev`, so customer runners can pull without credentials.
2. Create a Docker Hub access token with *Read & Write* scope for `rhysha`.
3. In this GitHub repository, go to Settings -> Secrets and variables -> Actions
   -> Secrets -> New repository secret, and add `DOCKERHUB_TOKEN` (the access
   token). The Docker Hub user name `rhysha` is set in the workflow itself.

## Each release

1. **Build and push the image.** Run the *Release image* workflow
   (`.github/workflows/release.yml`) from `main` with the version, for example
   `1.2.0`. It runs the tests, builds `linux/amd64` and `linux/arm64`, pushes
   `docker.io/rhysha/onequeuedev:1.2.0` (also tagged `v1.2.0`) with SBOM and provenance, records a
   GitHub build attestation, and prints the digest in the job summary.
2. **Pin the digest and tag.** Set `runs.image` in `action.yml` to
   `docker://docker.io/rhysha/onequeuedev@sha256:<digest>`.
   After it is on `main`, tag that commit `v1.2.0` and create a GitHub release.
   Customers pin the commit SHA of that tag.

Note: Docker Hub rate-limits anonymous pulls per IP address. Customers on
self-hosted runners that pull often may need to log in to Docker Hub on the
runner, or use a pull-through cache.

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
