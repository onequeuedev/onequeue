# syntax=docker/dockerfile:1.7
#
# OneQueue Scan.
# Every base image is pinned by digest, every downloaded binary is checksum-verified,
# and Semgrep is installed from a hash-locked requirements file.
# To update a scanner, change its version and the matching SHA256 values below.

# Base images are written out in each FROM line (not via ARG) so Dependabot can update them.

# ---------------------------------------------------------------------------
# 1. Build the TypeScript bundle (single file, no node_modules at runtime)
# ---------------------------------------------------------------------------
FROM node:24-bookworm-slim@sha256:01d566e8d94d8c619591d78652babfccd3c6992a3dffa9ed5ab39e11cf6c70e9 AS build
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY tsconfig.json ./
COPY src ./src
# Type checking and tests run in CI; the image build only bundles.
RUN npm run build

# ---------------------------------------------------------------------------
# 2. Download and verify scanner binaries
# ---------------------------------------------------------------------------
FROM python:3.12-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df AS scanners
ARG TARGETARCH
ARG TRIVY_VERSION=0.76.1
ARG TRIVY_SHA256_AMD64=c7cbe3137fb8a48a17574bede3dd6beb16742d1e9772929940fc90082c39d9c0
ARG TRIVY_SHA256_ARM64=e174dff2a6dba5e3ae41f8d0537a6324405bd08132497340304c6b20e0f16a1f
ARG GITLEAKS_VERSION=8.30.1
ARG GITLEAKS_SHA256_AMD64=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
ARG GITLEAKS_SHA256_ARM64=e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080
WORKDIR /dl
SHELL ["/bin/bash", "-euo", "pipefail", "-c"]
RUN case "${TARGETARCH:-amd64}" in \
      amd64) T_ARCH=64bit;  T_SHA="${TRIVY_SHA256_AMD64}"; G_ARCH=x64;   G_SHA="${GITLEAKS_SHA256_AMD64}" ;; \
      arm64) T_ARCH=ARM64;  T_SHA="${TRIVY_SHA256_ARM64}"; G_ARCH=arm64; G_SHA="${GITLEAKS_SHA256_ARM64}" ;; \
      *) echo "unsupported arch ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    fetch() { python3 -c 'import sys,urllib.request; urllib.request.urlretrieve(sys.argv[1], sys.argv[2])' "$1" "$2"; }; \
    fetch "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${T_ARCH}.tar.gz" trivy.tgz; \
    echo "${T_SHA}  trivy.tgz" | sha256sum -c -; \
    fetch "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${G_ARCH}.tar.gz" gitleaks.tgz; \
    echo "${G_SHA}  gitleaks.tgz" | sha256sum -c -; \
    mkdir -p /out/bin /out/licenses/trivy /out/licenses/gitleaks; \
    tar -xzf trivy.tgz -C /out/bin trivy; \
    tar -xzf trivy.tgz -C /out/licenses/trivy LICENSE; \
    tar -xzf gitleaks.tgz -C /out/bin gitleaks; \
    tar -xzf gitleaks.tgz -C /out/licenses/gitleaks LICENSE; \
    chmod 0755 /out/bin/*

# ---------------------------------------------------------------------------
# 3. Runtime image
# ---------------------------------------------------------------------------
FROM python:3.12-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df
ARG TRIVY_VERSION=0.76.1
ARG GITLEAKS_VERSION=8.30.1
ARG SEMGREP_VERSION=1.182.1
ARG ACTION_VERSION=dev

LABEL org.opencontainers.image.title="OneQueue Scan" \
      org.opencontainers.image.description="OneQueue: runs Trivy, Semgrep and Gitleaks in your pipeline and uploads only redacted findings." \
      org.opencontainers.image.vendor="OneQueue" \
      org.opencontainers.image.source="https://github.com/onequeuedev/onequeue" \
      org.opencontainers.image.licenses="LicenseRef-OneQueue-Proprietary"

# git is needed only for gitleaks-history mode.
RUN apt-get update \
 && apt-get install -y --no-install-recommends git \
 && rm -rf /var/lib/apt/lists/*

COPY docker/semgrep-requirements.txt /tmp/semgrep-requirements.txt
RUN pip install --no-cache-dir --no-compile --require-hashes --only-binary=:all: -r /tmp/semgrep-requirements.txt \
 && rm /tmp/semgrep-requirements.txt \
 && semgrep --version | grep -qx "${SEMGREP_VERSION}" \
 && pip uninstall -y pip

COPY --from=build /usr/local/bin/node /usr/local/bin/node
COPY --from=scanners /out/bin/ /usr/local/bin/
COPY --from=scanners /out/licenses/ /usr/share/doc/onequeue/third-party/
COPY --from=build /src/dist/main.js /opt/onequeue/main.js
COPY LICENSE THIRD_PARTY_NOTICES.md /usr/share/doc/onequeue/

RUN node --version && trivy --version | grep -q "${TRIVY_VERSION}" && gitleaks version | grep -q "${GITLEAKS_VERSION}"

ENV ONEQUEUE_ACTION_VERSION=${ACTION_VERSION} \
    ONEQUEUE_TRIVY_VERSION=${TRIVY_VERSION} \
    ONEQUEUE_SEMGREP_VERSION=${SEMGREP_VERSION} \
    ONEQUEUE_GITLEAKS_VERSION=${GITLEAKS_VERSION} \
    SEMGREP_SEND_METRICS=off \
    SEMGREP_ENABLE_VERSION_CHECK=0 \
    TRIVY_CACHE_DIR=/tmp/trivy-cache \
    TRIVY_NO_PROGRESS=true \
    TRIVY_DISABLE_TELEMETRY=true \
    PYTHONDONTWRITEBYTECODE=1

# GitHub runs container actions as root so they can read the mounted workspace.
ENTRYPOINT ["node", "/opt/onequeue/main.js"]
