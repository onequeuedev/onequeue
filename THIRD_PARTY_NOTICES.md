# Third-party notices

> TODO(legal review): confirm the obligations below before the first release.

The OneQueue Scan container image (`ghcr.io/onequeuedev/onequeue`)
redistributes the following third-party software. Each component is licensed
under its own terms, which are not changed by the OneQueue license in
[LICENSE](LICENSE). License texts are included in the image under
`/usr/share/doc/onequeue/third-party/`, and for Python packages in each
package's `*.dist-info` directory under `/usr/local/lib/python3.12/site-packages/`.

## Security scanners

| Component | Version | License | Source |
| --- | --- | --- | --- |
| Trivy | 0.76.1 | Apache License 2.0 | https://github.com/aquasecurity/trivy |
| Gitleaks | 8.30.1 | MIT License | https://github.com/gitleaks/gitleaks |
| Semgrep (Community Edition CLI and engine) | 1.182.1 | GNU Lesser General Public License v2.1 | https://github.com/semgrep/semgrep |

Notes:

- **Trivy** is redistributed unmodified as the official release binary.
  Its Apache-2.0 license text is in the image. Trivy downloads its
  vulnerability database at runtime; that database is not part of the image.
- **Gitleaks** is redistributed unmodified as the official release binary,
  with its MIT license text.
- **Semgrep** is installed unmodified from PyPI (`semgrep==1.182.1`). Under
  LGPL-2.1 you may replace it in a derived image with another version
  (`pip install semgrep==<version>`). The complete corresponding source code
  for the version shipped is available at
  https://github.com/semgrep/semgrep/tree/v1.182.1.
- **Semgrep rules** (for example `p/default`) are **not** redistributed. They
  are downloaded by Semgrep at runtime from the Semgrep Registry and are
  subject to the Semgrep Rules License.

## Runtime

| Component | License | Source |
| --- | --- | --- |
| Node.js 24 (binary only) | MIT License (with bundled third-party notices) | https://github.com/nodejs/node |
| Python 3.12 (official `python:3.12-slim-bookworm` image) | PSF License | https://www.python.org |
| Debian 12 base packages, including git | Various (see `/usr/share/doc/*/copyright`) | https://sources.debian.org |
| Semgrep's Python dependencies (pinned in `docker/semgrep-requirements.txt`) | Various permissive licenses (MIT, BSD, Apache-2.0, PSF, MPL-2.0) | PyPI |

Debian packages are redistributed unmodified; source is available from the
Debian archive for the package versions in the pinned base image.
