# Third-party notices

recon (`recon-tool`) is licensed under the MIT License (see [LICENSE](LICENSE)).
It depends on third-party open-source packages, each under its own license.

The **authoritative, complete, machine-readable inventory** of every runtime
dependency (direct and transitive) and its license is the CycloneDX SBOM
(`recon-tool-<version>.cdx.json`) attached to each
[GitHub Release](https://github.com/blisspixel/recon/releases), generated from
the hash-pinned `uv.lock`. See [docs/supply-chain.md](docs/supply-chain.md).

This file records the license obligations that warrant a human-readable notice.

## Mozilla Public License 2.0 (MPL-2.0)

The following runtime dependency is licensed under the MPL-2.0:

- **publicsuffixlist** — Public Suffix List lookup, used to reduce a lookup
  target to its registrable apex (eTLD+1).
  - Author: ko-zu (`causeless@gmail.com`)
  - Source: https://github.com/ko-zu/psl
  - License: MPL-2.0 (https://www.mozilla.org/en-US/MPL/2.0/)

MPL-2.0 is a file-level (weak) copyleft license. recon consumes this package
**unmodified** as an installed dependency and includes none of its source in
recon's own files, so the MPL-2.0 terms do not extend to recon's MIT-licensed
code. If you redistribute recon together with this dependency, the MPL-2.0
source-availability obligation is satisfied by the upstream source link above
(and by the package's own sdist on PyPI). Should recon ever modify and
redistribute MPL-2.0-covered files directly, those modified files would need to
remain under MPL-2.0 — recon does not currently do this.

## Other dependencies

All other declared runtime dependencies are under permissive licenses
(MIT / BSD / Apache-2.0 / PSF). The bundled PSL data inside `publicsuffixlist`
originates from the Public Suffix List (https://publicsuffix.org/), which is
distributed under the MPL-2.0. Per-package details for a given release are in
that release's SBOM.
