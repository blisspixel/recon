# Security Threat Model

This is the engineering-level threat model. For **how to report a
vulnerability**, see [`SECURITY.md`](../SECURITY.md) in the repository root.

recon is a passive, read-only CLI tool plus local MCP server. Its threat
surface is small by design — no active scanning, no credential handling,
no inbound network listeners, no user-code execution.

---

## Trust boundaries

| What recon trusts | Rationale |
|---|---|
| The user's configured DNS resolver | recon inherits the OS resolver. A compromised resolver is a compromise of the whole machine. |
| Public OIDC / UserRealm / Google identity / CT endpoints | These are Microsoft, Google, and Sectigo-operated services. recon validates response shapes but cannot out-verify the underlying TLS-authenticated origin. |
| `recon_tool/data/*.yaml` (built-in fingerprints, signals, profiles) | Ships with the package, loaded via `yaml.safe_load`. Same trust level as Python source. |
| Python stdlib + pinned dependencies in `uv.lock` | Standard supply-chain trust. CI and release jobs audit locked runtime dependencies on every build. |

| What recon does NOT trust | Mitigation location |
|---|---|
| User-supplied domain strings | `recon_tool/validator.py` — regex + length cap + scheme stripping |
| Raw DNS responses (TXT values, MX hostnames, CNAME targets) | Length caps + structured parsing in `recon_tool/sources/dns.py` |
| Environment variables (`RECON_CONFIG_DIR`) | Treated as arbitrary user input — CT and result cache path helpers validate resolved paths stay inside their cache dirs |
| Custom YAML at `~/.recon/fingerprints.yaml` and friends | Validated by `_validate_fingerprint`, `_validate_signal`, `_validate_profile` — regex compilation + ReDoS heuristic + required-field checks. Additive-only (cannot override built-ins). |
| CT provider response bodies | Size-capped, filtered for wildcards and malformed entries in `sources/cert_providers.py` |
| Malicious HTTP redirect targets / private-IP redirects | `recon_tool/http.py` `_SSRFSafeTransport` validates every hop |

---

## Attack surface & mitigations

### Malicious domain input

**Surface:** A user (or an agent) passes an arbitrary string to `recon <domain>` or a MCP tool.

**Mitigation:** [`recon_tool/validator.py`](../recon_tool/validator.py) line 18–85:
- Domain regex: labels must be 1–63 chars, alphanumeric + hyphens, TLD ≥ 2 alpha chars
- Max input length: 500 chars
- Schemes (`http://`, `https://`, `ftp://`) stripped
- `www.` prefix stripped
- Normalized to lowercase
- Typed `ValueError` on invalid input → CLI exit code 2 (`EXIT_VALIDATION`)

### Malicious DNS responses

**Surface:** A compromised or adversarial DNS response could attempt to exfiltrate via crafted values or trigger injection in downstream formatting.

**Mitigation:**
- Length caps on all DNS string values (`sources/dns.py`)
- A-to-PTR hosting detection only reverse-resolves globally routable unicast
  A-record IPs; private, loopback, link-local, reserved, multicast,
  unspecified, and other non-global addresses are skipped before PTR lookup.
- Rich-text rendering uses `Text.append(value, style=...)` which escapes Rich markup in the user-controlled portion
- JSON output uses `json.dumps` (escapes)
- No DNS value is interpolated into shell, SQL, or exec contexts anywhere in the codebase

### Malicious YAML / user-supplied regex

**Surface:** Custom fingerprint/signal YAML files under `~/.recon/` can contain arbitrary regex patterns.

**Mitigation:** [`recon_tool/fingerprints.py`](../recon_tool/fingerprints.py):
- `yaml.safe_load` (not `yaml.load`) — no arbitrary constructor execution
- Pattern length capped at 500 chars (line 56)
- ReDoS heuristic (`_REDOS_RE` line 68–74) rejects nested quantifiers like
  `(a+)+`, `(a*)+`, and `(\w+)+`, plus polynomial-backtracking shapes such as
  repeated wildcard groups. This is a heuristic guardrail, not a formal regex
  verifier.
- All patterns compile-validated via `re.compile` before use
- Same checks run on `~/.recon/signals.yaml` via `_validate_signal` in `signals.py`
- Custom entries are **additive only** — cannot override built-ins (design invariant)

### SSRF via malicious HTTP redirects

**Surface:** An adversarial upstream (or a DNS-rebound attacker) could redirect an HTTP request to a private/internal IP, potentially exposing cloud-metadata services (169.254.169.254) or internal infrastructure.

**Mitigation:** [`recon_tool/http.py`](../recon_tool/http.py) `_SSRFSafeTransport`:
- Every hop — initial request AND every redirect — validated
- Blocked networks: `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16` (link-local/cloud metadata), IPv6 `fc00::/7`, `fe80::/10`
- Literal IP check on URL host
- Asynchronous DNS resolution check (IP from resolver vs allowlist)
- Used by default in all outbound HTTP (OIDC discovery, UserRealm, cert providers, Google identity)

**Known limitation:** DNS rebinding with sub-second TTLs is not fully defeated (`http.py:9–16`). The check happens before the request, and `httpx` resolves the hostname again for the actual connection. For typical attacker TTLs (minutes) this is safe; for millisecond-TTL rebinding it is not. An attacker who controls both a public hostname and can flip its DNS within the connection window could bypass the check. This is documented in-code as a known tradeoff.

### Path traversal in local caches

**Surface:** `recon cache show ../../etc/passwd`, `recon cache clear ../../settings`, or a crafted `RECON_CONFIG_DIR` could cause a cache layer to read, write, or delete outside its intended directory.

**Mitigation:** [`recon_tool/ct_cache.py`](../recon_tool/ct_cache.py) `_safe_path` and [`recon_tool/cache.py`](../recon_tool/cache.py) `_safe_cache_path`:
- Resolves the target path
- Asserts the resolved path starts with the resolved cache directory
- Rejects traversal separators and malformed domains before filesystem access
- Rejects or ignores invalid paths on violation (tests: `tests/test_ct_cache.py`, `tests/test_cache_roundtrip.py`, `tests/test_cache_cli.py`)

### Malicious CT provider responses

**Surface:** A compromised crt.sh / CertSpotter could return extremely large subdomain sets or adversarially crafted names attempting to amplify downstream work.

**Mitigation:** `recon_tool/sources/cert_providers.py`:
- Bounded crt.sh extraction before filtering/sorting: at most
  `MAX_SUBDOMAINS * 20` JSON entries inspected, `MAX_SUBDOMAINS * 10`
  raw names collected, and `MAX_SUBDOMAINS * 10` cert-summary entries retained
- CertSpotter pagination stops early after enough raw names are collected
- Filtering of wildcards, duplicates, and noise prefixes
- Final cap at `MAX_SUBDOMAINS = 100` after prioritization
- 8-second timeout per provider
- Pagination capped at 2 pages on CertSpotter

### MCP server exposure

**Surface:** The MCP server is a local subprocess communicating with the user's AI client over stdio. The client controls what tools are called.

**Mitigation:**
- The lookup and analysis tools are read-only; `reload_data` and the
  ephemeral fingerprint tools only modify in-memory or local process
  state (verified in `recon_tool/server.py` ToolAnnotations and Server
  Instructions)
- Tools accept domain strings that go through the same `validator.py` pipeline
- `inject_ephemeral_fingerprint` only persists in current process memory; it
  never writes to built-in files, custom config files, or the cache.
- Ephemeral fingerprint injection is quota-bounded in-process: 100 fingerprints,
  20 detections per injected fingerprint, and 500 total ephemeral detections.
  Rejected injections return JSON errors instead of growing memory or lookup
  work without bound.
- 120-second TTL cache and per-domain rate limiter prevent repeated-lookup abuse
- No HTTP / OAuth transport, no network listener

---

## Out of scope

recon does **not** defend against:

- **Active scanning attacks.** recon is passive. An attacker with a shell on your machine can do more than recon can see.
- **Credential theft.** recon handles zero credentials. There is nothing to steal.
- **DNS cache poisoning at the OS level.** If the user's resolver is compromised, the entire threat model is compromised regardless of what recon does.
- **Supply-chain compromise of transitive dependencies.** Detected by `pip-audit` in CI (advisory-only) but not in-process.
- **Side-channel timing attacks against the user's identity.** Every query recon makes is visible to the intermediary services (OIDC endpoints, CT providers, the user's DNS resolver). See [`legal.md`](legal.md#what-sees-your-queries) for the exposure inventory.
- **Logging / telemetry exfiltration.** recon emits no telemetry. All output goes to the user's terminal or files they own.
- **Malicious plugin systems.** recon has no plugin system and executes no user code.

---

## Reporting vulnerabilities

See [`SECURITY.md`](../SECURITY.md). TL;DR: email `nick@pueo.io`, do not open a public issue.
