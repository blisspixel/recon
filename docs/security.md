# Security Threat Model

This is the engineering-level threat model. For **how to report a
vulnerability**, see [`SECURITY.md`](../SECURITY.md) in the repository root.

recon is a passive, read-only CLI tool plus local MCP server. Its threat
surface is small by design - no active scanning, no credential handling,
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
| User-supplied domain strings | `recon_tool/validator.py` - regex + length cap + scheme stripping |
| Raw DNS responses (TXT values, MX hostnames, CNAME targets) | Length caps + structured parsing in `recon_tool/sources/dns.py` |
| Environment variables (`RECON_CONFIG_DIR`) | Treated as arbitrary user input - CT and result cache path helpers validate resolved paths stay inside their cache dirs |
| Custom YAML at `~/.recon/fingerprints.yaml` and friends | Validated by `_validate_fingerprint`, `_validate_signal`, `_validate_profile` - regex compilation + ReDoS heuristic + required-field checks. Additive-only (cannot override built-ins). |
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

### Malicious CNAME chains (surface-attribution walker)

**Surface:** The surface-attribution pipeline (`_classify_related_surface` in `sources/dns.py`) walks the CNAME chain for every related subdomain it discovers, up to five hops per chain and one hundred chains per lookup. Each hop is a separate CNAME query through the operator's resolver, and successful chains are emitted in `EvidenceRecord.raw_value` for `--explain` consumers. An attacker who controls the queried apex (operator runs recon during diligence on `attacker.example`) controls every CNAME response and can in principle aim the walker at names of their choosing.

**Mitigation (layers + ambient bounds):**
- **Entry-point validation (v1.9.13).** The walker checks `_is_public_dns_name(host)` before issuing the first CNAME query. Catches the rare case where an unvalidated name made it into `ctx.related_domains` (e.g. from a populator that didn't suffix-check before adding); that name is rejected at the door without touching the resolver.
- **Per-hop suffix denylist (v1.9.3.5).** Every CNAME target returned by the resolver is validated against `_is_public_dns_name` before the walker continues. Names ending in `.local`, `.localhost`, `.intranet`, `.private`, `.corp`, `.lan`, `.home`, `.home.arpa`, `.internal`, `.test`, `.example`, `.invalid`, `.onion`, and the `.arpa` family are rejected. Single-label names and IP literals are also rejected.
- **Query type restriction across the entire walk (v1.9.4 + v1.9.14).** The walker issues CNAME queries only, on every hop including the terminus. CNAME responses do not cause recursive resolvers to chase further records, so an attacker-controlled name cannot drive the operator's resolver to query deeper internal names while answering. v1.9.3.5 had added an A/AAAA-on-each-hop check that caused exactly that recursive chase, and v1.9.4 removed it. v1.9.13 attempted to add the check back on the terminus only, on the assumption that a CNAME NoAnswer proved the terminus had no CNAME to chase; v1.9.14 reverted the check after a follow-up scanner pass showed authoritative DNS can return type-dependent answers, so the same recursive chase can be triggered by the A or AAAA query even when the prior CNAME query returned nothing.
- **Defense-in-depth on M365 redirect_domain extraction (v1.9.13).** `_detect_m365_cnames` suffix-validates the redirect_domain extracted from a non-Microsoft autodiscover CNAME response before adding it to `ctx.related_domains`. Prevents a private-suffix apex from being planted in the related-domains set even though the walker's own entry-point check would reject it subsequently.
- **Source scoping for CT-derived related domains.** `filter_subdomains` (`sources/cert_providers.py:197`) drops every CT entry that does not end in `.<queried_domain>`. An attacker cannot put `internal.victim.example` in their own cert and have it picked up by recon: the filter requires the name to be under the queried apex.
- **Per-call bounds.** Five-hop maximum, 100-host surface cap, 30-concurrent-query cap, five-second per-query timeout.

**Residual surface (documented, by design):**
- The walker still follows cross-apex CNAMEs the attacker returns at query time (`attacker.example → vault.victim.example → cdn.cloudflare.com`). Cross-apex following is intentional: legitimate CDN and SaaS chains cross apexes routinely. The intermediate hop names are attacker-controllable text and land in evidence output when the terminus matches a fingerprint. The data disclosed is text the attacker already put in their own DNS records, not internal-DNS topology of any third party.
- Split-horizon termini are not dropped by the walker. The v1.9.13 terminus-only A/AAAA check was the planned defense for this case but was reverted in v1.9.14 after the type-dependent-answer attack path was demonstrated against the check itself. Closing this residual requires evidence redaction by default or a dedicated public-DNS resolver path (see "Further defenses not yet shipped" below); neither is currently shipped.
- If the operator runs a split-horizon resolver where one of those attacker-named hops happens to resolve in a private zone, the walker's CNAME query for that name reaches internal DNS (one CNAME query per hop, no recursive A chase). The query is observable in internal DNS logs.

**Further defenses not yet shipped:**
- Evidence redaction (emit only the terminal hop in the default panel, full chain only under `--explain`) - would remove intermediate attacker-chosen names from default output at the cost of `--json` consumers losing the chain trace.
- Dedicated public-DNS resolver for the chain walker (1.1.1.1 / 8.8.8.8) - would eliminate split-horizon landing entirely at the cost of an external dependency operators behind air-gapped networks could not satisfy.

Neither is currently shipped; see `docs/security-audit-resolutions.md` ("Mitigated: CNAME chain walking can query and leak internal DNS names") for the closure-precedence record and tradeoff discussion.

**Pinned by:** `tests/test_cname_chain_validation.py` (including `test_walker_does_not_resolve_a_aaaa_during_walk` and `TestNoAAAAQueriesFromWalker` for the v1.9.4 + v1.9.14 invariant on all three exit paths, `TestEntryPointValidation` for the v1.9.13 entry-point check, and `TestM365RedirectDomainFilter` for the v1.9.13 redirect_domain filter).

### Malicious YAML / user-supplied regex

**Surface:** Custom fingerprint/signal YAML files under `~/.recon/` can contain arbitrary regex patterns.

**Mitigation:** [`recon_tool/fingerprints.py`](../recon_tool/fingerprints.py):
- `yaml.safe_load` (not `yaml.load`) - no arbitrary constructor execution
- Pattern length capped at 500 chars (line 56)
- ReDoS heuristic (`_REDOS_RE` line 68–74) rejects nested quantifiers like
  `(a+)+`, `(a*)+`, and `(\w+)+`, plus polynomial-backtracking shapes such as
  repeated wildcard groups. This is a heuristic guardrail, not a formal regex
  verifier.
- All patterns compile-validated via `re.compile` before use
- Same checks run on `~/.recon/signals.yaml` via `_validate_signal` in `signals.py`
- Custom entries are **additive only** - cannot override built-ins (design invariant)

### SSRF via malicious HTTP redirects

**Surface:** An adversarial upstream (or a DNS-rebound attacker) could redirect an HTTP request to a private/internal IP, potentially exposing cloud-metadata services (169.254.169.254) or internal infrastructure.

**Mitigation:** [`recon_tool/http.py`](../recon_tool/http.py) `_SSRFSafeTransport`:
- Every hop - initial request AND every redirect - validated
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

All posture and hardening tools operate exclusively on the same passive
observables used by the core correlation engine (see
[correlation.md](correlation.md)). The MCP surface adds no new data
sources; it only exposes the existing inference pipeline through a
different transport.

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
