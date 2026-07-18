# Security Threat Model

This is the engineering-level threat model. For **how to report a
vulnerability**, see [`SECURITY.md`](../SECURITY.md) in the repository root.

recon is a target-read-only CLI tool plus local MCP server with a passive
collection scope. It performs no port scanning, credential handling, inbound
listening, or user-code execution. It can write its own local cache and MCP
client configuration. DNS resolver traffic can be externally visible, MTA-STS
is the only default target-owned HTTP request, and Google CSE and BIMI
certificate requests are explicit opt-in direct probes.

---

## Trust boundaries

| What recon trusts | Rationale |
|---|---|
| The user's configured DNS resolver | recon inherits the OS resolver. A compromised resolver is a compromise of the whole machine. |
| Public OIDC / UserRealm / Google identity / CT endpoints | These are Microsoft, Google, and Sectigo-operated services. recon validates response shapes but cannot out-verify the underlying TLS-authenticated origin. |
| `src/recon_tool/data/fingerprints.generated.json` (built-in fingerprints) | Installed wheels load the checked-in generated JSON. Canonical split YAML is contributor source and ships in the source distribution, not as a second wheel runtime catalog. Both have the same trust level as Python source. |
| `src/recon_tool/data/*.yaml` and `src/recon_tool/data/profiles/*.yaml` (signals, posture rules, profiles) | These ship with the package and are loaded via `yaml.safe_load`. Same trust level as Python source. |
| Python stdlib + pinned dependencies in `uv.lock` | Standard supply-chain trust. CI and release jobs audit locked runtime dependencies on every build. |

| What recon does NOT trust | Mitigation location |
|---|---|
| User-supplied domain strings | `src/recon_tool/validator.py` - regex + length cap + scheme stripping |
| Raw DNS responses (TXT values, MX hostnames, CNAME targets) | Length caps + structured parsing in `src/recon_tool/sources/dns.py` |
| Environment variables (`RECON_CONFIG_DIR`) | Treated as arbitrary user input. Cache operations bind one resolved parent directory, validate lexical child paths, and use descriptor identity checks for reads. |
| Custom YAML at `~/.recon/fingerprints.yaml` and friends | Validated by `_validate_fingerprint`, `_validate_signal`, `_validate_profile` - regex compilation + ReDoS heuristic + required-field checks. Additive-only (cannot override built-ins). |
| CT provider response bodies | Size-capped, filtered for wildcards and malformed entries in `sources/cert_providers.py` |
| Malicious HTTP redirect targets / private-IP redirects | `src/recon_tool/http.py` `_SSRFSafeTransport` validates every hop |

---

## Attack surface & mitigations

### Malicious domain input

**Surface:** A user (or an agent) passes an arbitrary string to `recon <domain>` or a MCP tool.

**Mitigation:** [`src/recon_tool/validator.py`](../src/recon_tool/validator.py):

- Raw input is capped at 500 characters before parsing.
- Only `http://` and `https://` URL schemes are recognized and stripped.
  Bare inputs may include a copied path, query, fragment, or numeric port.
- Unicode hostnames are accepted only when the standard-library IDNA conversion
  round-trips without changing the normalized hostname.
- DNS labels use the letter, digit, and hyphen alphabet with no leading or
  trailing hyphen. The final label is at least two characters and begins with
  an ASCII letter, which admits validated Punycode TLDs while rejecting numeric
  TLDs.
- The normalized ASCII presentation form is capped at 253 octets total and 63
  octets per label before optional Public Suffix List apex reduction.
- A conventional `www.` prefix is removed only when the remainder is still a
  valid domain. A trailing root-label dot is removed, and output is lowercase.
- Invalid input raises `ValueError`; the CLI maps it to exit code 2
  (`EXIT_VALIDATION`). See the full [exit-code contract](schema.md#exit-codes).

### Diagnostic output and local failure artifacts

**Surface:** Debug logs and unexpected-crash artifacts can contain queried
namespaces, local paths, configuration context, or exception details. An
unexpected per-domain batch exception could otherwise copy those details into
structured output consumed or shared downstream.

**Mitigation:** Default batch output replaces unexpected exception details with
stable recovery text in JSON, NDJSON, CSV, and human modes. The full exception
is logged only at debug level. Root help warns operators to review diagnostics
before sharing. The top-level crash handler keeps its existing redaction notice,
and normal downstream pipe closure does not create a crash artifact. Structured
MCP validation-failure logs retain only a request ID and stable reason, never
the rejected domain or validation exception. Dynamic fields rendered by the
default doctor, `doctor --mcp`, `doctor --client`, `doctor --fix`,
`recon mcp install`, and live `recon mcp doctor` paths strip control bytes,
escape Rich markup, and bound displayed detail before rendering.
The live MCP doctor validates local JSON resource structure but never copies a
resource payload into its failure text. A failed later protocol phase retains
only prior check summaries plus bounded spawned-server stderr.

### Malicious DNS responses

**Surface:** A compromised or adversarial DNS response could attempt to exfiltrate via crafted values or trigger injection in downstream formatting.

**Mitigation:**
- Length caps on all DNS string values (`sources/dns.py`)
- A-to-PTR hosting detection only reverse-resolves globally routable unicast
  A-record IPs; private, loopback, link-local, reserved, multicast,
  unspecified, and other non-global addresses are skipped before PTR lookup.
- Rich-text rendering uses `Text.append(value, style=...)` which escapes Rich markup in the user-controlled portion
- Error, warning, and batch-progress sinks that print untrusted strings (a bad domain echoed back, a per-source error reason) escape Rich markup and strip control bytes (`render_error`, `render_warning`; output-injection sweep, v2.1.2), so a crafted domain or DNS value cannot inject terminal escapes or markup
- Markdown rendering backslash-escapes structural characters and existing
  backslashes in source-derived service labels, posture observations,
  explanation text, identity fields, insights, certificate issuers, and domain
  lists after control-byte stripping
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

**Mitigation:** [`src/recon_tool/fingerprints.py`](../src/recon_tool/fingerprints.py):
- `yaml.safe_load` (not `yaml.load`) - no arbitrary constructor execution
- Pattern length capped at 500 chars
- ReDoS heuristic (`_validate_regex` in `fingerprints.py`) rejects nested
  quantifiers like `(a+)+`, `(a*)+`, and `(\w+)+`; a balanced-paren scan
  (`_has_nested_quantifier`, v2.1.1) also catches the redundantly-nested
  `((a+))+` that a flat pattern misses; and an alternation-overlap check
  (`_alternation_redos`) catches prefix-overlapping branches like `(a|aa)+`.
  This is a heuristic guardrail, not a formal regex verifier; the input-length
  caps bound what it does not catch.
- All patterns compile-validated via `re.compile` before use
- Same checks run on `~/.recon/signals.yaml` via `_validate_signal` in `signals.py`
- Custom entries are **additive only** - cannot override built-ins (design invariant)

### SSRF via malicious HTTP redirects

**Surface:** An adversarial upstream (or a DNS-rebound attacker) could redirect an HTTP request to a private, internal, or special-use IP, potentially exposing cloud-metadata services (169.254.169.254) or internal infrastructure.

**Mitigation:** [`src/recon_tool/http.py`](../src/recon_tool/http.py) `_SSRFSafeTransport`:
- Every hop - initial request AND every redirect - validated
- Blocks anything that is not globally routable unicast, including loopback,
  private, link-local, shared-address, unspecified, reserved, documentation,
  multicast, and IPv6 unique-local ranges
- Literal IP check on URL host
- Asynchronous DNS resolution check (IP from resolver vs public-unicast policy)
- Missing hosts, DNS errors, empty answers, and invalid resolved addresses fail
  closed before the HTTP transport can perform its own resolution
- Used by default in all outbound HTTP (OIDC discovery, UserRealm, cert providers, Google identity)

**Known limitation:** The validated address is not pinned to the connection.
`httpx` resolves the hostname again after the preflight, so an attacker who can
change the answer between those operations may still rebind the request. Failing
closed on unresolved destinations removes the prior fail-open path but does not
eliminate this time-of-check/time-of-use residual.

### Path traversal in local caches

**Surface:** `recon cache show ../../etc/passwd`, `recon cache clear ../../settings`, or a crafted `RECON_CONFIG_DIR` could cause a cache layer to read, write, or delete outside its intended directory.

**Mitigation:** [`src/recon_tool/ct_cache.py`](../src/recon_tool/ct_cache.py),
[`src/recon_tool/cache.py`](../src/recon_tool/cache.py), and the shared bounded
JSON loader:

- Resolve and bind one cache parent directory for each write operation.
- Validate the domain without reducing literal-host keys and require the
  lexical child path to remain inside that parent.
- Reject stable symbolic links and Windows reparse-point cache directories,
  use no-follow open semantics where the operating system provides them, and
  verify the opened regular file still has the path's identity.
- Recheck size and metadata after the read, then reject mutation before JSON
  admission.
- Bind decoded payload identity to the expected domain and schema version.
- Reject or ignore invalid paths and entries without raising to the caller
  (tests: `tests/test_ct_cache.py`, `tests/test_cache_roundtrip.py`,
  `tests/test_cache_cli.py`, `tests/test_json_limits.py`).
- Keep operator inspection payload-free. The default `recon cache show`
  overview enumerates filenames for exact totals but validates only the
  lexicographically first 100 cached objects per layer; `--all` is the explicit
  complete mode. Both render only bounded metadata, distinguish absence from
  inspection failure, withhold raw exceptions outside debug logging, and exit
  4 when a requested entry cannot be inspected.
- Count only `*.tmp` artifacts matching the cache writer's domain-and-random-
  nonce filename shape without reading their payload, report them as an
  incomplete exit-4 state, and remove them only in the already-confirmed
  clear-all path. Unrelated temporary files remain untouched. Deletion stays
  nonrecursive and inside the validated cache directory.

**Boundary:** The cache is not a privilege boundary against another local actor
who can replace directories inside the invoking user's configuration tree while
an operation is in progress. Such an actor already controls that user's cache
contents. Stable symlinks, junctions, reparse points, and self-referencing
redirects are rejected; races by an actor with write access remain inside the
documented local-user trust boundary.

### Malicious CT provider responses

**Surface:** A compromised crt.sh / CertSpotter could return extremely large subdomain sets or adversarially crafted names attempting to amplify downstream work.

**Mitigation:** `src/recon_tool/sources/cert_providers.py`:
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
  state (verified in `src/recon_tool/server/app.py` ToolAnnotations and Server
  Instructions)
- Tools accept domain strings that go through the same `validator.py` pipeline
- Invalid domain arguments produce a target-free structured warning with a
  request ID and stable reason code. Raw rejected values and repeated exception
  text are not written to MCP operator logs.
- Importing the server does not mutate shared logging. A default stderr handler
  exists only for the running stdio loop and is removed on exit.
- Unexpected server exits retain one bounded control-free diagnostic line with
  the exception type, so exception text cannot forge terminal rows.
- `inject_ephemeral_fingerprint` only persists in current process memory; it
  never writes to built-in files, custom config files, or the cache.
- Ephemeral fingerprint injection is quota-bounded in-process: 100 fingerprints,
  20 detections per injected fingerprint, and 500 total ephemeral detections.
  Rejected injections return JSON errors instead of growing memory or lookup
  work without bound.
- 120-second TTL cache and per-domain rate limiter prevent repeated-lookup abuse
- No HTTP / OAuth transport, no network listener

All posture and hardening tools operate exclusively on the same public-metadata
observables used by the core correlation engine (see
[correlation.md](correlation.md)). The MCP surface adds no new data
sources; it only exposes the existing inference pipeline through a
different transport.

---

## Out of scope

recon does **not** defend against:

- **Active scanning attacks.** recon does not scan ports, crawl arbitrary target
  applications, or test exploitability. An attacker with a shell on your machine
  can do more than recon can see.
- **Credential theft.** recon handles zero credentials. There is nothing to steal.
- **DNS cache poisoning at the OS level.** If the user's resolver is compromised, the entire threat model is compromised regardless of what recon does.
- **Supply-chain compromise of transitive dependencies.** Locked runtime
  dependencies are checked by blocking `pip-audit` gates in CI and release
  workflows. This detects known advisories; it does not prevent a compromise or
  inspect dependencies in-process.
- **Side-channel timing attacks against the user's identity.** Every query recon makes is visible to the intermediary services (OIDC endpoints, CT providers, the user's DNS resolver). See [`legal.md`](legal.md#what-sees-your-queries) for the exposure inventory.
- **Logging / telemetry exfiltration.** recon emits no telemetry. All output goes to the user's terminal or files they own.
- **Malicious plugin systems.** recon has no plugin system and executes no user code.

---

## Reporting vulnerabilities

See [`SECURITY.md`](../SECURITY.md). TL;DR: email `nick@pueo.io`, do not open a public issue.
