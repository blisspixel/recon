# Security audit resolutions

External audits, scanners, and security-review tools sometimes report
findings that are already closed by subsequent commits — most scanners
flag the commit that *introduced* an issue and don't automatically
trace forward through fix commits. This file is the project's
authoritative disposition record. If a finding listed here is also
reported by a scanner as open, the closure status documented below
takes precedence; the scanner output is stale until it re-scans the
fix commit.

Findings are indexed by *topic* rather than vendor-specific ID so the
record stays portable across audit tools.

For the reporting process and disclosure expectations, see
[`SECURITY.md`](../SECURITY.md). For deeper engineering threat-model
notes, see [`docs/security.md`](security.md).

---

## Closed: MCP doctor/install can execute shadowed `recon_tool` package

| Field | Value |
|---|---|
| **Severity (as audited)** | High |
| **Introduced** | v1.9.2.1 (`recon mcp doctor` / `recon mcp install` shipped without cwd / `PYTHONSAFEPATH` isolation) |
| **Closed** | **v1.9.3.4** — commit `f9b3415` |
| **Pinned by** | `tests/test_mcp_path_isolation.py` |

**Summary.** Before v1.9.3.4, `recon mcp doctor` spawned the server
as `sys.executable -m recon_tool.server` with the caller's
environment and no controlled cwd. Python's `-m` flag prepends cwd to
`sys.path` on Python 3.10 (and on later versions when
`PYTHONSAFEPATH` is unset), so a malicious workspace containing a
`recon_tool/` directory could shadow the installed package and
execute attacker code. The same launch form was persisted into MCP
client configuration by the installer when `recon` was not on PATH,
extending the risk to subsequent client launches.

**Fix shape.**

* `recon_tool/mcp_doctor.py` spawns the subprocess with `cwd` set to
  an empty `tempfile.TemporaryDirectory` and `env["PYTHONSAFEPATH"]
  = "1"`. Cwd isolation works on Python 3.10 (where `PYTHONSAFEPATH`
  is a no-op); the env var is the belt to the cwd-isolation
  suspenders for 3.11+.
* `recon_tool/mcp_install.py` persists `PYTHONSAFEPATH=1` in the
  fallback launch block when `recon` is not found on PATH, so MCP
  clients launching via the persisted config also get the
  protection. `warn_if_fallback` surfaces a stderr advisory when
  the fallback form is written.
* `recon_tool/server.py` carries a runtime guard refusing
  cwd-shadow loads as defense-in-depth.

**Receipts (current code state).**

```python
# recon_tool/mcp_doctor.py
env["PYTHONSAFEPATH"] = "1"  # v1.9.3.4: disable cwd prepend on Py3.11+
with tempfile.TemporaryDirectory(prefix="recon-mcp-doctor-cwd-") as safe_cwd:
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "recon_tool.server"],
        env=env,
        cwd=safe_cwd,
    )
```

```python
# recon_tool/mcp_install.py — build_recon_block()
return {
    "command": sys.executable,
    "args": ["-m", "recon_tool.server"],
    "autoApprove": [],
    "env": {"PYTHONSAFEPATH": "1"},
}
```

---

## Closed: A/AAAA CNAME validation can trigger internal DNS lookups

| Field | Value |
|---|---|
| **Severity (as audited)** | Medium |
| **Introduced** | v1.9.3.5 (`_hop_resolves_publicly` added to chain walker) |
| **Closed** | **v1.9.4** — commit `6abbae1` |
| **Pinned by** | `tests/test_cname_chain_validation.py::test_walker_does_not_resolve_a_aaaa_during_walk` |

**Summary.** The v1.9.3.5 fix added a second defensive check
(`_hop_resolves_publicly`) that resolved A/AAAA records for every
intermediate hop in a CNAME chain. The original intent was to detect
split-horizon DNS where a public-suffix-looking hostname resolves to
a private IP. The audit found that calling A/AAAA on attacker-
influenced hops causes recursive resolvers to chase deeper CNAMEs
internally while answering the address query — leaking the internal
names recon was specifically trying to avoid querying. The check
itself reintroduced the leak it was added to prevent.

**Fix shape.** The walker in `_resolve_cname_chain` is now
**suffix-only**: every hop's name is validated against the private-
suffix denylist (`_is_public_dns_name`), but no A/AAAA queries are
issued during the walk. CNAME queries are the safe primitive —
recursive resolvers do not chase further records when answering a
CNAME-only query. The `_hop_resolves_publicly` helper is preserved
in `dns.py` (marked `# pyright: ignore[reportUnusedFunction]`) for
future callers who can guarantee a fully-suffix-validated name; no
current callers use it.

**Documented tradeoff.** Removing the A/AAAA check trades zero
internal-DNS leakage during the walk against the loss of split-
horizon detection on hops with public-looking suffixes that
resolve to private addresses. v1.9.4's CHANGELOG explicitly
accepts this tradeoff: "v1.9.4 errs on the side of zero internal-
DNS leakage. A future patch may add a terminus-only A/AAAA check
(resolve A/AAAA only after the entire chain has been suffix-
validated, and only on the last hop) if the split-horizon attack
pattern proves common enough to warrant the bounded leak risk."

**Receipt (current code state).**

```python
# recon_tool/sources/dns.py — _resolve_cname_chain
# v1.9.4: removed the A/AAAA resolution check that v1.9.3.5
# added here. A security audit established that calling
# _hop_resolves_publicly on an attacker-influenced target
# causes the recursive resolver to chase deeper CNAMEs while
# answering the A/AAAA query.
# (No call to _hop_resolves_publicly remains in the walk loop.)
```

The regression test
(`test_walker_does_not_resolve_a_aaaa_during_walk`) tracks every
DNS query the walker issues and asserts only `CNAME` queries fire —
never `A` or `AAAA`. A future regression that re-introduces inline
A/AAAA fails this test before reaching a release tag.

---

## Mitigated: CNAME chain walking can query and leak internal DNS names

| Field | Value |
|---|---|
| **Severity (as audited)** | Medium |
| **Introduced** | v1.7.0 / first CNAME surface-attribution commit (audit cites the original pre-defense commit) |
| **Mitigated** | **v1.9.3.5** (`f8b12dd`) + **v1.9.4** (`6abbae1`) |

**Summary.** The original CNAME walker followed attacker-controlled
CNAME targets recursively without validating the resulting names.
A malicious public domain could return CNAMEs to internal /
split-horizon hostnames such as `internal.example`, causing the
operator's resolver to query (and potentially leak in DNS logs)
the internal name.

**Mitigation shape.** Two layers, both shipped:

1. **Suffix denylist (v1.9.3.5).** Every CNAME target name is
   validated against `_is_public_dns_name`, which rejects names
   ending in well-known private suffixes (`.local`, `.corp`,
   `.internal`, `.home.arpa`, `.onion`, etc.) and IP literals
   before any further resolution happens.
2. **Query type restriction (v1.9.4).** The walker issues only
   CNAME queries during the chain walk — no A/AAAA queries. CNAME
   queries return the immediate CNAME target without recursive
   resolvers chasing onward, so an attacker-controlled
   public-suffix name cannot cause the operator's resolver to
   silently query further internal names while answering.

**Residual surface.** A determined attacker can still construct a
CNAME chain entirely under public suffixes (each hop in their own
controlled domain) — those chains will be walked. This is by
design: distinguishing "attacker-influenced public name" from
"legitimate public name" is not feasible passively without
querying. The 5-hop maximum (`_SURFACE_MAX_HOPS`), 100-host
surface cap (`_SURFACE_MAX_HOSTS`), 30-concurrent-query cap
(`_SURFACE_CONCURRENCY`), and 5-second per-query timeout
collectively bound the work an attacker can induce. The CNAMEs
themselves are queries through the operator's resolver to public-
suffix names; they do not pivot to internal namespace, and the
data emitted in `EvidenceRecord` is attacker-controllable text
that the operator already chose to resolve.

**Receipt (current code state).**

```python
# recon_tool/sources/dns.py — _resolve_cname_chain
for _ in range(max_hops):
    results = await _safe_resolve(cur, "CNAME")
    if not results:
        break
    target = results[0].lower().rstrip(".")
    if not target or target == cur:
        break
    if not _is_public_dns_name(target):
        logger.debug(
            "CNAME chain walker: refusing non-public-suffix hop from %s -> %s",
            cur, target,
        )
        break
    chain.append(target)
    cur = target
```

---

## Closed: Splunk SIEM example uses unescaped regex slugs

| Field | Value |
|---|---|
| **Severity (as audited)** | Informational |
| **Introduced** | v1.9.3.8 (`b81a701`) — shadow-IT alert SPL shipped with unsafe regex construction |
| **Closed** | **v1.9.4** — commit `6abbae1` |
| **Pinned by** | `tests/test_siem_examples.py::TestSplunkSearchSafety` |

**Summary.** The v1.9.3.8 shadow-IT alert example used
`match(current_slugs, mvjoin(baseline_slugs, "|"))`, which treats
every baseline slug value as a regex alternation. A baseline slug
containing metacharacters such as `.*` would match every current
slug and silently suppress the alert. recon accepts custom
fingerprint slugs from YAML and MCP-injected fingerprints without
enforcing a regex-safe alphabet, so the baseline could plausibly
contain such values.

**Fix shape.** Both `examples/siem/splunk/savedsearches.conf` and
the copy-pasteable SPL block in the README now use
`mvfilter(NOT in(current_slugs, baseline_slugs))`. The `in()`
function performs literal set-membership; slug values are never
interpreted as regex.

**Receipt (current code state).**

```spl
| eval new_slugs=mvfilter(NOT in(current_slugs, baseline_slugs))
```

The pinning test asserts the safe pattern is present in both the
conf and the README, and asserts the unsafe `match(...,
mvjoin(..., "|"))` form is absent from any executable SPL in the
examples tree. A regression that reverts to the unsafe form
fails the test.

---

## Process notes

* **Closure precedence.** If a scanner flags a finding listed here
  as open, the closure status documented above is authoritative. The
  scanner is reporting against the commit it last scanned, not the
  current `main`. Feed the closure commit SHA back into the scanner
  if it supports per-finding closure pointers.
* **Tradeoff disclosures.** When a finding is closed via a defensive
  choice that trades one risk against another (e.g., the v1.9.4
  CNAME walker dropping A/AAAA at the cost of split-horizon
  detection), the tradeoff is documented in the *Mitigated* row and
  in the corresponding CHANGELOG entry. The decision is reviewable;
  the tradeoff is not invisible.
* **No real-company artifacts.** Audit reports sometimes include
  attacker-supplied hostnames invented during PoC reproduction —
  those names are generic examples, not real internal infrastructure
  of any organization. The receipts above use generic placeholders
  (`internal.example`, `attacker.example`) consistent with the
  project's no-real-company-data policy.
