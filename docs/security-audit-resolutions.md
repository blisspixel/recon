# Security audit resolutions

External audits, scanners, and security-review tools sometimes report
findings that are already closed by subsequent commits - most scanners
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
| **Initial mitigation** | v1.9.3.4 - commit `f9b3415` (effective on Python 3.11+; Python 3.10 still relied on the runtime guard) |
| **Fully closed** | **v1.9.9** - `build_recon_block()` rewritten to use `python -c "<sys.path-stripping launcher>"` instead of `python -m recon_tool.server`. The launcher strips empty/`.` entries from `sys.path` BEFORE any `recon_tool` import, blocking the cwd-shadow attack at the language level on every supported Python (including 3.10 where `PYTHONSAFEPATH` is a no-op). |
| **Pinned by** | `tests/test_mcp_path_isolation.py`, `tests/test_mcp_install.py` |

**Summary.** Before v1.9.3.4, `recon mcp doctor` spawned the server
as `sys.executable -m recon_tool.server` with the caller's
environment and no controlled cwd. Python's `-m` flag prepends cwd to
`sys.path` on Python 3.10 (and on later versions when
`PYTHONSAFEPATH` is unset), so a malicious workspace containing a
`recon_tool/` directory could shadow the installed package and
execute attacker code. The same launch form was persisted into MCP
client configuration by the installer when `recon` was not on PATH,
extending the risk to subsequent client launches.

**v1.9.3.4 partial mitigation.**

* `recon_tool/mcp_doctor.py` spawns the subprocess with `cwd` set to
  an empty `tempfile.TemporaryDirectory` and
  `env["PYTHONSAFEPATH"] = "1"`. The cwd isolation works on every
  supported Python, including 3.10; the env var is the
  belt-and-suspenders for 3.11+. **This path was fully closed in
  v1.9.3.4.**
* `recon_tool/mcp_install.py` persisted `PYTHONSAFEPATH=1` in the
  fallback launch block when `recon` was not found on PATH. **This
  path was NOT fully closed in v1.9.3.4** because the MCP installer
  cannot control where the downstream MCP client launches the
  persisted command from. On Python 3.10, `PYTHONSAFEPATH` is a
  no-op; an MCP client launching the persisted
  `python -m recon_tool.server` form from an attacker-influenced
  cwd would still hit the cwd-shadow attack. The runtime guard in
  `server.py` runs AFTER Python imports the module - too late to
  protect against a malicious `recon_tool/server.py` whose payload
  runs at import time.

A subsequent external audit (May 2026) correctly flagged this
remaining gap on the supported Python 3.10 fallback path. The
fix shipped in v1.9.9.

**v1.9.9 full closure.**

`build_recon_block()` now persists a `python -c "<launcher>"` form
instead of `python -m recon_tool.server`. The launcher explicitly
strips `""` and `"."` entries from `sys.path` BEFORE any
`recon_tool` import:

```python
# recon_tool/mcp_install.py - build_recon_block() (v1.9.9)
_FALLBACK_LAUNCH_CODE = (
    "import sys; "
    "sys.path[:] = [p for p in sys.path if p not in ('', '.')]; "
    "from recon_tool.server import main; "
    "main()"
)

return {
    "command": sys.executable,
    "args": ["-c", _FALLBACK_LAUNCH_CODE],
    "env": {"PYTHONSAFEPATH": "1"},  # belt for 3.11+; no-op on 3.10
    "autoApprove": [],
}
```

The `sys.path` strip runs as ordinary Python code BEFORE the
`recon_tool` import, so a malicious `recon_tool/server.py` in cwd
cannot be selected. This protection works on every supported
Python version - language-level rather than env-flag-dependent.

`recon_tool/server.py` still carries the runtime guard as
defense-in-depth (catches misconfigured callers who bypass the
persisted launcher), but it is no longer the sole protection on
Python 3.10.

**Receipts (v1.9.9 code state).**

```python
# recon_tool/mcp_doctor.py
env["PYTHONSAFEPATH"] = "1"  # v1.9.3.4: belt for Python 3.11+
with tempfile.TemporaryDirectory(prefix="recon-mcp-doctor-cwd-") as safe_cwd:
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "recon_tool.server"],
        env=env,
        cwd=safe_cwd,  # v1.9.3.4: cwd isolation works on every supported Python
    )
```

```python
# recon_tool/mcp_install.py - build_recon_block() (v1.9.9)
return {
    "command": sys.executable,
    "args": ["-c", _FALLBACK_LAUNCH_CODE],  # v1.9.9: language-level cwd-strip
    "env": {"PYTHONSAFEPATH": "1"},  # belt-and-suspenders for 3.11+
    "autoApprove": [],
}
```

---

## Closed: A/AAAA CNAME validation can trigger internal DNS lookups

| Field | Value |
|---|---|
| **Severity (as audited)** | Medium |
| **Introduced** | v1.9.3.5 (`_hop_resolves_publicly` added to chain walker) |
| **Closed** | **v1.9.4** - commit `6abbae1` |
| **Pinned by** | `tests/test_cname_chain_validation.py::test_walker_does_not_resolve_a_aaaa_during_walk` |

**Summary.** The v1.9.3.5 fix added a second defensive check
(`_hop_resolves_publicly`) that resolved A/AAAA records for every
intermediate hop in a CNAME chain. The original intent was to detect
split-horizon DNS where a public-suffix-looking hostname resolves to
a private IP. The audit found that calling A/AAAA on attacker-
influenced hops causes recursive resolvers to chase deeper CNAMEs
internally while answering the address query - leaking the internal
names recon was specifically trying to avoid querying. The check
itself reintroduced the leak it was added to prevent.

**Fix shape.** The walker in `_resolve_cname_chain` is now
**suffix-only**: every hop's name is validated against the private-
suffix denylist (`_is_public_dns_name`), but no A/AAAA queries are
issued during the walk. CNAME queries are the safe primitive -
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
# recon_tool/sources/dns.py - _resolve_cname_chain
# v1.9.4: removed the A/AAAA resolution check that v1.9.3.5
# added here. A security audit established that calling
# _hop_resolves_publicly on an attacker-influenced target
# causes the recursive resolver to chase deeper CNAMEs while
# answering the A/AAAA query.
# (No call to _hop_resolves_publicly remains in the walk loop.)
```

The regression test
(`test_walker_does_not_resolve_a_aaaa_during_walk`) tracks every
DNS query the walker issues and asserts only `CNAME` queries fire -
never `A` or `AAAA`. A future regression that re-introduces inline
A/AAAA fails this test before reaching a release tag.

---

## Mitigated: CNAME chain walking can query and leak internal DNS names

| Field | Value |
|---|---|
| **Severity (as audited)** | Medium |
| **Introduced** | **v1.5.0** (`722220f`, 2026-05-01) - first CNAME surface-attribution commit, no defenses |
| **Mitigated** | **v1.9.3.5** (`f8b12dd`), **v1.9.4** (`6abbae1`), **v1.9.13** (entry-point + terminus-only check + redirect_domain filter) |
| **Current receipt** | `recon_tool/sources/dns.py:1732` (`_is_public_dns_name`), `recon_tool/sources/dns.py:1827` (`_resolve_cname_chain`), `recon_tool/sources/dns.py:547-562` (`_detect_m365_cnames` redirect_domain filter) |
| **Pinned by** | `tests/test_cname_chain_validation.py` (59 tests, including `test_walker_does_not_resolve_a_aaaa_on_intermediate_hops`, `TestEntryPointValidation`, `TestTerminusOnlyAAAACheck`, `TestM365RedirectDomainFilter`) |
| **Re-flagged** | 2026-05-17 - scanner pinned to introducing commit `722220f`. Re-flag prompted the v1.9.13 hardening pass even though the audit pointed at the v1.5.0 pre-defense commit. |

**Summary.** The original CNAME walker followed attacker-controlled
CNAME targets recursively without validating the resulting names.
A malicious public domain could return CNAMEs to internal /
split-horizon hostnames such as `internal.example`, causing the
operator's resolver to query (and potentially leak in DNS logs)
the internal name.

**Mitigation shape.** Five layers, all shipped, plus several
ambient bounds:

1. **Suffix denylist (v1.9.3.5).** Every CNAME target name is
   validated against `_is_public_dns_name`, which rejects names
   ending in well-known private suffixes (`.local`, `.localhost`,
   `.intranet`, `.private`, `.corp`, `.lan`, `.home`, `.home.arpa`,
   `.internal`, `.test`, `.example`, `.invalid`, `.onion`, `.arpa`
   and its `.in-addr.arpa` / `.ip6.arpa` zones), single-label
   names, IPv4 dotted-quad literals, and IPv6 colon-hex literals.
   Anything not matching one of those is treated as a name on the
   public DNS and may be followed.
2. **Query type restriction (v1.9.4).** The walker issues only
   CNAME queries during the walk loop - no A/AAAA queries on any
   intermediate hop. CNAME queries return the immediate CNAME
   target without recursive resolvers chasing onward, so an
   attacker-controlled public-suffix name cannot cause the
   operator's resolver to silently query further internal names
   while answering the query.
3. **Entry-point validation (v1.9.13).** The walker checks
   `_is_public_dns_name(host)` before issuing the first CNAME
   query. Catches the rare case where an unvalidated entry made it
   into `ctx.related_domains` (e.g. from a populator that didn't
   suffix-check before adding) - that name is rejected at the door
   without touching the resolver.
4. **Terminus-only A/AAAA check (v1.9.13).** When the walk
   terminates naturally (resolver returns no further CNAME for the
   current name, or returns a self-loop), the walker resolves A
   and AAAA on the terminus only. If every resolved address is in
   private/loopback/link-local/reserved space, the entire chain is
   dropped - the intermediate hop names (which include
   attacker-chosen text) never reach `EvidenceRecord.raw_value`.
   The check runs only when the walker has established the
   terminus has no further CNAME, so no recursive chase is
   possible; the v1.9.4 ban on A/AAAA during the walk loop is
   preserved.
5. **Per-call bounds.** 5-hop maximum (`_SURFACE_MAX_HOPS`),
   100-host surface cap (`_SURFACE_MAX_HOSTS`), 30-concurrent-query
   cap (`_SURFACE_CONCURRENCY`), and 5-second per-query timeout.
6. **Source scoping for CT-derived related domains.**
   `filter_subdomains` in `recon_tool/sources/cert_providers.py:197`
   drops every CT entry that does not end in `.<queried_domain>`,
   so the chain walker never sees a name an attacker put in their
   own cert for a sibling-of-victim domain.
7. **Defense-in-depth on M365 redirect extraction (v1.9.13).**
   `_detect_m365_cnames` suffix-validates the redirect_domain
   extracted from a non-Microsoft autodiscover CNAME response
   before adding it to `ctx.related_domains`. Prevents a private-
   suffix apex from being planted in the related-domains set even
   though the walker's own entry-point check would reject it
   subsequently.
8. **Character-class restriction in `_is_public_dns_name`
   (v1.9.13).** Names are required to contain only ASCII
   alphanumerics, hyphen, dot, and underscore. dnspython's strict
   parser usually rejects names with HTML / shell / control /
   whitespace / non-ASCII characters before they reach recon; this
   check is defense-in-depth in case the parser ever relaxes or a
   future caller passes a name from a non-DNS source. Closes the
   theoretical leak where a lax resolver could smuggle a string
   like `evil<script>.example` into evidence output.
9. **Entry-point case normalization in `_resolve_cname_chain`
   (v1.9.13).** `host` is lowercased and trailing-dot-stripped
   before the entry-point check and the walk loop. A mixed-case
   host followed by a lowercased self-loop CNAME is now detected
   on iteration 1 instead of iteration 2. Not a security gap on
   its own but tightens the walker's invariants.

**Residual surface (real, by design).** The audit text the
scanner re-prints describes the v1.5.0 state. The residual that
remains under the v1.9.13 defenses is narrower:

- An attacker who controls the queried apex (e.g. operator runs
  recon during diligence on `attacker.example`) can return a
  CNAME chain whose every hop is a public-suffix name of their
  choosing AND whose terminus resolves to a public IP they
  control. Those hops are walked, and their names appear in
  `EvidenceRecord.raw_value` when the chain terminus matches a
  built-in `cname_target` fingerprint.
- The v1.9.13 terminus-only A/AAAA check drops chains whose
  terminus resolves only to private space. Attacks that try to
  end a chain on a split-horizon-internal target are now caught.
- The narrower residual: an attacker can still emit intermediate
  hop names of their choosing into evidence output by pointing a
  legitimate-fingerprinted terminus (auth0.com, cloudflare.net,
  etc.) behind attacker-chosen intermediate names. Those
  intermediate names land in DNS logs and in `--explain` /
  `--json` chain traces. The information disclosed is text the
  attacker already chose to put in their own DNS records, not
  internal-DNS topology of any third party.
- If the operator runs a split-horizon resolver where one of
  those public-suffix intermediate names happens to resolve in a
  private zone, the walker's CNAME query for that name does
  reach internal DNS (one CNAME query per hop, no recursive A
  chase). The query is observable in internal DNS logs. The
  v1.9.13 terminus check does not catch this case directly
  because the terminus is the chain's last hop, not the
  intermediate one. Per-call bounds (5 hops, 100 hosts) limit
  the guess rate per recon invocation.

**Why this residual is not closed further.** Distinguishing
"attacker-influenced public name" from "legitimate public name"
passively is not feasible - every CDN and SaaS chain crosses
apexes routinely, and the walker cannot tell them apart without
an off-channel signal. The v1.9.3.5 attempt to add a
resolved-address check on each intermediate hop
(`_hop_resolves_publicly` called inside the walk loop)
re-introduced the leak it was added to prevent by causing the
recursive resolver to chase deeper CNAMEs while answering A/AAAA.
v1.9.4 removed that helper from the walk loop, and v1.9.13
brought it back in the only place where it is provably safe: on
the terminus only, after the walker has established the terminus
has no further CNAME.

A further reduction would either (a) emit only the terminal hop
in `EvidenceRecord.raw_value` by default and gate full-chain
emission behind `--explain` - would remove attacker-chosen
intermediate names from default output at the cost of
`--json` consumers losing the chain trace, or (b) route the
chain walker's queries through a dedicated public-DNS resolver
(1.1.1.1 / 8.8.8.8) - would eliminate the split-horizon
landing entirely at the cost of an external dependency operators
behind air-gapped or corporate-restricted networks could not
satisfy. Neither is currently shipped.

**Engineering rationale for not shipping (a) or (b) right now.**

The residual appears structural rather than fixable in code. The
chain walker performs DNS lookups on names the queried apex
returns, those lookups go through the operator's resolver, and
when the queried apex is adversarial, the adversary chooses the
names. Two questions help decide whether more hardening is worth
the cost: what does the adversary plausibly gain, and what does
the legitimate operator give up to close it?

*What the adversary plausibly gains.* The strings the adversary
emits into recon output are strings they wrote in their own DNS
records. They learn little new about the operator from those
strings themselves. The new signal is whether a guessed
public-suffix name in someone else's namespace resolves to a
CNAME the operator's resolver can see. If the operator uses a
typical public resolver (1.1.1.1, ISP, etc.), that signal is the
same one anyone in the world gets by typing the same `dig`
command. If the operator runs split-horizon DNS, the signal can
be slightly richer (whether internally-routed names exist). But
the adversary also needs to be able to observe the resulting
output. For a local CLI invocation, that means being in a
privileged position relative to the operator already. The
per-call bounds (5 hops, 100 hosts, 30 concurrent, 5s timeout)
cap how much guessing the adversary can drive per recon
invocation.

*What the legitimate operator gives up to close it.*

* Option (a), redaction by default, costs chain-trace
  visibility for every `--json` consumer. The chain shape is a
  useful signal for incident-response work (spotting lookalike
  infrastructure, finding shared CDN edges, attribution to a
  known reseller). Hiding it by default means most operators
  running recon defensively would pay a real cost to close a
  residual that mostly matters when output is shared with
  someone untrusted.
* Option (b), dedicated public-DNS resolver in the walker,
  would break recon in environments that block outbound DNS to
  anything except the local corporate resolver. Those
  environments are common in regulated and high-security
  workplaces, which tend to overlap with the operators most
  likely to face adversarial-domain investigations. The defense
  would break for the users it was meant to protect, with a
  silent failure mode (chains empty, everything else still
  works).

*Framing.* Recon's contract is "given a domain you chose to look
up, return public observables." The contract assumes the
operator picked the input. Making recon defensive against its
own input would change that contract. The position we land on is
that data from the internet is data from the internet, and the
same OpSec that applies to running `curl` or `dig` against an
adversary-controlled hostname applies to running recon against
one. The v1.9.13 hardening pass closes the specific harm class
the audit identified (internal-DNS topology leak via the chain
walker). The remaining residual is a property of doing DNS
lookups at all and is bounded by the per-call caps. We document
it here rather than hide it in the implementation.

**Receipt (current code state).**

```python
# recon_tool/sources/dns.py:1827 - _resolve_cname_chain (v1.9.13)
if not _is_public_dns_name(host):
    logger.debug(
        "CNAME chain walker: refusing non-public-suffix entry point %s",
        host,
    )
    return []

chain: list[str] = []
cur = host
terminated_cleanly = False
for _ in range(max_hops):
    results = await _safe_resolve(cur, "CNAME")
    if not results:
        terminated_cleanly = True
        break
    target = results[0].lower().rstrip(".")
    if not target or target == cur:
        terminated_cleanly = True
        break
    if not _is_public_dns_name(target):
        # cur has CNAME to rejected target; terminus check skipped.
        break
    chain.append(target)
    cur = target

if chain and terminated_cleanly and not await _hop_resolves_publicly(chain[-1]):
    return []
return chain
```

```python
# recon_tool/sources/dns.py:547-562 - _detect_m365_cnames (v1.9.13)
elif cl and not cl.endswith(domain.lower()):
    redirect_domain = cl.split(".", 1)[1] if "." in cl else None
    if (
        redirect_domain
        and "." in redirect_domain
        and redirect_domain != domain.lower()
        and _is_public_dns_name(redirect_domain)  # v1.9.13
    ):
        ctx.related_domains.add(redirect_domain)
```

The regression tests in
`tests/test_cname_chain_validation.py` track every DNS query
the walker issues. `test_walker_does_not_resolve_a_aaaa_on_intermediate_hops`
pins the v1.9.4 invariant (no A/AAAA on intermediate hops);
`TestEntryPointValidation` pins the v1.9.13 entry-point check
(no DNS query on private-suffix host); `TestTerminusOnlyAAAACheck`
pins the v1.9.13 terminus check including the skip-when-unsafe
behavior on max_hops and suffix-rejection exits;
`TestM365RedirectDomainFilter` pins the v1.9.13 redirect_domain
suffix filter. 59 tests in that file pass on current main.

---

## Closed: Splunk SIEM example uses unescaped regex slugs

| Field | Value |
|---|---|
| **Severity (as audited)** | Informational |
| **Introduced** | v1.9.3.8 (`b81a701`) - shadow-IT alert SPL shipped with unsafe regex construction |
| **Closed** | **v1.9.4** - commit `6abbae1` |
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
  if it supports per-finding closure pointers. When a scanner repeats
  a previously-closed finding against the original introducing commit,
  add a **Re-flagged** row to the relevant entry above with the date
  and the cited commit; do not re-open the finding.
* **Mitigated vs Closed.** *Closed* means the attack class no longer
  works against the current code. *Mitigated* means a documented
  residual remains, with explicit reasoning for why it is left in
  place (usually because closing it would re-introduce a different
  failure mode that was specifically audited and rejected). When
  reading an entry, the residual-surface paragraph is load-bearing,
  not boilerplate.
* **Tradeoff disclosures.** When a finding is closed via a defensive
  choice that trades one risk against another (e.g., the v1.9.4
  CNAME walker dropping A/AAAA at the cost of split-horizon
  detection), the tradeoff is documented in the *Mitigated* row and
  in the corresponding CHANGELOG entry. The decision is reviewable;
  the tradeoff is not invisible.
* **No real-company artifacts.** Audit reports sometimes include
  attacker-supplied hostnames invented during PoC reproduction -
  those names are generic examples, not real internal infrastructure
  of any organization. The receipts above use generic placeholders
  (`internal.example`, `attacker.example`, `victim.example`)
  consistent with the project's no-real-company-data policy.
