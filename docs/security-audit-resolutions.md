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

## Closed: ingestion-boundary resilience round (v2.1.9)

| Field | Value |
|---|---|
| **Severity (as audited)** | High (HTTP decompression bomb); Medium / Low (the rest) |
| **Source** | Internal boundary fault-injection audit (2026-06), adversarially verified |
| **Fully closed** | **v2.1.9** |
| **Pinned by** | `tests/test_resilience_hardening.py` |

A fault-injection sweep across every external-input boundary (DNS, CT / cert,
identity endpoints, HTTP, file / cache) confirmed four gaps an attacker who
controls a queried domain (or a CT provider) could reach. Each now degrades
cleanly with no crash, hang, or unbounded resource use.

- **HTTP decompression bomb (High).** `_MaxBytesStream` caps the response body
  at 10 MB, but it counts the *compressed* transfer bytes; httpx decodes
  Content-Encoding downstream of the transport stream, so a ~9 MB gzip body
  could decode to ~9 GB and exhaust memory on `resp.json()` / `resp.text`. The
  hosts behind `mta-sts.<domain>`, `cse.<domain>`, the BIMI VMC URL, and the CT
  providers are attacker-influenceable. **Fix:** recon requests
  `Accept-Encoding: identity` and the SSRF transport refuses any response that
  still carries a compressing Content-Encoding (`_RefusingStream`), since a host
  that ignores the identity request is the bomb vector. The two `http.py`
  docstrings that incorrectly claimed the byte cap defended against this are
  corrected to describe the actual mechanism.
- **Poisoned-cache RecursionError (Medium).** A deeply-nested JSON file under
  `~/.recon` raises `RecursionError` (a `RuntimeError`, not a `ValueError`),
  which the cache loaders' except tuples did not catch, so a poisoned cache file
  crashed the next lookup instead of degrading to a clean miss. **Fix:**
  `RecursionError` added to the catch in `cache_get`, `ct_cache_get`,
  `ct_cache_show`, and `rate_limit._load_persisted`, plus a pre-read file-size
  cap on the cache loaders.
- **CT graph entry-count amplification (Medium).** A fixed small SAN set reused
  across tens of thousands of CertSpotter issuances never tripped
  `MAX_GRAPH_NODES`, yet re-ran the per-cert clique build and accumulated one
  issuer string per edge per entry (quadratic in entries; about 21 s and
  150 MB in the measured worst case, blocking the event loop). **Fix:**
  `_build_graph` is bounded by `_MAX_GRAPH_ENTRIES`, per-edge issuer samples are
  capped at `_MAX_EDGE_ISSUER_SAMPLES`, and CertSpotter's accumulated entry list
  is capped like crt.sh's.
- **CT provider RecursionError (Low).** The providers' `resp.json()` guard
  caught only `ValueError`, so a deeply-nested CT payload skipped the
  provider-local degrade (the limiter health signal). The orchestrator's broad
  `except` still prevented a crash, so this is a degrade-fidelity gap, not a DoS.
  **Fix:** the guard now catches `(ValueError, RecursionError)`.

The same audit *rejected* seven other candidate gaps as already neutralized by
existing guards (the aggregate 120 s resolve timeout bounding the SPF
redirect fan-out, the 64 KB DNS message ceiling, the per-cert SAN slice and
entry caps, the 10 MB body cap on the identity path, and PyYAML's
reference-shared alias handling for the home-directory overlay loaders), which
is recorded here so a re-scan does not re-open them.

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
| **Re-introduced** | v1.9.13 (terminus-only A/AAAA check added on the assumption that a prior CNAME NoAnswer proved no chase was possible on a subsequent A/AAAA query) |
| **Re-closed** | **v1.9.14** - terminus-only A/AAAA check reverted after 2026-05-17 scanner pass flagged the type-dependent-answer attack path |
| **Pinned by** | `tests/test_cname_chain_validation.py::TestNoAAAAQueriesFromWalker` (natural exit, max_hops exit, suffix-rejection exit) and `test_walker_does_not_resolve_a_aaaa_during_walk` |

**Summary.** The v1.9.3.5 fix added a second defensive check
(`_hop_resolves_publicly`) that resolved A/AAAA records for every
intermediate hop in a CNAME chain. The original intent was to detect
split-horizon DNS where a public-suffix-looking hostname resolves to
a private IP. The audit found that calling A/AAAA on attacker-
influenced hops causes recursive resolvers to chase deeper CNAMEs
internally while answering the address query, leaking the internal
names recon was specifically trying to avoid querying. The check
itself reintroduced the leak it was added to prevent.

**Fix shape.** The walker in `_resolve_cname_chain` is
**suffix-only**: every hop's name is validated against the private-
suffix denylist (`_is_public_dns_name`), and no A/AAAA queries are
issued during the walk. CNAME queries are the safe primitive:
recursive resolvers do not chase further records when answering a
CNAME-only query. The unused `_hop_resolves_publicly` /
`_is_private_ip_literal` path was later removed entirely, so there
is no dormant A/AAAA helper in `dns.py` for future callers to
accidentally revive.

**Documented tradeoff.** Removing the A/AAAA check trades zero
internal-DNS leakage during the walk against the loss of split-
horizon detection on hops with public-looking suffixes that
resolve to private addresses. v1.9.4's CHANGELOG explicitly
accepts this tradeoff: "v1.9.4 errs on the side of zero internal-
DNS leakage. A future patch may add a terminus-only A/AAAA check
(resolve A/AAAA only after the entire chain has been suffix-
validated, and only on the last hop) if the split-horizon attack
pattern proves common enough to warrant the bounded leak risk."

**v1.9.13 deferred-future attempt and v1.9.14 reversion.** v1.9.13
shipped the deferred terminus-only A/AAAA check the v1.9.4 note
described, on the assumption that "no CNAME in the previous
CNAME-query response" implied "no CNAME chase possible on a
subsequent A/AAAA query." A 2026-05-17 scanner pass against the
v1.9.13 walker showed the assumption does not hold: authoritative
DNS servers can return type-dependent answers, so a malicious
server can answer the CNAME query for the terminus with NoAnswer
while returning a CNAME to an internal/split-horizon name on the
A or AAAA query. The recursive resolver follows that CNAME during
A resolution, re-introducing the v1.9.4 leak through the same
helper. v1.9.14 reverts the terminus check; the walker again
issues CNAME queries only. The v1.9.13 entry-point validation and
the M365 `redirect_domain` suffix filter are preserved (neither
depends on A/AAAA).

**Receipt (current code state).**

```python
# recon_tool/sources/dns.py - _resolve_cname_chain (v1.9.14)
# The walker issues only CNAME queries during the walk loop. The
# v1.9.13 terminus-only A/AAAA check was reverted after the
# type-dependent-answer attack path was demonstrated, and the
# unused A/AAAA helper was removed so it cannot be reused by
# accident.
```

The regression tests in
`tests/test_cname_chain_validation.py::TestNoAAAAQueriesFromWalker`
track every DNS query the walker issues on each exit path
(natural exit, `max_hops` exit, suffix-rejection exit) and assert
no A or AAAA query ever fires. The surface-attribution regression
`tests/test_surface_attribution.py::test_surface_classifier_drops_private_cname_target_without_evidence`
also pins the original scanner claim: an internal-looking CNAME
target is not followed and is not emitted in `EvidenceRecord.raw_value`.
A future regression that re-introduces inline A/AAAA or evidence
emission for rejected private hops fails before reaching a release
tag.

---

## Mitigated: CNAME chain walking can query and leak internal DNS names

| Field | Value |
|---|---|
| **Severity (as audited)** | Medium |
| **Introduced** | **v1.5.0** (`722220f`, 2026-05-01) - first CNAME surface-attribution commit, no defenses |
| **Mitigated** | **v1.9.3.5** (`f8b12dd`), **v1.9.4** (`6abbae1`), **v1.9.13** (entry-point validation + redirect_domain filter), **v1.9.14** (terminus-only A/AAAA check reverted after type-dependent-answer attack path demonstrated) |
| **Current receipt** | `recon_tool/sources/dns.py:1732` (`_is_public_dns_name`), `recon_tool/sources/dns.py:1857` (`_resolve_cname_chain`), `recon_tool/sources/dns.py:547-562` (`_detect_m365_cnames` redirect_domain filter) |
| **Pinned by** | `tests/test_cname_chain_validation.py` (including `test_walker_does_not_resolve_a_aaaa_during_walk`, `TestEntryPointValidation`, `TestNoAAAAQueriesFromWalker`, `TestM365RedirectDomainFilter`) |
| **Re-flagged** | 2026-05-17 - scanner pinned to introducing commit `722220f`. Re-flag prompted the v1.9.13 hardening pass even though the audit pointed at the v1.5.0 pre-defense commit. A subsequent scanner pass against v1.9.13 itself flagged the new terminus-only A/AAAA check on the type-dependent-answer path, prompting the v1.9.14 reversion documented above. |

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
   suffix-check before adding); that name is rejected at the door
   without touching the resolver.
4. **Terminus-only A/AAAA check attempted in v1.9.13, reverted
   in v1.9.14.** v1.9.13 added an A/AAAA query on the chain
   terminus after the walk completed naturally, intending to drop
   chains whose terminus resolved only to private space. The
   safety argument was that a prior CNAME-query NoAnswer proved
   the terminus had no CNAME, so no chase was possible. A
   2026-05-17 scanner pass showed the argument is wrong:
   authoritative DNS can return type-dependent answers, so the
   subsequent A/AAAA query can trigger a CNAME chase to an
   internal name even when the CNAME-only query returned nothing.
   v1.9.14 reverted the terminus check. The v1.9.4 ban on A/AAAA
   during the walk is restored unconditionally, and the
   split-horizon detection the terminus check was meant to add is
   left as a documented residual (see below).
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
remains under the v1.9.14 defenses is narrower:

- An attacker who controls the queried apex (e.g. operator runs
  recon during diligence on `attacker.example`) can return a
  CNAME chain whose every hop is a public-suffix name of their
  choosing. Those hops are walked, and their names appear in
  `EvidenceRecord.raw_value` when the chain terminus matches a
  built-in `cname_target` fingerprint. The information disclosed
  is text the attacker already chose to put in their own DNS
  records, not internal-DNS topology of any third party.
- Split-horizon termini are not dropped by the walker. The
  v1.9.13 terminus-only A/AAAA check was the planned defense for
  this case but was reverted in v1.9.14 after the
  type-dependent-answer attack path was demonstrated against the
  check itself. Closing this residual requires either redaction
  by default (option (a) below) or a dedicated public-DNS
  resolver path (option (b) below); neither is currently shipped.
- If the operator runs a split-horizon resolver where one of
  those public-suffix names happens to resolve in a private zone,
  the walker's CNAME query for that name does reach internal DNS
  (one CNAME query per hop, no recursive A chase). The query is
  observable in internal DNS logs. Per-call bounds (5 hops, 100
  hosts) limit the guess rate per recon invocation.

**Why this residual is not closed further.** Distinguishing
"attacker-influenced public name" from "legitimate public name"
passively is not feasible: every CDN and SaaS chain crosses
apexes routinely, and the walker cannot tell them apart without
an off-channel signal. The v1.9.3.5 attempt to add a
resolved-address check on each intermediate hop
(`_hop_resolves_publicly` called inside the walk loop)
re-introduced the leak it was added to prevent by causing the
recursive resolver to chase deeper CNAMEs while answering A/AAAA.
v1.9.4 removed that helper from the walk loop. v1.9.13 brought
it back in a position the docstring described as "provably safe":
on the terminus only, after the walker had established the
terminus had no further CNAME. The 2026-05-17 scanner pass
showed that argument was wrong because authoritative DNS can
answer the CNAME and A/AAAA queries differently for the same
name. v1.9.14 reverted the terminus check; A/AAAA is now banned
on every hop in the walker.

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
one. The v1.9.13 hardening pass closed the specific harm class
the audit identified (internal-DNS topology leak via the chain
walker); v1.9.14 reverted the terminus-only A/AAAA layer after a
follow-up scanner pass showed it had reopened the v1.9.4 leak
through a type-dependent-answer path. The remaining residual is
a property of doing DNS lookups at all and is bounded by the
per-call caps. We document it here rather than hide it in the
implementation.

**Receipt (current code state).**

```python
# recon_tool/sources/dns.py - _resolve_cname_chain (v1.9.14)
if not _is_public_dns_name(host):
    logger.debug(
        "CNAME chain walker: refusing non-public-suffix entry point %s",
        host,
    )
    return []

chain: list[str] = []
cur = host
for _ in range(max_hops):
    results = await _safe_resolve(cur, "CNAME")
    if not results:
        break
    target = results[0].lower().rstrip(".")
    if not target or target == cur:
        break
    if not _is_public_dns_name(target):
        break
    chain.append(target)
    cur = target

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
the walker issues. `test_walker_does_not_resolve_a_aaaa_during_walk`
pins the v1.9.4 + v1.9.14 invariant (no A/AAAA on any hop);
`TestEntryPointValidation` pins the v1.9.13 entry-point check
(no DNS query on private-suffix host);
`TestNoAAAAQueriesFromWalker` pins the v1.9.14 reversion across
all three exit paths (natural exit, `max_hops` exit, suffix
rejection); `TestM365RedirectDomainFilter` pins the v1.9.13
redirect_domain suffix filter. The classifier-level regression
`test_surface_classifier_drops_private_cname_target_without_evidence`
pins that rejected private hops do not reach
`EvidenceRecord.raw_value`.

### Second instance: SPF `redirect=` chasing (v1.9.15)

A follow-up review found the same internal-DNS leak class on a
different code path. The SPF `redirect=` chaser
(`_follow_spf_redirect`) resolves the redirect target of the
queried domain's SPF record to determine whether the chain ends in
`-all` (RFC 7208 6.1). Because the owner of the queried domain
authors their own SPF record, the redirect target is
attacker-controlled, and unlike a CNAME target it can name an
arbitrary zone rather than a subdomain of the queried apex. A
record such as `v=spf1 redirect=secret.internal.corp` would have
driven the operator's resolver to query the internal name, the
same DNS-oracle behavior as the original CNAME finding.

v1.9.15 adds the same suffix denylist guard the CNAME walker uses:

```python
# recon_tool/sources/dns.py - _follow_spf_redirect (v1.9.15)
target = match.group(1).strip().rstrip(".")
if not target or "." not in target:
    return
if not _is_public_dns_name(target):
    return  # refuse before any query; covers the recursive hop too
target_records = await _safe_resolve(target, "TXT")
```

The guard sits at the top of the function, so each recursive hop
(up to the existing `max_depth=3` cap) re-enters and is validated.
The SPF `include:` mechanism is only counted
(`spf_include_count`), never resolved, so it does not share this
path. Regression coverage:
`TestSpfRedirectBlocksPrivateTargets` in
`tests/test_cname_chain_validation.py` asserts a private-suffix
target is never queried and does not credit SPF strict, while a
legitimate public target ending in `-all` still does.

### Third layer: generalized canonical-name guard (v1.9.17)

The CNAME walker (CNAME-only) and the SPF chaser (per-target suffix
check) each close one path. v1.9.17 closes the rest of the class at a
single choke point. recon issues many non-CNAME queries on subdomains
of a domain whose DNS the looked-up party controls: DKIM-selector TXT,
SRV records, and the IdP / Exchange / wildcard probe prefixes. Any
non-CNAME query (A, AAAA, TXT, MX, SRV, ...) makes the recursive
resolver chase a CNAME on the queried name server-side before recon
sees the answer, so a prefix delegated to an internal name would be
queried by the operator's resolver.

**The guard.** `_safe_resolve` inspects `answers.canonical_name` (the
name the query resolved to after any chase) for every query type
except CNAME and PTR. When a chase occurred (`canonical != queried`)
and the canonical name fails `_is_public_dns_name`, the whole answer
is discarded:

```python
# recon_tool/sources/dns.py - _safe_resolve (v1.9.17)
answers = await resolver.resolve(domain, rdtype, lifetime=timeout)
if rdtype not in _CANONICAL_GUARD_SKIP_RDTYPES:  # {"CNAME", "PTR"}
    queried = domain.strip().rstrip(".").lower()
    canonical = str(answers.canonical_name).rstrip(".").lower()
    if canonical != queried and not _is_public_dns_name(canonical):
        return []  # resolver chased to a non-public canonical
```

Discarding (rather than inspecting and reporting) means an internal
name is never returned in records (no disclosure) and a private-chased
query is indistinguishable from a name that does not resolve (no
observable oracle, since the detection that would have fired does not).

**Why CNAME and PTR are exempt.** A CNAME query returns the immediate
record without the resolver chasing further, and the walker validates
that target itself. PTR records legitimately CNAME within the `.arpa`
tree (RFC 2317 classless reverse delegation), so a private-looking
`.arpa` canonical there is normal, not a leak; the PTR caller already
guards on global-IP scope (see the hosting-PTR path).

**A-presence probes.** `_detect_idp_hub`, `_detect_exchange_onprem`,
and the on-prem wildcard guard now resolve through
`_resolves_to_public_endpoint`, which is CNAME-first: a private CNAME
target is rejected by suffix before any A/AAAA query, so the obvious
attack costs zero internal queries. Direct-A self-hosted IdP and
on-prem Exchange detection is unchanged because a name with no CNAME
still falls through to the canonical-guarded A query.

**Documented residual.** In the type-dependent-answer case (the
authoritative server answers the CNAME query with no record but
returns a CNAME on the A query, the same trick that defeated the
v1.9.13 terminus check) a single A query still fires and the resolver
chases it once. The guard discards the result, so there is no
disclosure and no observable oracle, but one blind query reaches the
operator's resolver. Eliminating even that would require dropping
direct-A detection entirely, which would remove self-hosted IdP and
on-prem Exchange detection; the project keeps the detection and
accepts the blind, feedback-free query. Regression coverage:
`TestSafeResolveCanonicalGuard` and `TestResolvesToPublicEndpoint` in
`tests/test_cname_chain_validation.py`.

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

## Dependency advisories (CI audit gate, v1.9.16)

The CI `audit` job runs `pip-audit` against the frozen runtime
dependency set on every push and PR. Two advisories surfaced on
2026-05-20 against already-locked versions (newly published, not a
regression in any recon commit):

**idna 3.11, CVE-2026-45409 - fixed.** `idna` is transitive (via
httpx / anyio). The lockfile was bumped to idna 3.15, which carries
the fix. No ignore needed; the audit passes on the upgraded version.

**pyjwt, PYSEC-2025-183 / CVE-2025-45768 - fixed.** The historical
2.12.1 exception was removed on 2026-07-10 after the lockfile moved to
PyJWT 2.13.0 and an unignored audit of the frozen runtime dependency set
reported no known vulnerabilities. CI and the release workflow now run the
same unqualified `pip-audit` gate. The earlier reachability analysis remains
part of the audit history, but no exception is active.

---

## Closed: round-two ingestion audit (CT data + VMC fetch, v1.9.18)

Current behavior since v2.3.7 is stricter than the historical closure below:
the opt-in BIMI fetch records a plausible certificate document but does not
extract or trust subject identity without certificate-chain and VMC-profile
validation.

After the DNS internal-name leak class was closed, a second audit pass
looked at the other attacker-controlled data recon ingests: certificate
fields from CT logs (SAN names, issuer names) and the BIMI VMC fetch.
The looked-up domain's owner controls all of these (anyone can log a
certificate for a domain they own to a public CT log, and they author
their own BIMI TXT record). Three findings, each reachable on a normal
lookup.

### VMC fetch SSRF (HIGH) - closed

`_parse_bimi_vmc` extracts an `a=` URL from the BIMI TXT record and
fetched it with only an `.endswith(".pem")` check. The host came
straight from attacker-controlled DNS, so `a=https://attacker.example/x.pem`
(or an internal / split-horizon / IP-literal host) turned recon into an
attacker-directed outbound GET, with the shared client's
`follow_redirects=True` allowing a redirect onward. This was the only
outbound call in the tool whose host was attacker-chosen.

Fix: validate the URL before any fetch and disable redirects.

```python
# recon_tool/sources/dns.py - _parse_bimi_vmc (v1.9.18)
parsed = urlparse(a_url)
host = (parsed.hostname or "").lower()
if (
    parsed.scheme != "https"
    or parsed.username
    or parsed.password
    or parsed.port not in (None, 443)
    or not _is_public_dns_name(host)
):
    return
resp = await client.get(a_url, follow_redirects=False)
```

`_is_public_dns_name` (the same denylist the CNAME walker uses) rejects
IP literals and internal suffixes; the https / credential / port checks
reject the other URL-shape tricks; redirects are off; and the client's
transport still blocks private-IP destinations as defense in depth.
Legitimate VMCs are served over https from public hosts, so there is no
false negative.

### ANSI-escape / newline injection via CT data (HIGH) - closed

Certificate SAN names flowed into `related_domains` (and the wildcard /
burst surfaces) and issuer names into `top_issuers` with no character
validation. rich's `strip_control_codes` does not remove ESC (0x1B), so
a SAN or issuer carrying raw control bytes would emit ANSI escape
sequences to the operator's terminal when rendered (cursor moves, screen
clear, OSC sequences), and an interior newline would inject extra lines
into the markdown / MCP output an agent or SIEM consumes.

Fix at ingestion, two complementary tools:

- **SAN names** must be clean DNS names. `filter_subdomains` and the
  per-provider SAN extraction now drop any value failing
  `_is_safe_san_name` (ASCII letter-digit-hyphen plus dot, underscore,
  and the wildcard label). A malformed name is not a real related
  domain, so rejection (not sanitization) is correct.
- **Issuer and VMC subject names** are free text, not DNS names, so they
  are scrubbed with `recon_tool.validator.strip_control_chars` (removes
  C0 0x00-0x1F, DEL 0x7F, and C1 0x80-0x9F, bounds length) before
  counting and display. "DigiCert Inc" is unchanged; an ESC-laden
  payload is neutralized.

Regression coverage: `tests/test_bimi_vmc.py`,
`TestCertDataSanitization` in `tests/test_cert_providers.py`, and
`TestStripControlChars` in `tests/test_validator.py`.

### Lower-severity items noted, not yet changed

The audit also noted defense-in-depth items that are not exploitable
under the threat model and are left for a later polish pass: restrictive
`0o700` / `0o600` permissions on the `~/.recon` cache and config
directories (currently umask-dependent; local filesystem access is out
of scope), and a one-line note that `RECON_CONFIG_DIR` is a trust
boundary.

---

## Closed: round-three audit (MCP, CLI, output, DoS - v1.9.19)

A third pass ran four parallel reviews: the MCP server surface, the CLI
/ batch / cache paths, output-format injection, and DoS / resource
exhaustion. It confirmed rounds 1-2 held and found a further set of
issues, all fixed in v1.9.19.

### HTTP response-body size cap (HIGH) - closed

The shared client read whole bodies into memory (`resp.json()` /
`resp.text`). Several fetched endpoints have a host influenced by the
looked-up domain (`cse.<domain>`, `mta-sts.<domain>`, the BIMI `a=`
URL, an autodiscover redirect), so an oversized or gzip-decompression-
bomb response could grow memory without bound before the per-cert /
per-name caps applied. `recon_tool/http.py` now wraps every response
stream in `_MaxBytesStream`, which aborts the read past a 10 MB cap.
One choke point in `http_client()`; all call sites inherit it.

### Malformed BIMI port aborted the DNS source (MED, v1.9.18 regression) - closed

The SSRF validation added in v1.9.18 (round 2) read
`urlparse(a_url).port` before `_parse_bimi_vmc`'s `try`/`except`.
`urllib` raises `ValueError` on a malformed or out-of-range port
(`:bad`, `:99999`), so a crafted BIMI `a=` URL made the helper raise.
`_detect_email_security` awaited it without a local catch and
`_detect_services` gathers detectors, so the exception reached
`DNSSource.lookup`, which converts a propagated detector error into a
whole-source error - dropping otherwise valid SPF / DMARC / MX / CNAME
intelligence for that domain. Not SSRF and not a process crash, but an
attacker-controlled per-lookup availability / integrity bug introduced
by the round-2 fix.

Two-layer fix: the port is now read inside a `try`/`except ValueError`
that refuses the URL cleanly, and the `_parse_bimi_vmc` call in
`_detect_email_security` is wrapped in `try`/`except` so this
best-effort VMC enrichment can never abort the source (defense in depth
against any future unguarded raise in the helper). Regression coverage
adds malformed-port cases to `tests/test_bimi_vmc.py` plus a test that
a raising `_parse_bimi_vmc` does not abort `_detect_email_security`.

### Attacker-free-text sanitization, completed (MED) - closed

Rounds 1-2 sanitized CT SAN / issuer names and the BIMI subject. The
round-3 reviews found the free-text fields those passes missed, each
reaching a sink that does not neutralize control bytes (`rich`'s
`Text.append` does not strip ESC) or markdown / MCP output:

- `display_name` (GetUserRealm `FederationBrandName`), `auth_type`,
  `region`: stripped in `merger.py` at `TenantInfo` finalization. This
  fires on a normal lookup, so it was the highest-priority residual.
- `dominant_issuer`: the cert `issuer_name` reaches `infra_graph`
  cluster output on a path separate from `build_cert_summary` (which
  round 2 stripped). Now stripped in `_build_graph`;
  `_clean_sans` additionally drops non-DNS SAN names via
  `is_safe_dns_name` so the graph layer self-protects.
- `cache show` (`provider_used` / `cached_at`) and `test-fingerprint`
  (evidence `raw_value`): markup-escaped (`rich.markup.escape`) and
  control-stripped; the delta panel strips its prior-snapshot
  `auth_type`.

`strip_control_chars` removes control bytes but keeps printable
metacharacters, which is sufficient for JSON (the encoder escapes
structure) and `rich` `Text.append` (no markup parse) but not for
markdown. `format_tenant_markdown` now also markdown-escapes the issuer
and display-name fields (`_markdown_escape`), closing link / code-span /
table / HTML injection in the markdown report.

### MCP and resource bounds (MED / LOW) - closed

- `chain_lookup` (the most expensive tool) now goes through the
  per-domain rate limiter, removing a request-amplification lever.
- `cluster_verification_tokens` caps and deduplicates its input (100
  distinct domains), matching the CLI batch path.
- `reload_data` no longer clears the rate limiter (which let a caller
  reset it between lookups); it still clears the result cache.
- Cumulative retry-sleep cap; `test_hypothesis` / `simulate_hardening`
  argument-length caps; `domain_report` prompt control-strip; chain BFS
  queue cap; batch-file byte / line bound.

### Intentionally not changed (rationale)

- **Shared async resolver** (`_default_resolver`): safe to share across
  concurrent lookups. It is constructed with no answer cache
  (dnspython defaults `cache=None`), so concurrent `resolve()` calls
  share no mutable answer state; the only shared field is the
  benign nameserver-rotation index. Documented in `dns.py`.
- **`raw_dns_records` accumulation**: already bounded by the DNS
  response size per query (a TCP DNS answer caps near 64 KB), across a
  fixed set of queries. A further per-type cap is low value.
- **`discover_fingerprint_candidates(skip_ct=True)` cache sharing**: a
  correctness nicety (a CT-less discover run can serve a cache hit to a
  later full-fidelity tool within the TTL). Deferred so a security
  release does not also change the cache-key contract; tracked for a
  follow-up.
- **Negative `--timeout` / `--cache-ttl`**: cosmetic robustness only
  (no crash, no security impact); `--depth` and `--concurrency` are
  already clamped.

Regression coverage lives in the per-module test files each fix
exercises (`test_validator.py`, `test_http.py`, `test_infra_graph.py`,
`test_formatter.py`, `test_server_agentic.py`, `test_bimi_vmc.py`) plus
the updated `reload_data` test.

---

## Closed: round-four audit (config loading, analysis, detector safety - v1.9.20)

A fourth pass ran four parallel reviews (data-file / config loading,
analysis modules, detector exception-safety, and a regression re-audit
of the v1.9.19 changes) plus surfaced a dependency advisory.

### Detector exception isolation (HIGH) - closed

The BIMI-port fix (v1.9.19) restored exception-safety for one detector,
but `_detect_services` gathered all ~17 detectors with a bare
`asyncio.gather` (no `return_exceptions`, no per-task wrap), and the
surface-classification pass did the same for its `_process` gather.
`asyncio.gather` propagates the first exception, which `DNSSource.lookup`
converts into a whole-source error - so any single detector raising on
crafted input still discarded all other DNS intelligence. This is the
generalization the round-three doc noted it had stopped short of.

Fix: each detector now runs through a local `_isolate` wrapper that logs
and swallows `Exception` (BaseException / cancellation still
propagates), so one detector's failure degrades gracefully and every
other detector's contribution to the shared ctx survives. The surface
`_process` gather is wrapped the same way. This removes the dependency
on every detector being individually exception-proof, which is how the
v1.9.18 regression happened.

### starlette PYSEC-2026-161 (MED) - closed, and why v1.9.19 did not publish

`starlette` 1.0.0 (transitive via `mcp`) gained advisory PYSEC-2026-161
(fixed in 1.0.1). It was published after v1.9.19's CI ran but before its
release pipeline ran, so the release `test` job's `pip-audit` failed and
v1.9.19's build / publish / GitHub-release jobs were skipped - the tag
exists but never reached PyPI. The lockfile upgrade to 1.0.1 clears it.
v1.9.20 is the published successor and is cumulative over v1.9.19.

### Uncapped TXT length into a user regex (MED) - closed

`_detect_subdomain_txt` ran an operator / ephemeral regex against an
attacker-controlled TXT value with no length bound (the one DNS path
that lacked one; `match_txt` and the substring paths were already
bounded). A crafted multi-KB TXT plus a greedy or catastrophic regex
amplified backtracking. Now capped at 4096 chars before `re.search`,
matching `match_txt`, and aligning with the threat-model doc's "length
caps on all DNS string values" claim.

### Quadratic clustering blowup (MED) - closed

`compute_shared_tokens` built a `k*(k-1)` peer cross-product per shared
token; the CLI batch path allows up to 10k domains, so one widely-shared
token (a managed-DNS provider record, or an attacker registering many
domains with one crafted token) could materialize ~100M objects. Tokens
shared by more than 200 domains are now skipped as noise, bounding the
work. The MCP equivalent was already capped at 100.

### ReDoS heuristic gaps (MED) - partially closed + documented

`_REDOS_RE` missed bounded-repetition blowups like `(a+){20}` and its
comment falsely claimed it caught `(a|a)+`. The heuristic now flags the
`{n}` form. It deliberately does NOT flag quantified alternation,
because safe `(foo|bar)+` is common in real fingerprints and
distinguishing it from dangerous overlapping `(a|a)+` needs analysis a
regex cannot do. Overlapping-alternation and nested-group ReDoS are
instead bounded by the input length caps (the TXT cap above and
`_MAX_TXT_MATCH_LENGTH`), which cap worst-case backtracking regardless
of pattern. A linear-time engine (google-re2) would remove the heuristic
but crosses the pure-Python dependency floor.

### Markdown / token sanitization completed (LOW-MED) - closed

The v1.9.19 markdown escape covered `display_name` and issuer names but
missed `auth_type`, `region`, `google_auth_type`, `google_idp_name`, and
the `insights` list - all attacker-influenced free text rendered into
the markdown report. All now go through `_markdown_escape`.
`google-site-verification` tokens are control-stripped at extraction
(they reach JSON / MCP output and clustering; JSON encoding contained
them, but stripping at ingestion keeps any future renderer safe).

### Intentionally not changed (rationale)

- **Priors-override `0.0` / `1.0` root prior**: a degenerate root prior
  pins a node, but this is plausibly an intended operator capability in
  `~/.recon/priors.yaml`, and is distinct from the likelihood `{0,1}`
  ban (which exists so one mis-fingerprint cannot pin a node). Left as a
  documented operator choice rather than removing the capability.
- **Catalog-size caps on the fingerprint / signal / posture file
  loaders**, the **`_RetryTransport` unused base pool**, the
  **over-1024-byte batch-line split** (cosmetic spurious error rows),
  and the **PyYAML alias-bomb**: all operator-trust-boundary or
  cosmetic; deferred.

Regression coverage: detector gather isolation in
`tests/test_sources/test_dns.py`, the cluster cap in
`tests/test_clustering.py`, `{n}` ReDoS rejection in
`tests/test_security.py`, and markdown escaping in
`tests/test_formatter.py`.

---

## Round-five audit (response parsing, async, bug-hunt - v1.9.21)

A fifth pass ran three reviews: attacker-controlled HTTP response
parsing, async / concurrency / resource lifecycle, and a correctness
bug-hunt with a regression re-audit of the v1.9.20 changes. The headline
result is a negative one worth recording: no new reachable vulnerability
or correctness bug was found. The items below are observability and
defense-in-depth hardening.

### Response parsing - confirmed safe

Every parser of an attacker-influenced response was traced to its sink.
`cse.<domain>` config JSON (google.py), `mta-sts.<domain>` text and the
BIMI VMC PEM (dns.py), and the crt.sh / CertSpotter JSON
(cert_providers.py) are all `isinstance`-guarded on every field, parse
timestamps inside try/except, length- or prefix-check every split / index,
bound post-parse expansion before the public caps, and run under either
the detector gather isolation or resolver `_safe_lookup`. The only XML
parse (Autodiscover) uses defusedxml. The 10 MB body cap bounds every
response. One reported "control bytes via GetUserRealm display_name"
concern was a false positive: merger.py already control-strips
`display_name` / `auth_type` / `region` before they reach `TenantInfo`
(the round-3 fix), so the terminal renderer receives stripped values.

### Async / concurrency - confirmed safe

The single-event-loop design holds: the rate-limiter check-then-set is
synchronous (atomic, no double-resolve race), the server-state methods
are all await-free (no TOCTOU), the surface semaphore releases on every
path, and the `_isolate` / `_process` / `_safe_lookup` wrappers catch
`Exception` so `CancelledError` still propagates. All HTTP clients are
context-managed and closed.

### Observability fix (v1.9.21) - closed

The v1.9.20 gather isolation logged a failed detector at debug level and
dropped its contribution silently. A regression breaking a detector for
all inputs would therefore ship undetected. Failed detectors are now
added to `degraded_sources` (`detector:<name>`) and logged at warning
level, and the detector list carries stable names instead of coroutine
introspection. This keeps the crafted-input resilience while making a
real regression visible in output.

### Defense-in-depth (v1.9.21) - closed

- Verbose source-detail table control-strips `region` and `error`
  (parity with the primary panel).
- Autodiscover federated-domain list is control-stripped and capped
  (`_MAX_AUTODISCOVER_DOMAINS`). It is not DNS-charset-restricted, to
  preserve legitimate entity-decoded values; the body and count caps
  bound it.
- CertSpotter `issuer` friendly_name / name is `isinstance(str)`-checked
  before use.

### Deferred (operator-trust-boundary or cosmetic)

The `_RetryTransport` unused base transport pool (leaks nothing - the
pool never opens a socket); synchronous YAML parse on the event loop
during `reload_data` (rare, admin-triggered; `to_thread` is the eventual
fix); and the over-1024-byte batch-line split (cosmetic extra error
rows). The latent fingerprints lock-on-event-loop note applies only if
loads are ever moved to `asyncio.to_thread`.

---

## Closed: round-six audit (output-sink control stripping - v1.9.81)

A sixth pass re-traced every attacker-controlled parse boundary to its
output sink. The round-three fix control-strips `display_name` /
`auth_type` / `region` at the merger before they reach `TenantInfo`, and
round five confirmed the CSE / MTA-STS / VMC / CT parsers are
`isinstance`-guarded at parse time. But two source-derived strings reach
the live terminal panel (rendered via rich `Text.append`, which does not
strip ESC) without passing through that merger scrub. Both are new: not
previously listed, and not covered by the round-three field set.

### Service strings carrying control bytes (MED) - closed

`GoogleSource` builds a service entry `f"CSE Key Manager: {host}"` where
`host` is the `urlparse(...).hostname` of the `cse.<domain>` config's
`discovery_uri` (`sources/google.py`). `urlparse` preserves control bytes
in the host, and the `services` set was never control-stripped, so a
domain owner who controls `cse.<domain>` could land an ANSI/newline
payload on the operator's terminal (and in the un-escaped markdown service
list). Closed by scrubbing the whole `services` set through
`strip_control_chars` at the merger finalization boundary
(`merger.py`), so the score / insight logic and every renderer see clean
values regardless of which source produced the string.

### DMARC `p=` value carrying control bytes (MED) - closed

`_apply_dmarc` (`sources/dns.py`) stored the `p=` token as
`cleaned[2:].strip()` after a `.lower()`, which does not remove control
bytes; unlike `mta_sts_mode` (allowlist-validated) and `dmarc_pct`
(range-checked), the policy value was unvalidated. A record
`v=DMARC1; p=none<ESC>[31m...` reached the panel's email-summary line
verbatim. Closed by control-stripping `dmarc_policy` at the same merger
boundary. `google_idp_name` (derived from a redirect host; httpx already
rejects control bytes in redirect hosts, so this is defense in depth) is
folded into the same scrub.

The fix is one consistent place: `merge_results` now scrubs `services`,
`dmarc_policy`, and `google_idp_name` alongside the round-three fields, so
any future source that emits a control-bearing service string or policy is
covered without a per-source change. Pinned by
`tests/test_ingestion_sanitization.py` (control bytes stripped; clean
values unchanged).

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
