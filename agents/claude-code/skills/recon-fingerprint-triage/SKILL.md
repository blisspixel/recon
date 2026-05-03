---
name: recon-fingerprint-triage
description: Triage fingerprint-discovery candidates from recon's CNAME-chain classifier. Reads either a single `recon <domain> --json --include-unclassified` payload or a `candidates.json` produced by `validation/triage_candidates.py`, then proposes new `cname_target` fingerprint stanzas for `surface.yaml`. Use when the user asks to "find new fingerprints", "what SaaS are we missing", "discover unclassified CNAME targets", or wants to extend recon's catalog from a fresh scan or validation corpus run.
argument-hint: <domain | path/to/candidates.json>
allowed-tools: Bash(recon:*), Read, Edit, Write
---

# recon-fingerprint-triage

The companion skill to `recon`. The base `recon` skill gives you what an apex
*has*; this skill gives you the long tail of what an apex's *subdomains* point
at — and proposes catalog additions when those CNAME chains hit something
recon doesn't yet recognize.

## When to use this

The user wants to grow the fingerprint catalog by mining real DNS data:

- "Find new fingerprints from stripe.com"
- "What SaaS does this company use that we don't fingerprint?"
- "Triage gaps from my latest validation run"
- "Is there a fingerprint candidate in this CNAME chain?"
- "Help me add the missing fingerprint for example.com"

If they just want to look up a domain (not extend the catalog), use the base
`recon` skill instead. This skill is specifically for the discovery loop.

## Inputs you accept

The skill works at three different scales — pick whichever the user asks for:

**A. Single domain (incidental discovery during normal use):**
```
Run recon on <domain> and show me anything you'd want to fingerprint
```
You shell out: `recon <domain> --json --include-unclassified`. Read the
`unclassified_cname_chains` array from the JSON. Each entry is a candidate.

**B. A `gaps.json` from a corpus run:**
```
Triage gaps.json
```
The user has already run `validation/find_gaps.py` against a corpus. The file
contains pre-bucketed `{suffix, count, samples}` entries.

**C. A `candidates.json` from `validation/triage_candidates.py`:**
```
Triage candidates.json
```
Same shape as (B), but pre-filtered: already-fingerprinted patterns dropped,
intra-org chains dropped, low-count noise dropped. The cleanest input —
every entry is worth your judgment.

## Triage rubric

For each candidate (single chain or suffix bucket), classify into one of
five outcomes:

1. **Real third-party SaaS** — a recognizable product (Auth0, HubSpot, Sentry,
   etc.). The terminal hostname or its zone identifies the vendor. **Action:**
   propose a `cname_target` fingerprint stanza (see schema below).

2. **Generic infrastructure / CDN / cloud** — Akamai, Fastly, CloudFront, or
   similar. **Action:** if the pattern isn't already in `surface.yaml`,
   propose an entry with `tier: infrastructure`. Otherwise note "already
   covered" and skip.

3. **Intra-org self-reference** — the chain stays inside the organization's
   own brand zone (different TLD or sibling brand). Common for big enterprises
   (chase → gslbjpmchase, bbc → bbc.co.uk → eglb.bbc.co.uk).
   **Action:** drop. Don't fingerprint internal CDN patterns. Note this in
   your triage summary so the user knows it was intentionally skipped.

4. **Niche or one-off** — count is 1 across the corpus, hostname looks
   bespoke (e.g., a single customer's vanity vendor relationship).
   **Action:** record as a "see-once" candidate but do NOT propose a
   fingerprint. The threshold for inclusion is "would another user ever hit
   this pattern?" — niche one-offs fail that test.

5. **Unclear** — can't tell from the hostname alone whether it's SaaS or
   private. **Action:** flag for the user with the chain and a question. Do
   NOT guess and propose a fingerprint without confirmation.

## YAML schema for new entries

A candidate that survives triage as "real SaaS" or "infrastructure" produces
a stanza like:

```yaml
- name: <Display Name>
  slug: <lowercase-kebab>
  category: <Email & Communication | Identity | Infrastructure | Security |
            Productivity & Collaboration | Marketing | Business Apps |
            Commerce | AI & Generative>
  confidence: high
  detections:
  - type: cname_target
    pattern: <minimal substring that uniquely identifies the service>
    tier: <application | infrastructure>
    description: <short, factual; reference if available>
```

Critical rules for the pattern:

- **Be specific.** `amazonaws.com` is too broad. `elb.amazonaws.com`,
  `awsglobalaccelerator.com`, `awsapprunner.com` are right. The pattern is a
  case-insensitive substring match against every CNAME hop, so an
  over-broad pattern will fire on anything in that zone.
- **Prefer the service-specific subzone.** `customer.io` and `bnc.lt` (Branch)
  are good — the whole domain is owned by the SaaS. For multi-tenant SaaS
  zones, drop the customer prefix: `myshopify.com` is correct (every Shopify
  store is `<store>.myshopify.com`); `gymshark.myshopify.com` would be wrong.
- **Tier classification.** Application = the SaaS or product (Auth0, Shopify,
  Zendesk). Infrastructure = the CDN, load balancer, or edge layer (Fastly,
  CloudFront, Cloudflare). When a chain matches both, application wins as the
  primary attribution.

## When the slug already exists

If the candidate maps to an existing slug (e.g., `customer.io` extends an
existing `customerio` entry that was added via TXT detection only), produce
the YAML stanza using the **same name and slug** as the existing entry. The
validator's same-slug-same-name check allows extending an apex fingerprint
with new `cname_target` rules in `surface.yaml`. The validator complains
when same-slug entries have different display names, so:

- Look up the canonical name in `recon_tool/data/fingerprints/*.yaml` first
  (grep for `slug: <slug>`).
- Use that exact name in your new stanza.

## Category bucketing

The category determines which `Services` sub-line the slug appears under in
the panel. Mappings live in `recon_tool/formatter.py:_CATEGORY_BY_SLUG`. If
you add a new slug, also propose the entry there in your output:

```python
"<new-slug>": "<Email | Identity | Cloud | Security | AI | Collaboration | Business Apps>",
```

If you don't add a mapping, the slug falls into "Business Apps" by default,
which is sometimes wrong (CDN-as-a-service slugs should be Cloud, not
Business Apps).

## Output format

Produce a single response in this shape:

1. **Summary** — one line per candidate with its triage verdict.
2. **Proposed surface.yaml additions** — full YAML stanzas, one per fingerprint.
3. **Proposed formatter category mappings** — Python dict entries.
4. **Skipped** — list of candidates dropped with the reason (intra-org,
   niche one-off, already covered, unclear).
5. **Verification command** — the exact `recon <domain>` invocation the user
   should run to confirm the new fingerprint fires correctly.

Keep the response action-ready. The user should be able to apply your YAML
diff, run your verification command, and confirm uplift in one pass.

## Worked example

User invokes:
```
Triage runs-private/2026-05-02/candidates.json
```

You read the file. Suppose it contains:
```json
[
  {"suffix": "stspg-customer.com", "count": 16, "samples": [...status pages...]},
  {"suffix": "rootly.com", "count": 1, "samples": [{"subdomain": "status.example.com", ...}]},
  {"suffix": "gslb.example.com", "count": 8, "samples": [...same domain...]}
]
```

Your response:

> **Summary**
> - `stspg-customer.com` (16x): real SaaS — Atlassian Statuspage hosted endpoint. Propose extending the existing `statuspage` slug.
> - `rootly.com` (1x): real SaaS but one-off in this corpus — flag for revisit, do not fingerprint yet.
> - `gslb.example.com` (8x): intra-org self-reference (same brand) — skip.
>
> **Proposed surface.yaml additions:**
> ```yaml
> - name: Statuspage (Atlassian)
>   slug: statuspage
>   category: Productivity & Collaboration
>   confidence: high
>   detections:
>   - type: cname_target
>     pattern: stspg-customer.com
>     tier: application
>     description: Atlassian Statuspage customer CNAME endpoint
> ```
>
> **Proposed formatter category mapping:** none — `statuspage` already maps to Collaboration.
>
> **Skipped:**
> - `rootly.com` — niche, count 1
> - `gslb.example.com` — intra-org
>
> **Verification:** `recon cache clear --all && recon <one-of-the-status-page-domains> --full` should now show the subdomain in the External surface section attributed to "Statuspage (Atlassian)".

## What this skill does NOT do

- Active probing of any kind. The skill consumes recon's existing JSON
  output; it never makes its own DNS queries.
- Speculative fingerprinting on hostnames you can't recognize. Better to flag
  as "unclear" and ask the user than to ship a guess.
- Pattern broadening. Always prefer the most specific pattern that captures
  the service. Pattern-tightening is harder than pattern-expanding once
  shipped.
- Apex-side fingerprints. This skill only writes `cname_target` rules. TXT,
  MX, SPF, etc. are out of scope — use the broader contributor flow for those.

## Relationship to the base `recon` skill

| Goal | Use |
|---|---|
| Look up a domain | `recon` skill |
| Find candidates for new fingerprints | this skill |
| Verify a new fingerprint fires | `recon` skill (after applying YAML diff) |

You can chain both in one conversation: run base `recon` to triage one
target, then this skill to mine the unclassified chains and propose
catalog growth.
