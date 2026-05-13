# Contributing

Thanks for your interest in contributing to recon. This doc answers:

- [What kinds of contributions we're looking for](#what-were-looking-for)
- [What's out of scope](#whats-out-of-scope)
- [Local customization vs upstream contribution](#local-customization-vs-upstream-contribution)
- [How to contribute a fingerprint](#adding-fingerprints)
- [How to contribute a signal or profile](#adding-signals-and-profiles)
- [How to contribute code](#code-changes)
- [How to report a bug or suggest an idea](#bug-reports-and-ideas)

## Quick Start

```bash
git clone https://github.com/blisspixel/recon.git
cd recon
uv sync --extra dev                    # or: pip install -e ".[dev]"
pre-commit install                     # activate pre-commit hooks
uv run pytest tests/                   # or: pytest tests/
```

---

## What we're looking for

recon is a **narrow tool** that does one thing well: passive, zero-creds
domain intelligence. Contributions that tighten what the tool already does
are always welcome:

| Contribution type | Bar | Examples |
|---|---|---|
| **New fingerprints** | Must use public DNS/CT only. Specific pattern, not generic substring. Tested against a real customer domain. | "Add Statsig TXT verification", "Add Workspace ONE CNAME" |
| **Refined fingerprints** | `match_mode: all` to eliminate false positives, improved regex, broader selector coverage. | Converting ambiguous slug to a chained pattern |
| **New signals** | Must derive from existing evidence. Hedged language. | "AI tooling indicators observed alongside identity-provider signals" |
| **New profiles** | Must reweight existing observations; cannot invent new ones. | "Retail / e-commerce" profile |
| **Bug reports** | Reproducible + output of `recon <domain> --json --explain`. | Wrong provider classification, insight wording, display glitch |
| **Accuracy reports** | Domain you know ground truth for, plus what recon got wrong. | "Our org uses M365 primary; recon says Exchange on-prem" (omit real names in public reports) |
| **Documentation fixes** | Typos, clarifications, better examples. | README, CONTRIBUTING, docs/* |
| **Performance improvements** | With before/after measurement. Hot paths: `detect_provider`, `_curate_insights`, DNS query batching. | Reducing average lookup time, eliminating redundant DNS queries |
| **Test additions** | Sparse-data fixtures, adversarial inputs, corner cases. | Domain with zero MX + no tenant, IDN / punycode, wildcard DNS |

The **engine stays lean; the data grows**. Most contributions should be
YAML additions or refinements — that's the healthy scaling path for the
tool. Code changes earn their place against the post-1.0 ethos: correctness,
reliability, explainability, composability, then new features, in that
order.

---

## What's out of scope

These are **intentional rejections**, not gaps waiting to be filled. Don't
spend effort on PRs that will be closed:

### Violates invariants (hard no)

- **Active scanning of any kind.** No HTTP probes against target domains
  (even "light"), no port scans, no TLS handshakes, no brute-forcing.
- **Anything requiring credentials or API keys.** No OAuth, no PAT, no
  paid APIs (SecurityTrails, Censys, Shodan, etc.).
- **Aggregated local database.** Per-domain JSON files only. No SQLite/DuckDB
  store.
- **Bundled ML models, embeddings, or large data files.** ASN / GeoIP /
  fingerprint embeddings are all out.
- **Plugin systems that run user code.** YAML-only extensibility.

### Not this tool (soft rejections)

- HTML / PDF output, web dashboard, TUI, `recon serve`, interactive REPL
- STIX / MISP / Maltego / Excel / SBOM / Sigstore exports
- Scheduled / daemon mode with alerts
- Generic subdomain brute-forcing (DNS wordlist attacks)
- People-search / email-harvesting OSINT
- Docker image, Homebrew tap, PyInstaller single-binary

If you want any of these, **pipe `--json` into the right tool**. recon is a
CLI + a local-stdio MCP server; the integration surface is JSON, pipe it
wherever you need.

If unsure whether your idea fits, open an **idea** issue (template below)
and ask before writing code.

---

## Local customization vs upstream contribution

recon supports both.

**Local customization** (for your own use, never pushed):
- `~/.recon/fingerprints.yaml` — custom fingerprints (additive only; cannot override built-ins)
- `~/.recon/signals.yaml` — custom signal rules
- `~/.recon/profiles/*.yaml` — custom posture profiles
- `RECON_CONFIG_DIR` — override the default `~/.recon` location

Anything that's specific to your organization, your vendors, or your
internal naming should stay local.

**Upstream contribution** (shared with everyone via a PR):
- Detections that apply to at least one publicly-known service
- At least one real customer domain you can point to as evidence
  (kept locally and described in the PR body — not committed)
- General-purpose (not a specific org's internal pattern)

---

## Fictional-example policy

**Never commit real-company apex domains as examples, targets, test
corpora, or regression fixtures.** Use Microsoft's fictional-company
names — `contoso.com`, `northwindtraders.com`, `fabrikam.com`,
`tailspintoys.com`, `wingtiptoys.com`, `adventure-works.com`,
`wideworldimporters.com` — or IETF reserved placeholders
(`example.com`, `example.org`, `example.net`).

This applies to:

- README, CHANGELOG, and docs examples
- YAML fingerprint / signal / profile files
- Test fixtures, golden files, snapshots, and corpus files
- Issue / PR templates and comments
- Code comments and docstrings

It does **not** apply to:

- Vendor / product names recon detects as part of a tech stack
  (Cloudflare, Okta, Microsoft 365, Google Workspace, etc.) —
  these are detection classes, not targeting examples.
- Upstream service hostnames recon itself queries
  (`login.microsoftonline.com`, `crt.sh`, `api.certspotter.com`,
  `dns.google`, etc.).

Accuracy reports and live-validation work use real apexes locally;
that's why `/validation/` is gitignored except for the runner script,
the fingerprint audit helper, a fictional example corpus, and a README.
If you're writing a bug report that needs a real domain to reproduce, file
it privately or describe the behavior in terms of the fictional examples
whenever the real name isn't load-bearing. The rationale is simple: no
upside, accumulating reputational and legal downside over the lifetime of
the repository.

---

## Adding fingerprints

The most common contribution. From v1.1 onward, fingerprints live under
`recon_tool/data/fingerprints/` — one YAML file per category.

### 1. Find the right file

```bash
recon fingerprints list --category ai       # where do AI tools live?
recon fingerprints show openai              # what does the existing pattern look like?
```

Current layout:

```
recon_tool/data/fingerprints/
├── ai.yaml             AI / LLM providers, agent frameworks
├── email.yaml          Email providers, gateways, DMARC / DKIM tooling
├── security.yaml       EDR, SIEM, IdP, zero-trust access
├── infrastructure.yaml Cloud, CDN, DNS, CAs, CI/CD
├── productivity.yaml   Suite tools, helpdesk, HR
├── crm-marketing.yaml  CRM, sales intel, ad platforms
├── data-analytics.yaml Warehouses, BI, observability
└── verticals.yaml      Education, nonprofit, payments
```

Pick the file that matches your service's primary category. If nothing
fits, open an issue before adding a new category file — the split is
intentionally coarse.

### 2. Add your entry

Use the scaffolding command when possible:

```bash
recon fingerprints new service-slug
```

It walks through the stable schema and specificity checks before emitting YAML.

```yaml
- name: Service Name
  slug: service-slug          # lowercase, unique across ALL files
  category: Category Name     # use an existing category if possible
  confidence: high             # high, medium, or low
  detections:
    - type: txt                # txt, spf, mx, ns, cname, subdomain_txt, caa, srv, dmarc_rua
      pattern: "^service-domain-verification="
      description: What this record means
      reference: https://vendor.example/docs/domain-verification
```

`description` should explain the observable record. `reference` is optional,
but preferred when public vendor documentation exists. Do not add fields that
are not in the stable data-file schema unless a separate schema change has
already been accepted.

### 3. Validate locally before opening a PR

```bash
recon fingerprints check                    # validates the built-in catalog
recon fingerprints check path/to/custom.yaml  # validate a candidate file
```

The `check` command runs the same validation recon uses at runtime —
regex safety (ReDoS heuristic), required fields, known detection types,
weight range (0.0–1.0), `match_mode` value — **plus** a cross-file
duplicate-slug check. Exits 0 on success, 1 on failure with per-entry
error messages.

Under the hood this uses the packaged `recon_tool.fingerprint_validator`
module, so it works from installed wheels as well as source checkouts.
Contributors who prefer invoking the wrapper script directly can still run
`python scripts/validate_fingerprint.py <path>`.

### Chained patterns (`match_mode: all`)

For high-confidence attribution where a single record could be a false
positive, use `match_mode: all` — the fingerprint only fires when every
listed detection matches. See [docs/fingerprints.md](docs/fingerprints.md#chained-patterns-match_mode-all) for details.

For multi-detection changes, run:

```bash
python -m validation.audit_fingerprints
```

The audit is advisory. Use it to document whether the entry should remain
`any`, move to `all`, or be tightened before changing behavior.

### Fingerprint PR checklist

- [ ] Validates locally with `recon fingerprints check`
- [ ] `recon fingerprints show <slug>` displays your new entry after load
- [ ] Slug does not collide with an existing one (`recon fingerprints list | grep <slug>`)
- [ ] At least one detection pattern uses a service-specific token (not a generic substring)
- [ ] Detection metadata includes `description`, plus `reference` when public vendor docs exist
- [ ] Tested against a real public domain you know uses the service
- [ ] The service's DNS footprint is documented or publicly-observable (not leaked from a customer engagement)
- [ ] Multi-detection entries include a `match_mode` rationale from the audit output or PR notes
- [ ] Common legitimate false-negative cases are captured in the PR body, or in `docs/weak-areas.md` when broadly useful
- [ ] `pytest tests/` passes — property tests must still hold on the sparse-data corpus
- [ ] If the service could trip false positives on domains that merely *visited* the vendor's marketing site, used `match_mode: all`

### Vendor-doc-sourced `cname_target` rules

`cname_target` rules in `recon_tool/data/fingerprints/surface.yaml`
can be added two ways:

1. **Corpus-observed.** The default historical path: a private-corpus
   scan surfaces an unclassified CNAME terminus, the
   `/recon-fingerprint-triage` skill proposes a slug, and the rule
   ships in a release-window catalog-growth pass.
2. **Vendor-doc-sourced** *(v1.9.3.9+)*. A cloud vendor (GCP, AWS,
   Azure, Oracle, IBM, Alibaba, SSE/SASE platforms, PaaS providers,
   etc.) documents customer-facing custom-domain CNAME targets in
   their own product docs. Reading those docs and seeding fingerprints
   from them closes coverage blindspots BEFORE a customer of that
   vendor lands in our private corpus — corpus-observed alone has a
   built-in bias toward the segments our corpus already represents.

Both paths are encouraged. The **`reference`** field on each
detection makes the source explicit:

- Vendor-doc-sourced: `reference` MUST point at the canonical vendor
  documentation URL that names the CNAME pattern (e.g.
  `https://firebase.google.com/docs/hosting/custom-domain` for
  Firebase Hosting). The PR description should quote the relevant
  doc excerpt so review can verify the pattern is documented as
  stable, not a transient internal endpoint.
- Corpus-observed: `reference` SHOULD point at the vendor's
  marketing page or main docs index, and the PR description should
  cite the private-corpus delta count (e.g. "fired on 23/4270
  domains in the v1.9.2-pre-release scan").

Either way, `reference` exists so a future maintainer can re-verify
the pattern. A rule shipped without a `reference` is allowed but
will be flagged in the metadata-richness gate (v1.9.7+).

Use the fingerprint PR template — GitHub surfaces it automatically.

---

## Adding signals and profiles

> **Heads up — engine changes go through a design doc.** Fingerprints
> are data; contributors can iterate on them freely. The signal,
> fusion, and absence engines are inference code — bad changes there
> affect every domain recon analyses, not just the one you tested.
> Before PRing a change to `recon_tool/signals.py`, `merger.py`,
> `absence.py`, `fusion.py`, or the two-pass evaluator, please open
> an issue with:
>
> 1. What inference pattern you want to add or change.
> 2. Which domains in the validation corpus would fire differently.
> 3. How you'd guard against false positives on sparse-signal domains.
>
> Data-only contributions (new signals in `signals.yaml` that reuse
> the existing engine) don't need this — they follow the fingerprint
> PR workflow.

### Signals

Custom signal rules derive insights from fingerprint matches. Go in
`~/.recon/signals.yaml` (local) or `recon_tool/data/signals.yaml`
(upstream):

```yaml
signals:
  - name: My Custom Signal
    category: Custom
    confidence: medium
    description: Hedged explanation of what this signal suggests
    requires:
      any: [slug-a, slug-b, slug-c]    # fingerprint slugs to match
    min_matches: 2                       # how many must be present
```

Signals must use **hedged language** in their `description` (observed,
likely, fits a pattern) unless the evidence density genuinely justifies a
firmer claim. Sparse-data targets should never see confident verdicts.

See [docs/signals.md](docs/signals.md) for the full schema, including
`metadata` conditions, `contradicts`, `requires_signals`, and
`positive_when_absent`.

### Profiles

Profiles reweight existing observations for a specific audience (fintech,
healthcare, higher-ed, etc.). Go in `~/.recon/profiles/{name}.yaml` (local)
or `recon_tool/data/profiles/{name}.yaml` (upstream):

```yaml
name: retail
description: E-commerce / retail posture lens
category_boost:
  email: 1.5          # email security matters more for retail
  saas_footprint: 1.2
signal_boost:
  "DMARC Governance Investment": 1.5
focus_categories: [email, identity, consistency]
```

Profiles are **additive only** — cannot introduce new observations, only
reweight existing ones, and cannot create false confidence (caps at "high"
salience).

---

## Code changes

- Run `pre-commit run --all-files` or `ruff check recon_tool/` and `pyright recon_tool/` before submitting.
- Run `pytest tests/` — coverage must stay above 80%.
- Integration tests (`pytest -m integration`) require network access and are skipped by default.
- Keep PRs focused — one concern per PR.

### Post-1.0 bar for code changes

From 1.0 onward, `docs/stability.md` defines the stable public surface.
Any change that touches a stable surface needs:

- A clear reason the change can't be done as data-only (YAML).
- An explanation of backward compatibility (or a deprecation plan if the
  change is breaking — which requires a major version bump).
- Tests covering both existing consumers and the new behavior.

The bar is deliberately high. Most "I want recon to do X" ideas can be
solved with a new fingerprint, signal, or profile — not new code.

---

## CPT-change discipline (v1.9.6+)

The v1.9 Bayesian layer (`recon_tool/data/bayesian_network.yaml`) is a
**data file with semantic content**, not a free parameter surface to
tune against the corpus. Every CPT entry encodes a claim about how
evidence should move the posterior. Changing a number changes a
claim.

The discipline is one rule: **corpus runs are mirrors, not fitters.**
When the corpus disagrees with the network, the first question is
*is this node asking the right question?* — not *what number gets
the disagreement number down?* Only after the topology is clean do
CPT numbers get re-examined, and only with explicit reasoning
written in the YAML alongside the change.

### When you are about to change a CPT entry

Work the decision through in this order before editing the YAML:

1. **Is the disagreement reproducible?** Re-run the calibration
   against the current corpus. Single-domain anomalies are noise;
   patterns across ≥ 3 domains warrant continuing.
2. **Does the bound evidence's likelihood ratio match the binding's
   semantic claim?** A signal with LR 2.8 says "observing this
   roughly triples our odds of the node being present." If that's
   wrong as a *semantic* statement about what the signal actually
   indicates, the binding is mis-modeled — and the fix is either
   removing the binding or replacing it, not retuning the number to
   game the criterion.
3. **Is the prior consistent with the target population?** recon
   predicts enterprise apex domains. If a prior reflects the
   internet-at-large base rate when the network's input population
   is enterprise apexes, the prior is structurally wrong. Adjusting
   it is a CPT change *with a target-population concept comment*,
   not parameter-tuning.
4. **Is the topology asking the right question?** If a node's
   description doesn't match the claim its evidence bindings
   support, the topology is wrong. The answer is structural
   surgery, not a number adjustment. See the v1.9.3 worked
   example below.

### Worked example 1: v1.9.3 surgery on `email_security_strong`

**The temptation.** The v1.9.0 corpus showed 52.6% deterministic-
pipeline agreement on the `email_security_strong` node — much lower
than the other nodes (90%+). The corpus-fitting reflex was to
lower `P(strong | M365=present, gateway=present)` from 0.75 to
0.55 to "match the corpus rate of 55%."

**The pause.** Before tuning, we asked *what does
`email_security_strong` claim?* The description and the parent CPT
both said "the domain runs a modern, managed mail provider." But
the evidence bindings tested DMARC, DKIM, SPF, and MTA-STS — that's
*policy enforcement*, not *provider presence*. A weak-policy M365
tenant and a strong-policy on-prem domain were being scored
against the same node. No CPT tuning could reconcile them because
the node was entangling two distinct claims.

**The fix.** Topology surgery — `email_security_strong` was split
into `email_security_modern_provider` (CPT-driven, provider
presence) and `email_security_policy_enforcing` (evidence-driven,
policy enforcement). Both claims became first-class. Operators
who want the conjunction can compute it downstream from the two
posteriors.

**The lesson.** A 52.6%-agreement number can come from a node
that's correct on average across two populations and wrong on
both individually. Tuning the number averages harder; topology
surgery decomposes the claim.

### Worked example 2: v1.9.6 surgery on `email_security_policy_enforcing`

**The temptation.** The v1.9.5 stability report
(`validation/v1.9.5-stability.md`) found that 10 of 129
det-positive-HIGH non-sparse observations had posterior ≤ 0.5,
failing criterion (b1). Every one of those 10 cases was
`evidence_used = ('signal:dkim_present',)` alone. With
`dkim_present` likelihood `[0.85, 0.30]` and prior 0.25, the
posterior came out to ≈ 0.486 — just under 0.5. The corpus-fitting
reflex was to lower the likelihood for the absent case from 0.30
to 0.20, lifting the dkim-only posterior to 0.59. Criterion passes.

**The pause.** Before tuning, we asked *what does `dkim_present`
mean as evidence for `email_security_policy_enforcing`?* The node
claims "observable email-authentication policy is enforcing"
(DMARC reject/quarantine + DKIM + strict SPF + optional MTA-STS
enforce). DKIM publication is widespread — domains publish DKIM
for deliverability whether or not they enforce DMARC. A 2.83×
likelihood ratio (the current 0.85/0.30) says "observing DKIM
roughly triples our odds of enforcement." Empirically, that's not
true: DKIM is published by a large fraction of non-enforcing
domains as well.

**The fix.** Remove `dkim_present` as an evidence binding for
`email_security_policy_enforcing`. The node's remaining four
bindings (`dmarc_reject`, `dmarc_quarantine`, `mta_sts_enforce`,
`spf_strict`) all speak directly to enforcement. The dkim-only
domains correctly move to `evidence_used = ()` → sparse=true,
joining (b2)'s det-silent-correctly-hedged set.

**The lesson.** Tuning a likelihood to lift a posterior over a
threshold is fitting the criterion, not improving the model.
Removing a binding that doesn't speak to the node's claim
improves the model.

### Anti-pattern catalog

The following PR change descriptions should be rejected by
reviewers without further evidence. Each is a real corpus-fitting
reflex worth catching in the review:

1. **"Lowered P(X | Y) from 0.75 to 0.55 to match the corpus rate."**
   Rejection prompt: "What conceptual claim does this change
   reflect? What did you learn about Y when you saw the
   disagreement?" If the answer is "the corpus disagreed and 0.55
   makes it agree," the change is corpus-fitting, not
   model-improvement.
2. **"Adjusted likelihood to clear ECE threshold."** Rejection
   prompt: "Which binding's *semantic* claim changed? If none,
   why is the new number more accurate than the old one?"
3. **"Added priors override YAML to compensate for posterior
   miscalibration."** The priors-override mechanism
   (`~/.recon/priors.yaml`) is for operator base-rate adjustments
   — *I'm only looking at financial-sector domains, so raise the
   m365 prior*. It is not a place to silently fix engine
   miscalibration without changing the shipped CPT. If the
   shipped prior is wrong, change the shipped prior with a
   concept comment.
4. **"Wrote a script to auto-tune CPTs against corpus statistics."**
   Crosses the no-learned-weights invariant. Iteration with a
   human in the loop is the right cycle; automation of the
   number-fitting step is the wrong cycle. Reject.

### The concept-comment requirement

Every CPT or prior change in `bayesian_network.yaml` must carry a
YAML comment, immediately above the change, that:

1. Cites the corpus disagreement or design observation that
   surfaced the question.
2. States the conceptual claim the new number reflects.
3. Notes any prior alternatives considered and why they were
   rejected.

The comment is for future contributors who will look at the
number and wonder why it is what it is. "0.40 because corpus rate"
is a corpus-statistic comment, not a concept comment — reject. "0.40
reflects the enterprise-apex target population's published DMARC-
enforcement rate per [reference]; 0.25 was the internet-at-large
base rate and is structurally wrong for recon's input distribution"
is a concept comment.

### What this discipline does NOT prohibit

* **Iterating in a human-in-the-loop cycle.** "Look at corpus →
  rewrite mental model → write new CPTs" with a human deciding
  what to change is the right cycle. The corpus is data; the
  human is the fitter.
* **Adjusting numbers when the *semantic* claim has changed.** If
  a binding's likelihood ratio changes because empirical
  evidence about the binding's meaning has changed — not just
  because the corpus disagrees — that's a model improvement.
* **Splitting, redefining, or removing nodes.** Topology change
  at bridge milestones (v1.9.3 surgery, v1.9.5 dispositions,
  v1.9.6 binding removal) is explicitly authorized when the
  network's structure is asking the wrong question.

### Enforcement

The PR template (`.github/pull_request_template.md`) carries a
non-blocking checkbox prompting reviewers to confirm a YAML
concept comment is present for any CPT change. The checkbox is
the prompt, not the gate — reviewer judgement is the gate. There
is intentionally no CI test enforcing this: a CI test would game
the comment requirement (it could pass on a comment that doesn't
actually question the concept). The discipline is a review
practice, not an automated check.

---

## Bug reports and ideas

Three issue templates:

- **Fingerprint request** — you want recon to detect a service it
  currently misses.
- **Bug report** — recon got something wrong, crashed, or behaved
  unexpectedly.
- **Idea** — you want to propose something larger (new flag, new MCP
  tool, new CLI command, etc.).

For ideas, the template asks you to confirm the proposal fits the
project invariants (passive, zero-creds, no aggregated DB, no active
scanning). Ideas that don't fit will be politely closed with a pointer
to `--json` + pipe to the right tool.

---

## Pull request etiquette

- Keep PRs focused — one feature or fix per PR.
- Fingerprint-only PRs are welcome and easy to review.
- Include a brief description of what you changed and why.
- Reference the issue number if there is one.
- Be patient — this is a small project with a single maintainer.
