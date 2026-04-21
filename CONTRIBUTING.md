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
| **New signals** | Must derive from existing evidence. Hedged language. | "AI Governance Gap" signal from AI slugs + absence of DLP fingerprints |
| **New profiles** | Must reweight existing observations; cannot invent new ones. | "Retail / e-commerce" profile |
| **Bug reports** | Reproducible + output of `recon <domain> --json --explain`. | Wrong provider classification, insight wording, display glitch |
| **Accuracy reports** | Domain you know ground truth for, plus what recon got wrong. | "Softchoice uses M365 primary; recon says Exchange on-prem" |
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
- General-purpose (not a specific org's internal pattern)

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

```yaml
- name: Service Name
  slug: service-slug          # lowercase, unique across ALL files
  category: Category Name     # use an existing category if possible
  confidence: high             # high, medium, or low
  detections:
    - type: txt                # txt, spf, mx, ns, cname, subdomain_txt, caa, srv, dmarc_rua
      pattern: "^service-domain-verification="
      description: What this record means
```

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

Under the hood this wraps `scripts/validate_fingerprint.py`; contributors
who prefer invoking the script directly can still do so.

### Chained patterns (`match_mode: all`)

For high-confidence attribution where a single record could be a false
positive, use `match_mode: all` — the fingerprint only fires when every
listed detection matches. See [docs/fingerprints.md](docs/fingerprints.md#chained-patterns-match_mode-all) for details.

### Fingerprint PR checklist

- [ ] Validates locally with `recon fingerprints check`
- [ ] `recon fingerprints show <slug>` displays your new entry after load
- [ ] Slug does not collide with an existing one (`recon fingerprints list | grep <slug>`)
- [ ] At least one detection pattern uses a service-specific token (not a generic substring)
- [ ] Tested against a real public domain you know uses the service
- [ ] The service's DNS footprint is documented or publicly-observable (not leaked from a customer engagement)
- [ ] `pytest tests/` passes — property tests must still hold on the sparse-data corpus
- [ ] If the service could trip false positives on domains that merely *visited* the vendor's marketing site, used `match_mode: all`

Use the fingerprint PR template — GitHub surfaces it automatically.

---

## Adding signals and profiles

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
