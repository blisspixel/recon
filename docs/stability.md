# Stability Policy

As of v1.0, recon commits to the public surfaces listed below. **Stable**
surfaces will not break between patch or minor releases — breaking them
requires a major version bump and a deprecation window. **Experimental**
surfaces may evolve in minor releases without a major bump.

For the JSON output contract in full field-by-field detail, see
[`schema.md`](schema.md). For the release process, see
[`release-process.md`](release-process.md).

---

## Stable surfaces

### CLI commands

| Command | Stability | Notes |
|---|---|---|
| `recon <domain>` / `recon lookup <domain>` | Stable | Default panel layout (section order, field names). |
| `recon batch <file>` | Stable | One domain per line (comments with `#`), `--json` / `--md` / `--csv`. |
| `recon doctor` | Stable | Check labels and exit codes. `--fix` and `--mcp` sub-flags. |
| `recon mcp` | Stable | stdio transport only. |
| `recon delta <domain>` | Stable | Auto-cache diff (v0.10.2). Diff panel + `--json`. |
| `recon cache show [domain]` | Stable | Per-domain CT cache inspection. |
| `recon cache clear [domain \| --all]` | Stable | Clears both CT subdomain cache and TenantInfo result cache (v1.0.2+). |
| `recon fingerprints list` | Stable | v1.1+. Per-category summary by default; `--category`, `--type`, `--all`, `--json`. |
| `recon fingerprints search <query>` | Stable | v1.1+. Search slug / name / category / detection pattern. |
| `recon fingerprints show <slug>` | Stable | v1.1+. Full entry definition, including synthetic-slug provenance. |
| `recon fingerprints check [path]` | Stable | v1.1+. Runtime schema, duplicate-slug, and specificity (v1.2+) checks. |
| `recon fingerprints new <slug>` | Stable | v1.2+. Scaffolding wizard — slug / schema / specificity gates then emits YAML. |
| `recon fingerprints test <slug>` | Stable | v1.2+. Runs one fingerprint against the bundled public corpus. |
| `recon signals list` / `search` / `show` | Stable | v1.1+. Same shape as the fingerprints inspect commands. |

### CLI flags (on `recon <domain>`)

| Flag | Stability | Notes |
|---|---|---|
| `--json` | Stable | JSON output contract in [`schema.md`](schema.md). |
| `--md` | Stable | Markdown H2 section structure is stable; prose is not. |
| `--full` / `-f` | Stable | Verbose + all services + all domains + posture. |
| `--verbose` / `-v` | Stable | Dual confidence + detection scores + evidence chain. |
| `--explain` | Stable | Full reasoning + evidence provenance DAG. |
| `--services` / `-s`, `--domains` / `-d` | Stable | Progressive disclosure toggles. |
| `--sources` | Stable | Per-source resolution status table. |
| `--posture` / `-p`, `--exposure`, `--gaps` | Stable | Posture observation modes. |
| `--profile NAME` | Stable | Built-in profiles: fintech, healthcare, saas-b2b, high-value-target, public-sector, higher-ed. Custom profiles additive. |
| `--confidence-mode {hedged,strict}` | Stable | v0.11. Default `hedged`. |
| `--compare <file>` | Stable | Diff against previous JSON export. |
| `--chain`, `--depth <1-3>` | Stable | Recursive related-domain resolution. |
| `--no-cache`, `--cache-ttl <sec>` | Stable | Cache control. |
| `--timeout <sec>` / `-t` | Stable | Pipeline timeout (default 120s). |
| `--fusion` | **Experimental** | v0.11. Opt-in Bayesian fusion. |

### CLI exit codes

| Code | Meaning | Stability |
|---|---|---|
| 0 | Success | Stable |
| 1 | General error (fallback) | Stable |
| 2 | Input validation error (bad domain format, missing file) | Stable |
| 3 | No data found | Stable |
| 4 | Internal / network error | Stable |

### MCP tools

All 17 MCP tools are **stable** — names, parameter names, parameter types,
and return-payload shapes will not change between patch or minor releases.
New optional parameters may be added.

| Tool | Parameters |
|---|---|
| `lookup_tenant` | `domain`, `format` ("text"\|"json"\|"markdown"), `explain` (bool) |
| `analyze_posture` | `domain`, `explain` (bool), `profile` (str, optional) |
| `chain_lookup` | `domain`, `depth` (1-3, default 1) |
| `reload_data` | (none) |
| `assess_exposure` | `domain` |
| `find_hardening_gaps` | `domain` |
| `compare_postures` | `domain_a`, `domain_b` |
| `get_fingerprints` | `category` (optional) |
| `get_signals` | `category` (optional), `layer` (1-4, optional) |
| `explain_signal` | `signal_name`, `domain` (optional) |
| `test_hypothesis` | `domain`, `hypothesis` |
| `simulate_hardening` | `domain`, `fixes` (list[str]) |
| `inject_ephemeral_fingerprint` | `name`, `slug`, `category`, `confidence`, `detections` (list[dict]) |
| `list_ephemeral_fingerprints` | (none) |
| `clear_ephemeral_fingerprints` | (none) |
| `reevaluate_domain` | `domain` |
| `cluster_verification_tokens` | `domains` (list[str]) |

All MCP tools are stability-covered, but not all are read-only. The
lookup/analysis tools are read-only; `reload_data`,
`inject_ephemeral_fingerprint`, and `clear_ephemeral_fingerprints`
modify only local session state for the running process. The FastMCP
Server Instructions document those boundaries for agents each session.

### JSON output fields

The full top-level JSON contract is in [`schema.md`](schema.md). Summary
of stability tags:

- **~45 stable fields** covering identity, provider, sources, services,
  domains, email security, CT metadata, sovereignty, and nested
  `cert_summary` / `bimi_identity` objects.
- **1 experimental field**: `slug_confidences` (Bayesian fusion, v0.11).

Any `--json` consumer that reads only stable fields will work across
patch and minor releases without modification.

### Config / data files

| Surface | Stable guarantee |
|---|---|
| `data/fingerprints/*.yaml` schema | Stable — fields: name, slug, category, confidence, detections, match_mode, weight, m365, provider_group, display_group. v1.1 split the monolith into per-category files; file boundaries are a repo-organization detail, not part of the schema contract. |
| `~/.recon/fingerprints.yaml` schema | Same. Custom entries are **additive only** — cannot override built-ins. A `~/.recon/fingerprints/` directory is also accepted (v1.1+). |
| `data/signals.yaml` schema | Stable — fields: name, category, confidence, description, requires, metadata, contradicts, requires_signals, expected_counterparts, positive_when_absent. |
| `~/.recon/signals.yaml` schema | Same. Additive only. |
| `data/profiles/*.yaml` schema | Stable — fields: name, description, category_boost, signal_boost, focus_categories, exclude_signals, prepend_note. |
| `~/.recon/profiles/*.yaml` schema | Same. Additive only. |
| `~/.recon/cache/*.json` (TenantInfo cache) | Stable — backward-compatible reads, forward-compatible writes. |
| `~/.recon/ct-cache/*.json` (per-domain CT cache) | Stable. |
| `RECON_CONFIG_DIR` environment variable | Stable. |

---

## Experimental surfaces

These may evolve in minor releases without a major version bump. Use at
your own risk in automation — the field shape, semantics, or existence
are not guaranteed.

| Surface | Introduced | Notes |
|---|---|---|
| `--fusion` CLI flag | v0.11 | Opt-in Bayesian fusion layer. |
| `slug_confidences` field on TenantInfo / JSON output | v0.11 | Populated only when `--fusion` is set. Empty list otherwise. Algorithm, priors, and field shape may change. |

---

## What "stable" means

A stable surface will not break between patch releases (`x.y.z` → `x.y.z+1`)
or between minor releases (`x.y` → `x.y+1`). Breaking changes to stable
surfaces require a major version bump (`x.y` → `(x+1).0`) and a minimum
one-release deprecation window with a warning emitted before removal.

**Additions are not breaking changes.** New optional CLI flags, new
optional JSON fields, new MCP tools, new fingerprints or signals — all of
these can land in minor releases without breaking existing consumers.

**Default value changes to existing fields** ARE breaking changes if a
consumer was relying on the default.

---

## What is NOT in the stability contract

- **Rich panel visual formatting** — colors, whitespace, row ordering
  within Services categories, box-drawing details. The section structure
  is stable; pixel-level rendering is not.
- **Insight wording** — individual insight text may be refined. The
  insight *types* and their *trigger conditions* are stable (see
  `signals.yaml`); the exact phrasing is not.
- **Which specific fingerprints fire for a given domain** — the `slugs`
  field is stable as a mechanism; its contents depend on the fingerprint
  database version and may change as new fingerprints are added or
  existing ones are refined.
- **Debug / verbose internals** — `--explain` output is stable at the
  section level; per-line detail may evolve.
- **Cache file internal layouts beyond the documented TenantInfo/CT
  shapes** — future fields may be added; consumers should ignore unknown
  fields (forward-compatible reads).

---

## Python support policy

The stable Python surface is the range advertised in `pyproject.toml` and
tested in CI.

- **Currently tested:** Python 3.10, 3.11, 3.12, and 3.13.
- **Adding a Python version:** update CI, classifiers, and this section in the
  same change.
- **Dropping a Python version:** treat as a compatibility change, document it
  in `CHANGELOG.md`, and warn one minor release ahead when practical.

---

## SemVer commitment

From 1.0 onward, recon follows [Semantic Versioning](https://semver.org)
strictly:

- **MAJOR** (1.x → 2.0): breaking change to any stable surface.
- **MINOR** (1.x → 1.(x+1)): backward-compatible additions. Breaking
  changes to *experimental* surfaces are allowed.
- **PATCH** (1.x.y → 1.x.(y+1)): bug fixes only. No new features, no
  schema changes.

Pre-1.0 releases (0.9.x through 0.11.x) did not honor this contract
strictly — some minor releases included breaking changes within a minor.
From 1.0 onward the contract is enforced.
