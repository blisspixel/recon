# Stability Policy

recon is approaching v1.0. This document defines which public surfaces are
**stable** (breaking changes require a major version bump + deprecation
window) and which are **experimental** (may evolve in minor releases).

## Stable surfaces

### CLI

| Surface | Stable guarantee |
|---|---|
| `recon <domain>` default panel layout (section order, field names) | Stable |
| `recon <domain> --json` top-level field names and types (`display_name`, `services`, `slugs`, `ct_provider_used`, `email_security_score`, …) | Stable |
| `recon <domain> --md` markdown structure (H2 section headers) | Stable |
| `recon <domain> --full / --verbose / --explain` flag semantics | Stable |
| `recon <domain> --confidence-mode {hedged,strict}` | Stable (new in v0.11) |
| `recon doctor` exit codes and check labels | Stable |
| `recon cache show / clear` output format | Stable |
| `recon delta <domain>` diff panel + `--compare <file>` | Stable |
| `recon batch <file>` JSON output format | Stable |
| `recon mcp` stdio transport | Stable |

### MCP server

| Tool | Stability |
|---|---|
| `lookup_tenant`, `analyze_posture`, `chain_lookup`, `reload_data` | Stable |
| `assess_exposure`, `find_hardening_gaps`, `compare_postures` | Stable |
| `get_fingerprints`, `get_signals`, `explain_signal` | Stable |
| `test_hypothesis`, `simulate_hardening` | Stable |
| `cluster_verification_tokens` | Stable |
| `inject_ephemeral_fingerprint` / `list_ephemeral_fingerprints` / `clear_ephemeral_fingerprints` / `reevaluate_domain` | Stable |

Tool names, parameter names, parameter types, and return shapes are all
stable. New optional parameters may be added in minor releases.

### Config / data files

| Surface | Stable guarantee |
|---|---|
| `~/.recon/fingerprints.yaml` schema (name, slug, category, confidence, detections, match_mode, weight) | Stable |
| `~/.recon/signals.yaml` schema | Stable |
| `~/.recon/profiles/*.yaml` schema | Stable |
| `~/.recon/cache/` TenantInfo JSON format | Stable (backward-compatible reads, forward-compatible writes) |
| `~/.recon/ct-cache/` per-domain CT JSON format | Stable |
| `RECON_CONFIG_DIR` environment variable | Stable |

## Experimental surfaces

These may evolve in minor releases without a major version bump. Use at your
own risk in automation — the field shape, semantics, or existence are not
guaranteed.

| Surface | Introduced | Notes |
|---|---|---|
| `--fusion` CLI flag | v0.11 | Bayesian fusion is experimental. Algorithm, priors, and the `slug_confidences` field shape may change. |
| `slug_confidences` field on TenantInfo / JSON output | v0.11 | Only populated when `--fusion` is set. |

## What "stable" means

A stable surface will not break between patch releases (0.x.y → 0.x.z) or
between minor releases (0.x → 0.y). Breaking changes to stable surfaces
require a major version bump (0.x → 1.0 → 2.0) and a minimum 3-month
deprecation window with a warning emitted before removal.

Additions (new optional CLI flags, new optional JSON fields, new tools) are
NOT breaking changes — existing consumers continue to work.

## What's NOT in the stability contract

- **Rich panel visual formatting** — colors, whitespace, row ordering within
  Services categories, emoji/box-drawing details. The section structure is
  stable; pixel-level rendering is not.
- **Insight wording** — individual insight text may be refined. Insight
  types and trigger conditions are stable (see `signals.yaml`); exact
  phrasing is not.
- **Fingerprint detection internals** — the `detection_scores` and
  `confidence` fields are stable. Which specific fingerprints fire for a
  given domain may change as the fingerprint database is updated.
- **Debug / verbose internals** — `--explain` output format is stable at the
  section level; per-line detail may evolve.

## Python version support

CPython N-2 (currently 3.10, 3.11, 3.12). Python 3.10 support ends when
CPython 3.13 reaches end-of-life per PEP 602.
