# Microsoft Internal Triad Motif

Date: 2026-06-19

## Scope

This memo records the public rationale for adding the
`tm_to_azurefd_to_msedge` built-in chain motif. It contains no customer domains,
no corpus rows, and no per-target findings.

The v1.8 validation summary already identified the complete Microsoft internal
CNAME shape as Traffic Manager to Azure Front Door to the Microsoft Edge fabric.
The built-in catalog had the two pairwise motifs:

- `tm_to_azurefd`
- `azurefd_to_msedge`

The new motif adds the complete ordered triad while leaving the pairwise motifs
unchanged.

## Candidate-Chain Delta

Public fictional candidate chain:

```text
api.example.invalid:
  scenario.trafficmanager.net
  scenario.azurefd.net
  scenario.t-msedge.net
```

Before this change, the built-in catalog matched:

- `tm_to_azurefd`
- `azurefd_to_msedge`

After this change, the same candidate chain matches:

- `tm_to_azurefd`
- `azurefd_to_msedge`
- `tm_to_azurefd_to_msedge`

Delta:

- triad motif count: 0 to 1
- pairwise motif count: unchanged at 2

## Regression Coverage

The tests pin two behaviors:

- the complete ordered fictional chain fires `tm_to_azurefd_to_msedge`;
- reversing the first two markers does not fire the triad.

## Validation

Focused tests:

```bash
uv run python -m pytest tests/test_motifs.py tests/test_validation_hygiene.py -q
```

Result: passed with 25 tests.

Focused lint:

```bash
uv run python -m ruff check tests/test_motifs.py
```

Result: passed.

Validation hygiene:

```bash
uv run python scripts/check_validation_hygiene.py
```

Result: passed.

Full local gate:

```bash
uv run python scripts/check.py
```

Result: passed. Coverage was 86.18 percent. Tests: 3413 passed, 6 skipped,
4 deselected.

External spend: 0 USD.
