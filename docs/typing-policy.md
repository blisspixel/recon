# Effective typing policy

Pyright 1.1.414 defaults to `strict` for `src/recon_tool`, `tests` and the three
validation modules and the new policy checker explicitly listed in
`pyproject.toml`. The target language
version is Python 3.11. The policy is not a claim of unsuppressed strictness:
legacy file controls and line-specific exceptions remain in the exact owned
[exception inventory](typing-exceptions.json).

Run `uv run python scripts/check.py` before pushing. Its normal Pyright stage,
CI typecheck job and pre-commit hook share the configured include list. The
additional `scripts/check_typing_policy.py` stage is blocking in all three.
It rejects global or execution-environment relaxations, changed scopes and
unowned file/line controls. It then copies only Python source needed for import
resolution to a temporary directory, restores each checked file's relaxed
families to errors, and runs the pinned checker without executing copied code.
The audit uses the Linux static platform of hosted typecheck; the ordinary
checker still uses the native platform, and runtime CI covers supported OSes.
The real checkout is never rewritten. An exact analyzed-file count rejects
empty or narrowed audits. Import-only validation modules retain their controls;
this work does not expand the configured validation scope.

The audit compares content-bound diagnostic identities per exact path and
family. A new error, a same-count replacement, or a repaired error requires
review and a corresponding inventory reduction/update. This is stricter than
an aggregate warning ceiling: removing an unrelated error cannot pay for a
new wrong call. Inline exceptions are separately bound to the complete source
line, including the tested call and rule marker. The inventory is maintainer
owned; its reason categories and revisit conditions apply to each referenced
path/family. It contains hashes and counts, not raw fixture values or workstation
paths. The check neither uploads source nor makes network requests.

## Measured baseline and changes

The [baseline inventory](typing-baseline.json) records immutable revision
`85c61662ee7e84501d7710e4fe2c6f3a084fdb7f`, uv 0.13.5, Python 3.15.1 and
Pyright 1.1.414. The configured check and each originally disabled family were
measured separately; every experiment analyzed 603 files. Counts overlap across
experiments and are not additive. Exact paths distinguish production, tests and
selected validation code. Historical comments about YAML or dependency typing
were not treated as evidence that every exception remained necessary.

The original missing-module-source experiment found no errors. That diagnostic
is enabled everywhere. Missing stubs are distinct: the pinned `publicsuffixlist`
production import and pip-audit `RequirementSource` test import lack supplied
typing markers. Their exceptions are on those exact imports; runtime source is
present. Production unknown-parameter diagnostics also needed no exception.

Checked JSON adapters now retain `object` values until validated. A container
check proves string keys, not that a particular value is a string. The bounded
JSON loader returns `object`; cache admission and the fingerprint artifact
parser validate their roots and rows. OIDC parsing accepts a read-only mapping
of untrusted values and checks the authorization endpoint before URL parsing.
A malformed non-string endpoint returns the existing unavailable/parse-error
state. Valid discovery behavior and network scope are unchanged.

Collection and DNS ledger factories have explicit container types. Rate-limit
snapshots have their actual eleven-field shape, and persisted numeric helpers
accept read-only object mappings. Certificate summary helpers also describe
read-only input sequences/mappings rather than unnecessarily invariant mutable
containers. These are actual input/output contracts, not unchecked casts or
substitution of `Any` for unknown values.

All diagnostic families are enabled at the repaired JSON, cache-admission,
artifact, OIDC, collection-limit, DNS primitive and rate-limit module boundaries
and the shared tenant fixture module. The policy forbids file-level relaxations
there. Existing line exceptions, including the legacy limiter factory adapter,
remain separately inventoried; this work does not claim to eliminate all `Any`.

## Tests and remaining debt

Test relaxations were reviewed separately. Shared tenant constructor fixtures
now use `TypedDict`/`Unpack`; rate-limit Hypothesis options preserve their actual
keyword types. Bayesian posterior helpers name their result types. Optional
mock calls, certificate summaries, errors and incomplete delta diagnostics are
narrowed before access. StringIO/Text inspection checks the actual renderer
value. Canonical test imports fix stale compatibility-shim attribute assumptions
and a tests-root environment that incorrectly resolved the `validation` package
to `tests/validation`. Dedicated shim compatibility tests remain intact.

The previous global unknown-type overrides and the entire test execution
environment have been removed. New files receive every strict diagnostic.
Legacy unknown containers, unannotated fixture parameters, deliberate private
access, generic JSON fixtures and negative inputs/test doubles still have exact
measured exceptions. They are debt, not proof that a check is unnecessary.
Their unmasked identities remain blocking against growth or substitution even
inside an already excepted file. Restore an individual family by repairing its
producer or fixture and removing that path's control; do not weaken assertions,
change invalid runtime inputs into valid ones, lower coverage or broaden an
ignore to make the checker pass.

Committed positive/negative fixtures under `tests/fixtures/typing` run the real
pinned checker. They demonstrate that wrong budgets, byte limits, tenant values,
fixture values and unchecked JSON members are rejected, while checked values
are accepted. The same committed loader probe passes incorrectly against the
old `Any` return and rejects the unchecked value after narrowing to `object`;
the baseline inventory records both actual one-file checker runs. Runtime cases
cover malformed JSON containers, artifact admission
and non-string OIDC endpoints. Synthetic checks establish these contracts;
they do not establish population accuracy or constitute a security audit.

## Reviewing a change to an exception

Inspect the normal checker and the actual unmasked errors first. Use
`uv run python scripts/check_typing_policy.py --audit-output .agent/typing-audit.json --diagnostics-output .agent/typing-errors.json`
to write measured identities and actual errors with relative source paths and
line numbers, without changing the inventory. Keep the error file private: its
messages may contain fixture literals. Neither file is uploaded. The command
still fails when identities differ. Diagnose the relevant source or test and
prefer checked narrowing, an accurate signature or an explicit negative-input
line over a file control. Do not copy a newly measured digest into the inventory
without understanding the diagnostic. Keep the owner, reason and revisit
condition accurate, remove stale controls, and review the diff with the full
local gate and relevant hosted CI. A toolchain upgrade needs a fresh reviewed
measurement; an automatic baseline refresh is not a pass.
