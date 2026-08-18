# ADR-0017: The default view is one briefing in every shape

Status: accepted, 2026-08-17.

## Context

recon renders one record through eight surfaces: the Rich panel, `--plain`,
`--plain --full`, `--json`, `--csv`, `--md`, the MCP text tool, and the MCP JSON
tool. The default human view among these is a *briefing*: it leads with the
vendor roles, names the high-signal related domains and caps the insight list,
and states how much it withheld. ADR-0015 established the role split and ADR-0016
made `--plain` the panel linearised with the full record behind `--full`.

Four consecutive independent black-box rounds then found the same class of
defect, over and over, and never in the data: a decision applied to one renderer
and not the others. ADR-0015 fixed the panel while `--plain` kept the singular
provider row. ADR-0016 gave `--plain` the panel's rows but not its cuts. The
cuts shipped but the note counts were computed on the wrong basis. Each round
closed one surface's copy of the defect while the next surface still carried it,
because there was no shared definition of the default view: each renderer
reached into a set of loose helper functions, and `--md` and the MCP text
surface reached past them entirely. `--md` had no provider row, so the report
could not say who handled mail; it rendered every insight and related domain as
a roll call; it ignored `--confidence-mode`; and it titled the report on the
attacker-controllable display name. The MCP text tool was the same roll call,
and the MCP JSON tool advertised the fusion fields in its schema while always
emitting them empty.

A defect class that survives four rounds of one-surface fixes is not a set of
bugs. It is a missing abstraction.

## Decision

There is one definition of the default view, `build_briefing`, returning a
`BriefingView`, and every human surface renders it. The panel, `--plain`,
`--md`, and the MCP text tool all consume the same object: the same role split,
the same related-domain selection, the same insight cap, the same withheld
counts. A renderer cannot show the default view without making the same cuts,
because the selection is the object, not a convention each renderer re-derives.

`BriefingView` carries data, not formatted lines. Each surface keeps its own
wording: the panel counts withheld insights against its curated `--full`, the
linear surfaces count against the record, and each note names the `--full`
command its own reader types (`--plain --full`, `--md --full`, or `format="json"`
for the agent). One record can therefore carry two different remainders on two
surfaces; each is exact about the destination it names, which is what keeps two
numbers from reading as one contradiction.

The complete record stays behind each surface's own `--full`: `--plain --full`,
`--md --full`, and `format="json"` for MCP. `--json` and `--csv` remain the
machine contract and are unchanged except for the additive fusion population on
the MCP JSON path, which was a field lying about its value rather than a new
contract.

A gated artifact enforces this. `docs/surface-parity.md` is generated from one
maximal fixture rendered through all eight surfaces, and the `surface-parity`
gate in `scripts/check.py` fails when a surface gains or loses a claim, or a cut
stops reconciling, without the committed matrix moving in the same commit. The
reconcile property (shown plus withheld equals that surface's `--full`) would
have caught the note-count defect, the `--md` roll call, and the MCP fusion gap
as failing cells rather than as a tester's report. The fixture is deliberately
maximal: a role split, a filtered wildcard in the related list, and two insights
the curator drops, so its surfaces are able to disagree. A fixture whose
surfaces cannot disagree cannot guard against them disagreeing, which is exactly
how the 2.15.1 note bug passed its own test.

## Consequences

`--md` and the MCP text surface change shape. This is a **breaking change to two
human-facing renderers**, of the same class ADR-0016 made to `--plain`: the
default selection changes, the migration is each surface's `--full`, and no
stable machine contract moves. `--json`, `--csv`, the cache, and the capsule
schema are unchanged.

The escaping stayed on the full CommonMark set. A narrower, more readable escape
was tried for recon-authored strings and reverted when the injection tests
caught that service labels and insight text carry substrings parsed from source
records, and `region` and `auth_type` come from the identity endpoint. The
report reads `example\.com` when pasted raw; the defense is worth more than the
polish.

The parity gate is the durable outcome. The value of the black-box rounds was
never the individual findings; it was the discovery that presentation drift is
the standing defect class. The gate turns the next such drift into a failing
check in the commit that introduces it.

## SemVer reconciliation

`docs/stability.md` lists `--plain` as Stable and commits to a major version
bump plus a deprecation window for a breaking change to a stable surface, and
ADR-0016 openly called the 2.15 `--plain` change breaking. That was an
unreconciled contradiction in the document whose job is the contract. This ADR
resolves it, not by claiming the surface was never covered, but by naming what
is contractual and what is not.

Which rows a human view selects, the panel, `--plain`, `--md`, and the MCP text
surface, is a curated briefing and may change in a minor release. The flags,
their exit codes, and the stable schema key names those surfaces print do not
change without the stability contract's process. `--json` is the surface
automation parses, and `--plain --full` / `--md --full` restore the complete
record. `docs/stability.md` records this as the general form of the ADR-0016
one-surface decision, with 2.15 named as the precedent it generalises.

## Alternatives considered

**Keep fixing one surface per round.** Rejected: four rounds proved it does not
converge. Each fix is correct and the next surface still carries the defect.

**A separate `--brief` flag, leaving each renderer independent.** Rejected as in
ADR-0016: it grows the flag surface the roadmap is cutting, and it does nothing
about the surfaces that already disagree.

**A shared object without the gate.** Rejected: the object removes today's
drift, but nothing stops a new renderer, or a new field on an old one, from
reaching past it. The gate is what makes the invariant hold going forward.
