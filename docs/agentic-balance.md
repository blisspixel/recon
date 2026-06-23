# Rules vs agentic: the balance

Read this before adding a rule, a heuristic, or any agent-driven behavior, and
before wiring recon to an agent or MCP client. It is the standing answer to one
recurring question: should this be a deterministic rule, a more principled rule,
or agent judgment, and where does it live. Keep it current as the boundary moves
(see [Keeping this current](#keeping-this-current)).

## The one principle

recon's observe-infer-report core is rules-based and deterministic by invariant.
The agentic intelligence lives outside that core, in the consumer (an agent over
MCP) and in maintainer loops. recon's job toward agents is to be a trustworthy
data primitive, not to be agentic itself.

This is not a bias toward rules for their own sake. It follows from what recon
promises: full provenance, reproducible output, and honest uncertainty. A
learned or LLM-driven component anywhere in the core would break byte-identical
output, sever the evidence DAG, and violate the no-learned-weights invariant.

## The decision guide

Three questions, in order. Stop at the first that fits.

1. **Is this in the observation, inference, or output core?** (collection,
   fingerprint matching, the Bayesian layer, graph correlation, the credible
   interval, JSON/exit-code emission) Then it is **rules-based, never agentic.**
   No learned weights, no LLM call, no network-dependent nondeterminism. The
   invariants in [the concept that orders the plan](roadmap.md) and the
   reproducible-build gate enforce this.

2. **If it is a rule, is it a brittle rule or a principled one?** Most
   foot-guns are not "should have been agentic." They are brittle rules that
   should have been principled rules. See
   [Rules-based is not brittle-rules](#rules-based-is-not-brittle-rules). The fix
   is almost always to generalize the rule, move the specifics into a
   data-driven catalog, or push the uncertainty into the Bayesian layer instead
   of hard-coding a verdict, not to reach for an agent.

3. **Is this a maintenance loop or an interaction with an agent/MCP client?**
   Then agent judgment is appropriate, but kept outside the deterministic core
   and fenced by the rules in [The agentic boundary](#the-agentic-boundary):
   data-not-instructions, untrusted external content, and agent-proposes /
   gate-and-human-dispose.

## Rules-based is not brittle-rules

The repeated foot-gun is not choosing rules over agents. It is writing a brittle
rule (over-fit to a specific string or case) where a principled rule belonged.
recon has paid for several of these and fixed each by making the rule more
principled, not by abandoning rules. Treat the list below as smells: if a change
matches one, generalize it before merging.

| Brittle-rule smell | Principled fix | Precedent |
|---|---|---|
| Substring match where structure matters (`"-all" in spf`, `pattern in hostname`) | Token-aware or label-aware match | spf `-all` substring to token match (v2.1.6); `cname_target` substring overmatch (v2.1.4); label-aware chain match so `vendor.com.attacker.tld` no longer matches `vendor.com` (`dns_tables.classify_chain`) |
| Hard-coded vendor string in code | A catalog entry in `fingerprints.yaml` / `signals.yaml`, additive and vendor-doc-sourced | The whole fingerprint catalog exists so detection grows by data, not code |
| Treating absence of a signal as proof of absence | Absence is no evidence by default (MNAR, `LR = 1`); only public-declaration signals disconfirm on absence | The MNAR absence rule in [correlation.md](correlation.md); the declarative-missingness model and `group_absence` for the email-policy node (CAL14) |
| A confident yes/no verdict on sparse evidence | Emit the claim as a credible interval that widens on sparse input; set `sparse=true` | The credible interval is the load-bearing field by design; the Bayesian layer exists to discipline claims, not decorate them |
| Co-firing observations multiplied as if independent | Group correlated bindings (one evidence cluster contributes once) | Evidence groups / CAL7 over-confidence treatment |
| A rule tuned to make the local corpus look right | Validate against the corpus as a distribution, keep priors at observed base rates, never over-fit | The calibration track (CAL6/CAL12) and the no-over-fit discipline |

The through-line: when a rule feels brittle, the answer is usually a more
general rule plus honest uncertainty, kept deterministic. The Bayesian layer is
the project's main tool for this. It is what lets recon avoid both brittle
verdicts and a leap to agent judgment.

## The agentic boundary

Where agent judgment is the right tool, it stays outside the core and obeys
these rules:

- **recon is consumed by agents; it does not become one.** The MCP server hands
  an agent structured data (`structuredContent`, per-tool `outputSchema`,
  `isError`). Interpretation, what-if loops, and cross-domain reasoning are the
  agent's job, not the core's.
- **Data, not instructions.** Everything recon returns from the public channel
  (DNS TXT, CT SAN names, BIMI metadata, identity-endpoint responses) is
  untrusted external content and is marked as such. A consuming agent must treat
  it as data, never as instructions. The agent is assumed adversarial in the
  threat model ([security.md](security.md), `SECURITY.md`).
- **Agent proposes, gate and human dispose.** Maintenance loops (PV2) may use an
  agent to scan, re-ground base rates, and propose a CPT change, but a
  deterministic gate decides (`validation/drift_check.py`) and the maintainer
  approves any semantic change. Agent output never feeds back into the core
  weights or catalog without passing the gate
  ([maintainer-validation.md](maintainer-validation.md)).
- **Manual approval by default at the MCP surface.** Read-only tools and stateful
  tools are split; do not auto-approve stateful ones. See the autoApprove
  guidance in [mcp.md](mcp.md).

Agentic foot-guns to refuse, by symmetry with the brittle-rule list: letting
recon emit anything an agent could read as a command; trusting an external
string because it arrived through a tool call; auto-approving a stateful tool;
and the cardinal one, putting any learned or LLM component inside the
deterministic core.

## Allowed loop shapes

Agent loops are useful when they make maintenance more repeatable without
changing what recon is. The loop may perceive repo state, run deterministic
checks, propose a patch, and summarize evidence. It must have a clear stop
condition and a human gate for semantic changes.

These loops are optional maintainer/developer workflows, not a user-facing
requirement. A user can install and run recon as a CLI, library, JSON producer,
or MCP server without using an AI assistant. If loop prompts, schedules, or
agent-context bundles live in the repository, they are examples and runbooks for
maintainers and operators who want them, not part of recon's runtime contract.

| Loop | Good use | Stop condition | Human gate |
|---|---|---|---|
| Release readiness | Check version references, README examples, schema copies, Homebrew formula freshness, no-real-data examples, `scripts/check.py`, and CI status | All gates pass, or the loop opens a reviewed issue/PR with failures grouped by source | Required before tagging, publishing, or changing release artifacts |
| CI failure repair | Read failing checks, inspect logs, patch code/tests/docs, rerun the narrow failing gate and then the broad check | Failing check passes, or a reproducible blocker is documented | Required before merge |
| Calibration orchestration | Run existing validation harnesses over the private corpus and produce aggregate-only memos | Aggregate metrics are produced and checked for policy compliance, or the run fails with logs | Required before committing any memo or CPT change |
| Fingerprint triage | Read local gap output, propose YAML, references, sparse-result wording, and regression tests | Proposed diff includes evidence and tests, or candidate is rejected | Required before catalog or motif changes |
| Docs/context packaging | Generate an agent-readable surface inventory or OKF-style bundle from existing docs | Generated artifact matches sources under a drift gate | Required before making the artifact a stable surface |

The common constraints are strict: no target data in committed output, no
persistent aggregate scan database, no autonomous catalog/CPT/schema mutation,
no hosted service inside recon, no user requirement to use AI, and no
agent-written inference logic. If a loop needs to keep state, that state belongs
in git, in committed baselines, in gitignored maintainer-local validation
outputs, or in the operator's external automation system.

## A checklist before you add a rule or an agentic behavior

- Does it keep collection passive and credential-free?
- Does it keep output reproducible (byte-identical) and provenance intact?
- If it is a rule: is it general, or over-fit to one string/case? Could the
  specifics be a catalog entry instead?
- Does it assert more than the public channel supports? If sparse, does the
  interval widen rather than the verdict harden?
- If it involves an agent: is the agent outside the core, fed data-not-
  instructions, and unable to mutate the core without a gate and a human?
- What new failure mode does it add, and is that failure visible (flagged,
  hedged, logged) rather than silent?

If any answer is wrong, the design is not ready, regardless of whether it is a
rule or an agentic behavior.

## External validation (2026)

The boundary above predates the 2026 agentic-security guidance that now states
it as consensus. That convergence is worth recording: it shows recon's choices
are the standard ones, not idiosyncratic.

The central principle in the current literature is that security must be enforced
by deterministic controls outside the model's reasoning loop, never by the
model's own reasoning or prompt-level instructions. AWS states it directly:
enforce security through "deterministic, infrastructure-level controls external
to the agent's reasoning loop, not through the agent's own reasoning, internal
guardrails, or prompt-based instructions," because "LLMs are probabilistic
reasoning engines, not security enforcement mechanisms"
([AWS, four security principles for agentic AI systems](https://aws.amazon.com/blogs/security/four-security-principles-for-agentic-ai-systems/)).
Prompt injection remains the top-ranked LLM risk in the OWASP catalog, and the
underlying problem, that a model reads instructions and data on one channel, is
still unsolved in the general case.

The mapping onto this document is one-to-one:

- The deterministic control outside the reasoning loop is what this doc calls the
  rules-based observe-infer-report core. No model output can move a posterior, a
  fingerprint match, or an exit code.
- The unsolved data-vs-instructions problem is what the data-not-instructions
  rule contains, by refusing to let recon emit anything an agent could read as a
  command and by assuming the consuming agent is adversarial
  ([the agentic boundary](#the-agentic-boundary)).
- "Autonomy earned through evaluation" is the agent-proposes, gate-and-human-
  dispose rule: a proposal reaches the catalog or the CPTs only through a
  deterministic gate and a human, never on the model's say-so.

The practical consequence for recon is that the determinism of its own output is
the load-bearing guarantee, not the consuming agent's good behavior. recon must
stay correct even when the agent reading it has been fully compromised.

## Keeping this current

This doc is the load-bearing reference for the rules-vs-agentic call, so it is
meant to drift forward as recon does. Update it when:

- a new brittle-rule foot-gun is found and fixed (add a row with its precedent);
- the agentic surface changes (a new MCP tool class, a new maintainer loop, a
  change to the autoApprove split);
- an invariant is added or sharpened.

The roadmap points here from its top so the question gets re-asked at the right
moment. If the boundary in this doc and the invariants in
[roadmap.md](roadmap.md) ever disagree, that is a bug in one of them; reconcile,
do not leave both standing.
