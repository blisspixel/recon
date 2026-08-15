"""Structured option models for the lookup command.

The Typer command necessarily exposes many flags, but the lookup implementation
should receive a small, coherent object. These models keep normalization and
cross-flag validation in one place so adding a flag does not widen the internal
orchestration signature.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

# Renderers accepted by --explain-dag-format. Kept beside the option model so
# the pre-collection check and the renderer cannot drift apart.
_EXPLAIN_DAG_FORMATS = frozenset({"text", "dot", "mermaid"})


class LookupOutputMode(StrEnum):
    """Primary renderer selected by output flags."""

    PANEL = "panel"
    JSON = "json"
    MARKDOWN = "markdown"
    PLAIN = "plain"


class LookupOperationMode(StrEnum):
    """High-level lookup operation selected by mode flags."""

    STANDARD = "standard"
    COMPARE = "compare"
    CHAIN = "chain"
    EXPOSURE = "exposure"
    GAPS = "gaps"


@dataclass(frozen=True)
class LookupOutputOptions:
    """Output renderer flags and JSON-shape modifiers."""

    json_output: bool = False
    markdown: bool = False
    plain: bool = False
    include_unclassified: bool = False

    @property
    def mode(self) -> LookupOutputMode:
        if self.json_output:
            return LookupOutputMode.JSON
        if self.markdown:
            return LookupOutputMode.MARKDOWN
        if self.plain:
            return LookupOutputMode.PLAIN
        return LookupOutputMode.PANEL

    @property
    def quiet(self) -> bool:
        return self.mode in {LookupOutputMode.JSON, LookupOutputMode.MARKDOWN}

    def validation_error(self) -> str | None:
        if sum([self.json_output, self.markdown, self.plain]) > 1:
            return "--json, --md, and --plain are mutually exclusive"
        return None


@dataclass(frozen=True)
class LookupDisplayOptions:
    """Human-facing panel/detail controls."""

    verbose: bool = False
    show_services: bool = False
    show_domains: bool = False
    show_sources: bool = False
    show_posture: bool = False
    show_explain: bool = False
    profile_name: str | None = None
    confidence_mode: str = "hedged"

    @classmethod
    def from_flags(
        cls,
        *,
        services: bool,
        domains: bool,
        full: bool,
        verbose: bool,
        sources: bool,
        posture: bool,
        explain: bool,
        profile: str | None,
        confidence_mode: str,
    ) -> LookupDisplayOptions:
        if full:
            services = True
            domains = True
            verbose = True
            posture = True
        if profile and not posture:
            posture = True
        return cls(
            verbose=verbose,
            show_services=services,
            show_domains=domains,
            show_sources=sources,
            show_posture=posture,
            show_explain=explain,
            profile_name=profile,
            confidence_mode=confidence_mode,
        )


@dataclass(frozen=True)
class LookupOperationOptions:
    """Mode flags that choose the lookup pipeline."""

    compare_file: str | None = None
    chain_mode: bool = False
    chain_depth: int = 1
    show_exposure: bool = False
    show_gaps: bool = False

    @property
    def mode(self) -> LookupOperationMode:
        # ``is not None`` rather than truthiness: --compare "" is a supplied
        # path, not an absent flag. Treating it as absent selected STANDARD
        # mode, so the empty path was ignored and the mutual-exclusion
        # checks below could not see it either.
        if self.compare_file is not None:
            return LookupOperationMode.COMPARE
        if self.chain_mode:
            return LookupOperationMode.CHAIN
        if self.show_exposure:
            return LookupOperationMode.EXPOSURE
        if self.show_gaps:
            return LookupOperationMode.GAPS
        return LookupOperationMode.STANDARD

    def validation_error(self) -> str | None:
        if self.chain_mode and self.compare_file is not None:
            return "--chain and --compare are mutually exclusive"
        if self.show_exposure and self.show_gaps:
            return "--exposure and --gaps are mutually exclusive"
        if self.show_exposure and (self.chain_mode or self.compare_file is not None):
            return "--exposure and --chain/--compare are mutually exclusive"
        if self.show_gaps and (self.chain_mode or self.compare_file is not None):
            return "--gaps and --chain/--compare are mutually exclusive"
        if self.chain_depth > 1 and not self.chain_mode:
            return "--depth requires --chain"
        if not 1 <= self.chain_depth <= 3:
            # The help text and the chain engine both say 1 to 3. Out-of-range
            # values were silently clamped, so --depth 99 reported success for a
            # traversal the operator did not ask for.
            return "--depth must be between 1 and 3"
        return None


@dataclass(frozen=True)
class LookupInferenceOptions:
    """Bayesian fusion and DAG-output controls."""

    fusion: bool = True
    explain_dag: bool = False
    explain_dag_format: str = "text"

    def validation_error(self) -> str | None:
        # The renderer rejected a bad format, but only after the lookup had
        # already resolved, so a typo cost a full collection round against the
        # target before exit 2. Checking here keeps a misspelled flag from
        # reaching the network at all. Validated whenever the value is not a
        # supported one, even without --explain-dag: silently ignoring an
        # explicit value reports success for something the caller asked for,
        # the same defect already fixed for an out-of-range --depth.
        if self.explain_dag_format.lower() not in _EXPLAIN_DAG_FORMATS:
            supported = ", ".join(sorted(_EXPLAIN_DAG_FORMATS))
            return f"--explain-dag-format must be one of {supported}, got {self.explain_dag_format!r}"
        return None


@dataclass(frozen=True)
class LookupExecutionOptions:
    """Resolver, cache, CT, and probe controls."""

    timeout: float = 120.0
    no_cache: bool = False
    cache_ttl: int = 86400
    skip_ct: bool = False
    active_probes: bool = False
    exact: bool = False


@dataclass(frozen=True)
class LookupOptions:
    """Complete normalized option set for one lookup invocation."""

    output: LookupOutputOptions
    display: LookupDisplayOptions
    operation: LookupOperationOptions
    inference: LookupInferenceOptions
    execution: LookupExecutionOptions

    def validation_error(self) -> str | None:
        # Delegate to each component that validates itself, then check the
        # cross-component combinations that no single component can see. The
        # loop keeps adding a component validator free rather than growing one
        # return per component.
        for component in (self.output, self.operation, self.inference):
            if error := component.validation_error():
                return error
        if self.plain and self.operation.mode is not LookupOperationMode.STANDARD:
            return "--plain cannot be combined with --chain/--compare/--exposure/--gaps"
        if self.markdown and self.operation.mode is not LookupOperationMode.STANDARD:
            return "--md cannot be combined with --chain/--compare/--exposure/--gaps"
        # --explain-dag renders its own report and returns before the output
        # branches, so pairing it with a renderer silently discarded the
        # requested format: a scripted `--json --explain-dag | jq` received
        # prose and exit 0. `--json --md` is already rejected; be consistent.
        if self.explain_dag and (self.json_output or self.markdown or self.plain):
            return "--explain-dag cannot be combined with --json/--md/--plain"
        return None

    @property
    def json_output(self) -> bool:
        return self.output.json_output

    @property
    def markdown(self) -> bool:
        return self.output.markdown

    @property
    def plain(self) -> bool:
        return self.output.plain

    @property
    def quiet(self) -> bool:
        return self.output.quiet

    @property
    def include_unclassified(self) -> bool:
        return self.output.include_unclassified

    @property
    def operation_mode(self) -> LookupOperationMode:
        return self.operation.mode

    @property
    def compare_file(self) -> str | None:
        return self.operation.compare_file

    @property
    def chain_depth(self) -> int:
        return self.operation.chain_depth

    @property
    def verbose(self) -> bool:
        return self.display.verbose

    @property
    def show_services(self) -> bool:
        return self.display.show_services

    @property
    def show_domains(self) -> bool:
        return self.display.show_domains

    @property
    def show_sources(self) -> bool:
        return self.display.show_sources

    @property
    def show_posture(self) -> bool:
        return self.display.show_posture

    @property
    def show_explain(self) -> bool:
        return self.display.show_explain

    @property
    def profile_name(self) -> str | None:
        return self.display.profile_name

    @property
    def confidence_mode(self) -> str:
        return self.display.confidence_mode

    @property
    def fusion(self) -> bool:
        return self.inference.fusion

    @property
    def explain_dag(self) -> bool:
        return self.inference.explain_dag

    @property
    def explain_dag_format(self) -> str:
        return self.inference.explain_dag_format

    @property
    def timeout(self) -> float:
        return self.execution.timeout

    @property
    def no_cache(self) -> bool:
        return self.execution.no_cache

    @property
    def cache_ttl(self) -> int:
        return self.execution.cache_ttl

    @property
    def skip_ct(self) -> bool:
        return self.execution.skip_ct

    @property
    def active_probes(self) -> bool:
        return self.execution.active_probes

    @property
    def exact(self) -> bool:
        return self.execution.exact
