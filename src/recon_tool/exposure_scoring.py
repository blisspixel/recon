"""Proof-carrying construction for the model-bound public-evidence index."""

from __future__ import annotations

from dataclasses import dataclass, replace

from recon_tool.claim_contract import dmarc_policy_projection
from recon_tool.constants import (
    SVC_BIMI,
    SVC_DMARC,
    SVC_MTA_STS,
    SVC_SPF_SOFTFAIL,
    SVC_SPF_STRICT,
)
from recon_tool.exposure_copy import evidence_refs
from recon_tool.exposure_gaps import EMAIL_GATEWAY_SLUGS, mta_sts_mode_evidence, mta_sts_txt_evidence
from recon_tool.exposure_models import (
    BIMI_COMPONENT_ID,
    CAA_COMPONENT_ID,
    DKIM_COMPONENT_ID,
    DMARC_COMPONENT_ID,
    DMARC_QUARANTINE_POINTS,
    EMAIL_GATEWAY_COMPONENT_ID,
    EXPOSURE_COMPONENT_IDS,
    FEDERATED_IDENTITY_COMPONENT_ID,
    MTA_STS_COMPONENT_ID,
    MTA_STS_TESTING_POINTS,
    SPF_COMPONENT_ID,
    TLS_RPT_COMPONENT_ID,
    EvidenceReference,
    ExposureIndex,
    ExposureIndexComponent,
    ExposureIndexState,
    ExposureMetadataDependency,
    ExposureMetadataValue,
    exposure_component_spec,
)
from recon_tool.exposure_observability import ObservableEmailState
from recon_tool.fingerprints import get_caa_patterns
from recon_tool.models import EvidenceRecord, TenantInfo


@dataclass(frozen=True)
class _ComponentProof:
    """Typed proof payload shared by every component constructor."""

    dependencies: tuple[ExposureMetadataDependency, ...]
    scope: tuple[str, ...]
    evidence: tuple[EvidenceReference, ...] = ()


@dataclass(frozen=True)
class _RecordComponentRule:
    """Declarative selector for a fixed-record index component."""

    component_id: str
    metadata_field: str
    scope: str
    source_types: frozenset[str]
    rule_names: frozenset[str] | None = None
    slugs: frozenset[str] | None = None
    declared_slugs: frozenset[str] | None = None


_RECORD_COMPONENT_RULES = (
    _RecordComponentRule(
        BIMI_COMPONENT_ID,
        "bimi_record_observed",
        "dns:bimi",
        frozenset({"BIMI"}),
        frozenset({SVC_BIMI}),
        frozenset({"bimi"}),
        frozenset({"bimi"}),
    ),
    _RecordComponentRule(
        TLS_RPT_COMPONENT_ID,
        "tls_rpt_record_observed",
        "dns:tls_rpt",
        frozenset({"TXT"}),
        frozenset({"TLS-RPT"}),
        frozenset({"tls-rpt"}),
        frozenset({"tls-rpt"}),
    ),
    _RecordComponentRule(
        CAA_COMPONENT_ID,
        "caa_record_observed",
        "dns:caa",
        frozenset({"CAA"}),
        declared_slugs=frozenset({"caa"}),
    ),
)
_BIMI_RECORD_RULE, _TLS_RPT_RECORD_RULE, _CAA_RECORD_RULE = _RECORD_COMPONENT_RULES


def _maximum(component_id: str) -> int:
    """Return one component's canonical weight."""
    return exposure_component_spec(component_id)[1]


def _dependency(
    field: str,
    expected: ExposureMetadataValue,
    observed: ExposureMetadataValue,
) -> ExposureMetadataDependency:
    return ExposureMetadataDependency(field, "eq", expected, observed)


def _records(
    info: TenantInfo,
    *,
    source_types: frozenset[str],
    rule_names: frozenset[str] | None = None,
    slugs: frozenset[str] | None = None,
) -> tuple[EvidenceRecord, ...]:
    """Select exact retained records for one index rule."""
    return tuple(
        record
        for record in info.evidence
        if record.source_type.upper() in source_types
        and (rule_names is None or record.rule_name in rule_names)
        and (slugs is None or record.slug in slugs)
    )


def _component(
    component_id: str,
    state: ExposureIndexState,
    awarded_points: int,
    proof: _ComponentProof,
) -> ExposureIndexComponent:
    control, maximum_points = exposure_component_spec(component_id)
    return ExposureIndexComponent(
        component_id=component_id,
        control=control,
        state=state,
        awarded_points=awarded_points,
        maximum_points=maximum_points,
        generator_rule_id=component_id,
        metadata_dependencies=proof.dependencies,
        observation_scope=proof.scope,
        evidence=proof.evidence,
    )


def _hypothetical_state(
    component_id: str,
    state: ExposureIndexState,
    hypothetical_components: frozenset[str],
) -> ExposureIndexState:
    if component_id in hypothetical_components and state == "observed_value":
        return "hypothetical_value"
    return state


def _dmarc_component(
    info: TenantInfo,
    observed: ObservableEmailState,
    hypothetical_components: frozenset[str],
) -> ExposureIndexComponent:
    component_id = DMARC_COMPONENT_ID
    projection = dmarc_policy_projection(info)
    refs = evidence_refs(projection.evidence)
    declared = SVC_DMARC in info.services or "dmarc" in info.slugs
    if not observed.dmarc_available:
        state: ExposureIndexState = "unavailable"
        points = 0
    elif projection.exact_value and refs:
        state = "observed_value"
        points_by_policy: dict[str | None, int] = {
            "reject": _maximum(component_id),
            "quarantine": DMARC_QUARANTINE_POINTS,
        }
        points = points_by_policy.get(projection.effective_policy, 0)
    elif projection.exact_empty and not declared:
        state = "observed_empty"
        points = 0
    else:
        state = "unresolved"
        points = 0
    state = _hypothetical_state(component_id, state, hypothetical_components)
    return _component(
        component_id,
        state,
        points,
        _ComponentProof(
            dependencies=(
                _dependency(
                    "dmarc_construction_state",
                    projection.construction_state.value,
                    projection.construction_state.value,
                ),
                _dependency("effective_dmarc_policy", projection.effective_policy, projection.effective_policy),
            ),
            scope=("dns:dmarc",),
            evidence=refs,
        ),
    )


def _dkim_component(
    info: TenantInfo,
    observed: ObservableEmailState,
    hypothetical_components: frozenset[str],
) -> ExposureIndexComponent:
    component_id = DKIM_COMPONENT_ID
    records = _records(info, source_types=frozenset({"DKIM"}))
    configured = bool(records)
    if not observed.dkim_available:
        state: ExposureIndexState = "unavailable"
    elif configured:
        state = "observed_value"
    else:
        state = "unresolved"
    state = _hypothetical_state(component_id, state, hypothetical_components)
    return _component(
        component_id,
        state,
        _maximum(component_id) if configured and observed.dkim_available else 0,
        _ComponentProof(
            dependencies=(_dependency("dkim_observed_at_common_selectors", configured, configured),),
            scope=("dns:dkim_common_selectors",),
            evidence=evidence_refs(records),
        ),
    )


def _spf_component(
    info: TenantInfo,
    observed: ObservableEmailState,
    hypothetical_components: frozenset[str],
) -> ExposureIndexComponent:
    component_id = SPF_COMPONENT_ID
    strict_records = _records(
        info,
        source_types=frozenset({"SPF"}),
        rule_names=frozenset({SVC_SPF_STRICT}),
        slugs=frozenset({"spf-strict"}),
    )
    other_records = _records(info, source_types=frozenset({"SPF"}), rule_names=frozenset({SVC_SPF_SOFTFAIL}))
    strict = bool(strict_records)
    declared = bool(
        {SVC_SPF_STRICT, SVC_SPF_SOFTFAIL} & set(info.services)
        or {"spf-strict", "spf-softfail"} & set(info.slugs)
    )
    if not observed.spf_available:
        state: ExposureIndexState = "unavailable"
        records: tuple[EvidenceRecord, ...] = ()
    elif strict or other_records:
        state = "observed_value"
        records = strict_records or other_records
    elif declared:
        state = "unresolved"
        records = ()
    else:
        state = "observed_empty"
        records = ()
    state = _hypothetical_state(component_id, state, hypothetical_components)
    return _component(
        component_id,
        state,
        _maximum(component_id) if strict and observed.spf_available else 0,
        _ComponentProof(
            dependencies=(_dependency("spf_strict_observed", strict, strict),),
            scope=("dns:apex_txt",),
            evidence=evidence_refs(records),
        ),
    )


def _mta_sts_component(
    info: TenantInfo,
    observed: ObservableEmailState,
    hypothetical_components: frozenset[str],
) -> ExposureIndexComponent:
    component_id = MTA_STS_COMPONENT_ID
    mode = observed.mta_sts_mode
    refs = mta_sts_mode_evidence(info, mode) if mode in {"enforce", "testing", "none"} else ()
    txt_refs = mta_sts_txt_evidence(info)
    declared = SVC_MTA_STS in info.services or bool({"mta-sts", "mta-sts-enforce"} & set(info.slugs))
    if not observed.mta_sts_available:
        state: ExposureIndexState = "unavailable"
        points = 0
        scope = ("dns:mta_sts", "http:mta_sts_policy")
    elif mode in {"enforce", "testing", "none"} and refs:
        state = "observed_value"
        points = _maximum(component_id) if mode == "enforce" else MTA_STS_TESTING_POINTS if mode == "testing" else 0
        scope = ("dns:mta_sts", "http:mta_sts_policy")
    elif mode is None and not txt_refs and not declared:
        state = "observed_empty"
        points = 0
        scope = ("dns:mta_sts",)
    else:
        state = "unresolved"
        points = 0
        scope = ("dns:mta_sts", "http:mta_sts_policy")
    state = _hypothetical_state(component_id, state, hypothetical_components)
    return _component(
        component_id,
        state,
        points,
        _ComponentProof(
            dependencies=(_dependency("mta_sts_mode", mode, mode),),
            scope=scope,
            evidence=refs or txt_refs,
        ),
    )


def _record_component(
    info: TenantInfo,
    observed_available: bool,
    hypothetical_components: frozenset[str],
    rule: _RecordComponentRule,
) -> ExposureIndexComponent:
    component_id = rule.component_id
    maximum_points = _maximum(component_id)
    records = _records(
        info,
        source_types=rule.source_types,
        rule_names=rule.rule_names,
        slugs=rule.slugs,
    )
    record_observed = bool(records)
    if not observed_available:
        state: ExposureIndexState = "unavailable"
    elif record_observed:
        state = "observed_value"
    else:
        declared_slugs = rule.declared_slugs or rule.slugs or frozenset()
        declared_services = rule.rule_names or frozenset()
        if component_id == CAA_COMPONENT_ID:
            caa_detections = get_caa_patterns()
            declared_slugs = declared_slugs | frozenset(detection.slug for detection in caa_detections)
            declared_services = declared_services | frozenset(detection.name for detection in caa_detections)
        declared_by_slug = bool(declared_slugs & set(info.slugs))
        declared_by_service = bool(declared_services & set(info.services))
        declared = declared_by_slug or declared_by_service
        state = "unresolved" if declared else "observed_empty"
    state = _hypothetical_state(component_id, state, hypothetical_components)
    return _component(
        component_id,
        state,
        maximum_points if record_observed and observed_available else 0,
        _ComponentProof(
            dependencies=(_dependency(rule.metadata_field, record_observed, record_observed),),
            scope=(rule.scope,),
            evidence=evidence_refs(records),
        ),
    )


def _identity_component(
    info: TenantInfo,
    hypothetical_components: frozenset[str],
) -> ExposureIndexComponent:
    from recon_tool.collection_view import auth_type_channel_unavailable

    component_id = FEDERATED_IDENTITY_COMPONENT_ID
    matching_records = tuple(
        record
        for record in info.evidence
        if record.source_type.upper() == "HTTP"
        and record.rule_name == "GetUserRealm"
        and record.slug == "microsoft365"
        and record.raw_value == f"NameSpaceType={info.auth_type}"
    )
    unavailable = auth_type_channel_unavailable(info.degraded_sources)
    if unavailable:
        state: ExposureIndexState = "unavailable"
    elif info.auth_type in {"Federated", "Managed"} and matching_records:
        state = "observed_value"
    else:
        state = "unresolved"
    state = _hypothetical_state(component_id, state, hypothetical_components)
    points = _maximum(component_id) if info.auth_type == "Federated" and matching_records and not unavailable else 0
    return _component(
        component_id,
        state,
        points,
        _ComponentProof(
            dependencies=(_dependency("auth_type", info.auth_type, info.auth_type),),
            scope=("identity:user_realm",),
            evidence=evidence_refs(matching_records),
        ),
    )


def _gateway_component(
    info: TenantInfo,
    observed: ObservableEmailState,
    hypothetical_components: frozenset[str],
) -> ExposureIndexComponent:
    component_id = EMAIL_GATEWAY_COMPONENT_ID
    gateway_records = tuple(
        record for record in info.evidence if record.source_type.upper() == "MX" and record.slug in EMAIL_GATEWAY_SLUGS
    )
    evidence_gateway = (
        " + ".join(sorted({EMAIL_GATEWAY_SLUGS[record.slug] for record in gateway_records}))
        if gateway_records
        else None
    )
    exact = evidence_gateway is not None and evidence_gateway == info.email_gateway
    if not observed.gateway_available:
        state: ExposureIndexState = "unavailable"
    elif exact:
        state = "observed_value"
    else:
        state = "unresolved"
    state = _hypothetical_state(component_id, state, hypothetical_components)
    return _component(
        component_id,
        state,
        _maximum(component_id) if exact and observed.gateway_available else 0,
        _ComponentProof(
            dependencies=(
                _dependency("gateway_mx_observed", bool(gateway_records), bool(gateway_records)),
                _dependency("email_gateway", info.email_gateway, info.email_gateway),
            ),
            scope=("dns:mx",),
            evidence=evidence_refs(gateway_records),
        ),
    )


def compute_exposure_index(
    info: TenantInfo,
    *,
    hypothetical_components: frozenset[str] = frozenset(),
) -> ExposureIndex:
    """Build the complete weighted ledger from collection-observable evidence."""
    from recon_tool.collection_view import collection_claim_info

    unknown_hypotheticals = hypothetical_components - EXPOSURE_COMPONENT_IDS
    if unknown_hypotheticals:
        raise ValueError("unsupported hypothetical exposure component(s): " + ", ".join(sorted(unknown_hypotheticals)))

    observed_info = collection_claim_info(info)
    observed = ObservableEmailState.from_info(observed_info)
    hypothetical_info = (
        collection_claim_info(replace(info, degraded_sources=())) if hypothetical_components else observed_info
    )
    hypothetical_observed = ObservableEmailState.from_info(hypothetical_info)

    def component_input(component_id: str) -> tuple[TenantInfo, ObservableEmailState]:
        if component_id in hypothetical_components:
            return hypothetical_info, hypothetical_observed
        return observed_info, observed

    dmarc_info, dmarc_observed = component_input(DMARC_COMPONENT_ID)
    dkim_info, dkim_observed = component_input(DKIM_COMPONENT_ID)
    spf_info, spf_observed = component_input(SPF_COMPONENT_ID)
    mta_sts_info, mta_sts_observed = component_input(MTA_STS_COMPONENT_ID)
    bimi_info, bimi_observed = component_input(BIMI_COMPONENT_ID)
    tls_rpt_info, tls_rpt_observed = component_input(TLS_RPT_COMPONENT_ID)
    caa_info, caa_observed = component_input(CAA_COMPONENT_ID)
    identity_info, _ = component_input(FEDERATED_IDENTITY_COMPONENT_ID)
    gateway_info, gateway_observed = component_input(EMAIL_GATEWAY_COMPONENT_ID)
    record_component_inputs = (
        (bimi_info, bimi_observed.bimi_available, _BIMI_RECORD_RULE),
        (tls_rpt_info, tls_rpt_observed.tls_rpt_available, _TLS_RPT_RECORD_RULE),
        (caa_info, caa_observed.caa_available, _CAA_RECORD_RULE),
    )
    components = (
        _dmarc_component(dmarc_info, dmarc_observed, hypothetical_components),
        _dkim_component(dkim_info, dkim_observed, hypothetical_components),
        _spf_component(spf_info, spf_observed, hypothetical_components),
        _mta_sts_component(mta_sts_info, mta_sts_observed, hypothetical_components),
        *(
            _record_component(record_info, available, hypothetical_components, rule)
            for record_info, available, rule in record_component_inputs
        ),
        _identity_component(identity_info, hypothetical_components),
        _gateway_component(gateway_info, gateway_observed, hypothetical_components),
    )
    index = ExposureIndex(components)
    emitted_hypotheticals = frozenset(
        component.component_id for component in components if component.state == "hypothetical_value"
    )
    if emitted_hypotheticals != hypothetical_components:
        missing = hypothetical_components - emitted_hypotheticals
        raise ValueError(
            "hypothetical exposure components require internally consistent asserted evidence: "
            + ", ".join(sorted(missing))
        )
    return index


__all__ = ["compute_exposure_index"]
