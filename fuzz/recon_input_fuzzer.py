"""ClusterFuzzLite entry point for recon parser and serializer boundaries."""

from __future__ import annotations

import json
import re
import sys
from contextlib import suppress

from recon_tool.cache import tenant_info_from_dict, tenant_info_to_dict
from recon_tool.formatter_serialize import format_tenant_dict
from recon_tool.models import ConfidenceLevel, EvidenceRecord, TenantInfo, UnclassifiedCnameChain
from recon_tool.validator import is_safe_dns_name, strip_control_chars, validate_domain

_LABEL_RE = re.compile(r"[^a-z0-9-]+")


def _text(data: bytes) -> str:
    return data.decode("utf-8", "ignore")[:500]


def _label(value: str) -> str:
    label = _LABEL_RE.sub("-", strip_control_chars(value, max_len=80).lower()).strip("-")
    if not label or not label[0].isalnum() or not label[-1].isalnum():
        return "fuzz"
    return label[:40]


def _tokens(value: str) -> tuple[str, ...]:
    tokens = [_label(part) for part in re.split(r"[\s,;:/?#@]+", value)]
    return tuple(dict.fromkeys(token for token in tokens if token))[:8] or ("fuzz",)


def _exercise_domain_boundary(value: str) -> None:
    strip_control_chars(value)
    is_safe_dns_name(value)
    for candidate in (value, f"{_label(value)}.example", f"https://www.{_label(value)}.example/path?q=1"):
        with suppress(ValueError):
            validate_domain(candidate, apex=False)


def _tenant_from_text(value: str) -> TenantInfo:
    tokens = _tokens(value)
    label = _label(value)
    slugs = tuple(f"fuzz-{token}" for token in tokens[:4])
    services = tuple(token.replace("-", " ").title() for token in tokens[:4])
    evidence = tuple(
        EvidenceRecord(
            source_type="TXT",
            raw_value=strip_control_chars(token, max_len=120),
            rule_name="fuzz-boundary",
            slug=slug,
        )
        for token, slug in zip(tokens, slugs, strict=False)
    )
    return TenantInfo(
        tenant_id=None,
        display_name=strip_control_chars(value, max_len=80) or "Fuzz Org",
        default_domain=f"{label}.example",
        queried_domain=f"{label}.example",
        confidence=ConfidenceLevel.MEDIUM,
        sources=("fuzz",),
        services=services,
        slugs=slugs,
        evidence=evidence,
        domain_count=min(len(tokens), 8),
        tenant_domains=tuple(f"{token}.example" for token in tokens[:4]),
        related_domains=tuple(f"rel-{token}.example" for token in tokens[:4]),
        unclassified_cname_chains=(
            UnclassifiedCnameChain(
                subdomain=f"app.{label}.example",
                chain=(f"app.{label}.example", f"{tokens[0]}.example.net"),
            ),
        ),
    )


def _exercise_serializers(value: str) -> None:
    info = _tenant_from_text(value)
    cache_payload = tenant_info_to_dict(info)
    tenant_info_from_dict(cache_payload)
    rendered_payload = format_tenant_dict(info, include_unclassified=True)
    json.dumps(rendered_payload, sort_keys=True)


def TestOneInput(data: bytes) -> None:
    value = _text(data)
    _exercise_domain_boundary(value)
    _exercise_serializers(value)


def main() -> None:
    import atheris

    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
