"""Derived connection_map: grouped vendors, empty lanes, related-host classes."""

from __future__ import annotations

import json

from recon_tool.formatter.connection_map import (
    HOST_CLASS_PREFIXES,
    OTHER_HOST_CLASS,
    build_connection_map,
    first_sentence,
    host_class_prefix,
    lane_id,
)
from recon_tool.formatter.markdown import format_tenant_markdown
from recon_tool.formatter.serialize import format_tenant_dict
from recon_tool.models import ConfidenceLevel, EvidenceRecord, SurfaceAttribution, TenantInfo


def _info(**overrides: object) -> TenantInfo:
    defaults: dict[str, object] = {
        "tenant_id": None,
        "display_name": "Synthetic Map Ltd",
        "default_domain": "map.invalid",
        "queried_domain": "map.invalid",
        "confidence": ConfidenceLevel.HIGH,
        "sources": ("dns_records", "oidc"),
        "services": (),
        "slugs": (),
    }
    defaults.update(overrides)
    return TenantInfo(**defaults)  # type: ignore[arg-type]


def test_lane_id_slugifies_ampersand_labels() -> None:
    assert lane_id("AI") == "ai"
    assert lane_id("Data & Analytics") == "data-analytics"
    assert lane_id("Business Apps") == "business-apps"


def test_first_sentence_stops_at_period() -> None:
    assert first_sentence("First sentence. Second sentence.") == "First sentence."
    assert first_sentence("") == ""
    assert first_sentence("No terminator") == "No terminator"


def test_host_class_prefix_matches_longest_routing_label() -> None:
    assert host_class_prefix("auth.map.invalid") == "auth."
    assert host_class_prefix("loyalty-app.map.invalid") == "loyalty-"
    assert host_class_prefix("shop.map.invalid") == "shop."
    assert host_class_prefix("workday.map.invalid") == "workday."
    assert host_class_prefix("developer.map.invalid") == "developer."
    assert host_class_prefix("community-prod.map.invalid") == "community-"
    assert host_class_prefix("mystery.map.invalid") == OTHER_HOST_CLASS
    assert "auth." in HOST_CLASS_PREFIXES


def test_empty_ai_lane_stays_visible_and_is_unresolved() -> None:
    info = _info(
        services=("Microsoft 365", "DMARC"),
        slugs=("microsoft365",),
        evidence=(EvidenceRecord("MX", "10 map-mail.invalid", "Microsoft 365", "microsoft365"),),
    )
    cmap = build_connection_map(info)
    lanes = {lane["id"]: lane for lane in cmap["lanes"]}
    assert set(lanes) >= {"email", "ai", "identity", "security"}
    assert lanes["ai"]["entries"] == []
    assert any(entry["name"] == "Microsoft 365" for entry in lanes["email"]["entries"])
    assert cmap["explicit_absences"]["email_gateway"] is None


def test_role_unavailable_match_is_kept() -> None:
    info = _info(
        services=("Okta SSO hub",),
        slugs=("okta-sso-hub",),
        evidence=(),
    )
    cmap = build_connection_map(info)
    identity = next(lane for lane in cmap["lanes"] if lane["id"] == "identity")
    assert identity["entries"], "unattributed Okta hub must stay on the machine face"
    hub = next(entry for entry in identity["entries"] if "Okta" in entry["name"])
    assert hub["role"] == "unavailable"
    assert hub["slug"] == "okta-sso-hub"


def test_auth_host_attribution_lands_on_auth0() -> None:
    info = _info(
        services=("Auth0",),
        slugs=("auth0",),
        related_domains=("auth.map.invalid", "shop.map.invalid", "random.map.invalid"),
        evidence=(EvidenceRecord("CNAME", "auth.map.invalid", "Auth0", "auth0"),),
        surface_attributions=(
            SurfaceAttribution(
                subdomain="auth.map.invalid",
                primary_slug="auth0",
                primary_name="Auth0",
                primary_tier="application",
            ),
        ),
    )
    cmap = build_connection_map(info)
    identity = next(lane for lane in cmap["lanes"] if lane["id"] == "identity")
    auth0 = next(entry for entry in identity["entries"] if entry["slug"] == "auth0")
    assert auth0["hosts"] == ["auth.map.invalid"]
    assert auth0["role"] != "unavailable"
    classes = {item["prefix"]: item for item in cmap["related_host_classes"]}
    assert classes["auth."]["hosts"] == ["auth.map.invalid"]
    assert classes["auth."]["primary_slugs"] == ["auth0"]
    assert classes["shop."]["hosts"] == ["shop.map.invalid"]
    assert classes[OTHER_HOST_CLASS]["hosts"] == ["random.map.invalid"]


def test_microsoft365_summary_follows_role_not_a_later_cname_file() -> None:
    info = _info(
        services=("Microsoft 365",),
        slugs=("microsoft365",),
        evidence=(EvidenceRecord("MX", "10 map-mail.invalid", "Microsoft 365", "microsoft365"),),
    )
    cmap = build_connection_map(info)
    email = next(lane for lane in cmap["lanes"] if lane["id"] == "email")
    m365 = next(entry for entry in email["entries"] if entry["slug"] == "microsoft365")
    assert m365["role"] == "MX delivery path"
    assert "summary" in m365
    assert "Mira" not in m365["summary"]


def test_openai_summary_is_the_catalog_first_sentence() -> None:
    info = _info(
        services=("OpenAI Enterprise",),
        slugs=("openai",),
        evidence=(EvidenceRecord("TXT", "openai-domain-verification=abc", "OpenAI Enterprise", "openai"),),
    )
    cmap = build_connection_map(info)
    ai = next(lane for lane in cmap["lanes"] if lane["id"] == "ai")
    openai = next(entry for entry in ai["entries"] if entry["slug"] == "openai")
    assert openai["role"] == "public TXT account indicator"
    assert "summary" in openai
    assert "ChatGPT" in openai["summary"] or "OpenAI" in openai["summary"]
    assert "Mira" not in openai["summary"]
    assert openai["summary"].endswith(".")


def test_json_envelope_always_emits_connection_map() -> None:
    payload = format_tenant_dict(_info())
    assert "connection_map" in payload
    assert {lane["id"] for lane in payload["connection_map"]["lanes"]} == {
        "email",
        "identity",
        "cloud",
        "security",
        "ai",
        "data-analytics",
        "collaboration",
        "business-apps",
    }


def test_default_md_groups_lanes_and_omits_empty() -> None:
    info = _info(
        services=("Microsoft 365", "OpenAI Enterprise", "Slack"),
        slugs=("microsoft365", "openai", "slack"),
        evidence=(
            EvidenceRecord("MX", "10 map-mail.invalid", "Microsoft 365", "microsoft365"),
            EvidenceRecord("TXT", "openai-domain-verification=abc", "OpenAI Enterprise", "openai"),
            EvidenceRecord("TXT", "slack-domain-verification=abc", "Slack", "slack"),
        ),
    )
    md = format_tenant_markdown(info)
    assert "## Email" in md
    assert "## AI" in md
    assert "## Collaboration" in md
    assert "## Tech Stack" not in md
    assert "Microsoft 365 Services" not in md
    assert "*none observed in public DNS*" not in md


def test_full_md_keeps_empty_lanes_roles_and_host_classes() -> None:
    info = _info(
        services=("Microsoft 365", "Okta SSO hub"),
        slugs=("microsoft365", "okta-sso-hub"),
        related_domains=("auth.map.invalid", "login.map.invalid"),
        evidence=(EvidenceRecord("MX", "10 map-mail.invalid", "Microsoft 365", "microsoft365"),),
        surface_attributions=(
            SurfaceAttribution(
                subdomain="auth.map.invalid",
                primary_slug="auth0",
                primary_name="Auth0",
                primary_tier="application",
            ),
        ),
        mta_sts_mode=None,
    )
    md = format_tenant_markdown(info, full=True)
    assert "## AI" in md
    assert "*none observed in public DNS*" in md
    assert "## Related Host Classes" in md
    assert "auth" in md.replace("\\", "")
    assert "login" in md.replace("\\", "")
    assert "map.invalid" in md.replace("\\", "")
    assert "use --md --full to see all" not in md
    assert "(MX delivery path)" in md or "Microsoft 365" in md


def test_emitted_json_matches_connection_map_schema() -> None:
    from pathlib import Path

    from jsonschema import Draft202012Validator

    schema = json.loads(
        (Path(__file__).resolve().parents[1] / "docs" / "recon-schema.json").read_text(encoding="utf-8")
    )
    payload = format_tenant_dict(
        _info(
            services=("OpenAI Enterprise", "Okta SSO hub"),
            slugs=("openai", "okta-sso-hub"),
            related_domains=("auth.map.invalid", "developer.map.invalid"),
            evidence=(EvidenceRecord("TXT", "openai-domain-verification=abc", "OpenAI Enterprise", "openai"),),
            mta_sts_mode=None,
        )
    )
    Draft202012Validator(schema).validate(payload)
    cmap = payload["connection_map"]
    ai = next(lane for lane in cmap["lanes"] if lane["id"] == "ai")
    assert ai["entries"][0]["slug"] == "openai"
    identity = next(lane for lane in cmap["lanes"] if lane["id"] == "identity")
    hub = next(entry for entry in identity["entries"] if entry["slug"] == "okta-sso-hub")
    assert hub["role"] == "unavailable"
    prefixes = {item["prefix"] for item in cmap["related_host_classes"]}
    assert "auth." in prefixes
    assert "developer." in prefixes


def test_full_panel_classifies_related_hosts() -> None:
    from rich.console import Console

    from recon_tool.formatter import render_tenant_panel

    info = _info(
        related_domains=("auth.map.invalid", "shop.map.invalid"),
        services=("Auth0",),
        slugs=("auth0",),
        evidence=(EvidenceRecord("CNAME", "auth.map.invalid", "Auth0", "auth0"),),
        surface_attributions=(
            SurfaceAttribution(
                subdomain="auth.map.invalid",
                primary_slug="auth0",
                primary_name="Auth0",
                primary_tier="application",
            ),
        ),
    )
    console = Console(no_color=True, record=True, width=120)
    console.print(render_tenant_panel(info, show_domains=True))
    out = console.export_text()
    assert "Related host classes" in out
    assert "auth." in out
    assert "shop." in out
    assert "Related domains\n" not in out
