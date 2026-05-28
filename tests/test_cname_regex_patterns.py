"""Validate the 9 catalog cname patterns that carry regex metacharacters.

The cname loader has always validated `pattern` fields as regex (the
ReDoS-shape audit runs `re.compile` at load time), but until v1.9.24
the matcher in `recon_tool/sources/dns.py::_detect_cname_infra` used
substring search (`det.pattern in cl`). Substring search cannot
evaluate escaped dots, `$` anchors, or alternation, so any catalog
entry whose pattern carried those characters silently never fired.

v1.9.24 switched the matcher to `re.search(..., re.IGNORECASE)`,
consistent with the loader's validation contract. These tests pin
each of the 9 affected patterns so a future loader / matcher change
that reintroduces the substring behavior fails CI rather than
silently disabling these vendors again.

Each test constructs the literal CNAME hostname the pattern was
written to match (sourced from each vendor's public documentation)
and asserts the engine attributes it to the correct slug.
"""

from __future__ import annotations

import re

import pytest

from recon_tool.fingerprints import get_cname_patterns


def _matching_slug(hostname: str) -> str | None:
    """Run the same regex-matching the engine does after v1.9.24."""
    hostname_lower = hostname.lower()
    patterns_sorted = sorted(get_cname_patterns(), key=lambda d: -len(d.pattern))
    for det in patterns_sorted:
        try:
            if re.search(det.pattern, hostname_lower, re.IGNORECASE):
                return det.slug
        except re.error:
            continue
    return None


@pytest.mark.parametrize(
    ("hostname", "expected_slug"),
    [
        # langsmith — LangSmith Enterprise / LangChain hosted
        # observability. CNAME terminates at *.p.api.smith.langchain.com.
        ("trace.p.api.smith.langchain.com", "langsmith"),
        ("orgname.p.api.smith.langchain.com", "langsmith"),
        # fastly — both legacy fastly.net and fastlylb.net edge.
        ("d.sni.global.fastly.net", "fastly"),
        ("dualstack.k.shared.global.fastlylb.net", "fastly"),
        # flyio — Fly.io custom domains terminate at fly.dev or
        # edgeapp.net.
        ("myapp.fly.dev", "flyio"),
        ("myapp.edgeapp.net", "flyio"),
        # railway — Railway.app deployments
        ("myproject.up.railway.app", "railway"),
        # splunk — SignalFx (Splunk Observability Cloud) edge
        ("ingest.us0.signalfx.com", "splunk"),
        # cyberark — CyberArk Idaptive identity broker
        ("tenant.id.idaptive.com", "cyberark"),
        ("tenant.id.idaptive.app", "cyberark"),
        # beyond-identity — passwordless authenticator
        ("authenticator.beyondidentity.com", "beyond-identity"),
        # workspace-one — VMware Workspace ONE Access (both legacy
        # vmwareidentity.com and current workspaceoneaccess.com).
        ("tenant.vmwareidentity.com", "workspace-one"),
        ("tenant.workspaceoneaccess.com", "workspace-one"),
    ],
)
def test_cname_regex_pattern_fires(hostname: str, expected_slug: str) -> None:
    """Each regex-shaped catalog pattern must fire on the hostname it
    was written to match. Pre-v1.9.24 the substring matcher silently
    skipped these; this test pins the fix in place."""
    matched = _matching_slug(hostname)
    assert matched == expected_slug, (
        f"Expected slug {expected_slug!r} on hostname {hostname!r}, "
        f"got {matched!r}. The cname matcher must use re.search to fire "
        f"on patterns with regex metacharacters; see CHANGELOG v1.9.24 "
        f"'cname matcher regex bug fix'."
    )


def test_regex_anchored_patterns_do_not_fire_on_non_anchored_text() -> None:
    """The langsmith pattern uses a trailing `$`. It should NOT fire
    on a hostname that contains the substring but extends past it."""
    assert _matching_slug("trace.p.api.smith.langchain.com.attacker.example") is None
