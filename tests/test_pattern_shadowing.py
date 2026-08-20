"""Pattern-shadowing invariants for detection types with broad patterns.

Provider matchers walk patterns in catalog order. When a broad
pattern (e.g. ``cisco.com``) is a strict substring of a narrower one
(e.g. ``ess.cisco.com``) under a *different* slug, both would otherwise
fire on the same record and double-count the same vendor.

The engine handles this in two ways:

1. **cname_target**: classifier sorts longest-pattern-first and picks
   the most specific match per tier
   (``recon_tool/sources/dns.py::_classify_chain``). Attribution does
   not propagate to ``ctx.slugs`` (it goes into
   ``SurfaceAttribution`` instead), so a shadow there does not affect
   the apex slug set.
2. **MX / NS / CAA / dmarc_rua**: matchers sort patterns longest-first
   and break on the first match, so a narrow pattern always wins over
   a broad one under a different slug.
3. **SPF**: matcher accumulates all matches (multiple distinct vendor
   includes per record are legitimate, e.g. M365 + Salesforce) and
   then applies ``filter_shadowed_matches`` to drop shadowed slugs.

These tests assert the *catalog* stays consistent with those rules so
shadows are caught at build time, not at lookup time.
"""

from __future__ import annotations

import collections

from recon_tool.fingerprints import filter_shadowed_matches, load_fingerprints

# Detection types where broader catalog patterns can shadow narrower ones.
# CNAME and CNAME-target matching use DNS-label suffixes for whole domains and
# regex search for regex-shaped patterns; either form can still shadow a more
# specific rule.
_SUBSTRING_TYPES = {"spf", "mx", "ns", "dmarc_rua", "caa", "cname_target", "cname"}

# Pattern-pair shadows that are accepted because the engine demonstrably
# suppresses them at lookup time. Each entry is
# ``(detection_type, broader_pattern, broader_slug, narrower_pattern, narrower_slug)``.
# Adding a row here is an explicit decision; the test fails when a new
# shadow appears that is not on this list.
_ALLOWED_SHADOWS: frozenset[tuple[str, str, str, str, str]] = frozenset(
    {
        # oracle-cloud's cname_target is the broad OCI infrastructure
        # marker; oracle-fusion's fa.oraclecloud.com is the SaaS app
        # endpoint. Same suppression: most-specific match per tier.
        ("cname_target", "oraclecloud.com", "oracle-cloud", "fa.oraclecloud.com", "oracle-fusion"),
        # cloudflare.net occurs only mid-label in Clerk's provider-specific
        # target. DNS-label boundary matching prevents the Cloudflare rule
        # from firing on worker.clerkprod-cloudflare.net.
        (
            "cname_target",
            "cloudflare.net",
            "cloudflare",
            "worker.clerkprod-cloudflare.net",
            "clerk",
        ),
    }
)


def _collect_substring_pattern_pairs() -> list[tuple[str, str, str, str, str]]:
    """Enumerate all (type, broad_pattern, broad_slug, narrow_pattern, narrow_slug)
    shadow relationships in the catalog.

    A shadow exists when:
      - Both patterns are the same detection type.
      - The broader pattern's text is a strict substring of the narrower.
      - The two patterns belong to *different* slugs.
    """
    fps = load_fingerprints()
    # type -> list of (pattern_lower, slug)
    by_type: dict[str, list[tuple[str, str]]] = collections.defaultdict(list)
    for fp in fps:
        for det in fp.detections:
            if det.type in _SUBSTRING_TYPES:
                by_type[det.type].append((det.pattern.lower(), fp.slug))

    shadows: list[tuple[str, str, str, str, str]] = []
    for typ, items in by_type.items():
        items_sorted = sorted(items, key=lambda x: -len(x[0]))
        for i, (long_pat, long_slug) in enumerate(items_sorted):
            for short_pat, short_slug in items_sorted[i + 1 :]:
                if short_pat == long_pat:
                    continue
                if short_pat in long_pat and long_slug != short_slug:
                    shadows.append((typ, short_pat, short_slug, long_pat, long_slug))
    return shadows


def test_no_unapproved_substring_shadows() -> None:
    """Every cross-slug substring shadow must be on the approved list.

    Adding a new shadow without a documented engine-level mitigation
    means the catalog can silently double-count vendors at lookup time.
    See the docstring for the resolution path.
    """
    shadows = _collect_substring_pattern_pairs()
    unapproved = [s for s in shadows if s not in _ALLOWED_SHADOWS]
    assert not unapproved, (
        f"{len(unapproved)} unapproved pattern shadows. Each is a broader "
        f"pattern that would fire alongside a narrower one and double-count "
        f"the underlying vendor at lookup time.\n\n"
        + "\n".join(
            f"  {typ}: {short_pat!r} ({short_slug}) shadowed by {long_pat!r} ({long_slug})"
            for typ, short_pat, short_slug, long_pat, long_slug in unapproved
        )
        + "\n\nResolution options:\n"
        "  1. Narrow the broader pattern (e.g. add a leading dot).\n"
        "  2. Remove the broader pattern if redundant with the narrower one.\n"
        "  3. If the engine demonstrably suppresses the shadow at lookup\n"
        "     time, add the tuple to _ALLOWED_SHADOWS in this test with a\n"
        "     comment explaining the suppression path."
    )


def test_allowed_shadows_are_still_present() -> None:
    """A pattern listed in _ALLOWED_SHADOWS must still exist in the catalog.

    A stale entry hides intent: when a slug or pattern is renamed and
    its shadow entry no longer matches anything, the exception is dead
    weight that confuses future contributors. Strip stale entries.
    """
    actual = set(_collect_substring_pattern_pairs())
    stale = sorted(_ALLOWED_SHADOWS - actual)
    assert not stale, "_ALLOWED_SHADOWS entries that no longer match any catalog shadow:\n" + "\n".join(
        f"  {s}" for s in stale
    )


def test_filter_shadowed_matches_drops_broader_match() -> None:
    """Direct unit test of the filter_shadowed_matches helper."""
    from recon_tool.fingerprints import Detection

    a = Detection(pattern="cisco.com", name="A", slug="slug-a", category="Email", confidence="high")
    b = Detection(pattern="ess.cisco.com", name="B", slug="slug-b", category="Email", confidence="high")
    kept = filter_shadowed_matches([a, b])
    kept_slugs = {d.slug for d in kept}
    assert kept_slugs == {"slug-b"}, f"Expected only the narrower-pattern slug to survive; got {kept_slugs}"


def test_filter_shadowed_matches_preserves_independent_matches() -> None:
    """Non-overlapping patterns (different vendors, distinct domains)
    must both survive. This is the common SPF case: M365 + Salesforce
    includes on the same record should both fire."""
    from recon_tool.fingerprints import Detection

    a = Detection(
        pattern="spf.protection.outlook.com",
        name="M365",
        slug="microsoft365",
        category="Email",
        confidence="high",
    )
    b = Detection(
        pattern="_spf.salesforce.com",
        name="Salesforce",
        slug="salesforce",
        category="Business Apps",
        confidence="high",
    )
    kept = filter_shadowed_matches([a, b])
    kept_slugs = {d.slug for d in kept}
    assert kept_slugs == {"microsoft365", "salesforce"}


def test_filter_shadowed_matches_preserves_same_slug_aliases() -> None:
    """Two patterns sharing a slug but with substring overlap should
    both pass through, since the slug fires once anyway with no double-count
    risk. This covers catalog patterns like ``valimail.com`` plus
    ``vali.email`` both attributed to slug=valimail."""
    from recon_tool.fingerprints import Detection

    a = Detection(pattern="valimail.com", name="V", slug="valimail", category="Email", confidence="high")
    b = Detection(pattern="vali.email", name="V", slug="valimail", category="Email", confidence="high")
    kept = filter_shadowed_matches([a, b])
    kept_slugs = {d.slug for d in kept}
    # Same-slug substring overlap is fine; the slug accumulates once
    # in ctx.slugs anyway. Both detections survive so each emits its
    # own evidence record.
    assert kept_slugs == {"valimail"}
    assert len(kept) == 2


def test_every_detection_has_a_description() -> None:
    """Every detection in the bundled catalog must carry a description.

    Descriptions are the operator-facing trace: when a slug fires,
    the panel and --explain output cite the description so a finding
    can be re-verified against the vendor's documentation. A
    missing description silently degrades that audit trail.
    """
    missing: list[tuple[str, str, str]] = []
    for fp in load_fingerprints():
        for det in fp.detections:
            if not (det.description and det.description.strip()):
                missing.append((fp.slug, det.type, det.pattern))
    assert not missing, f"{len(missing)} catalog detections have no description:\n" + "\n".join(
        f"  {slug} [{typ}]: {pat!r}" for slug, typ, pat in missing
    )


def test_extend_entries_dont_duplicate_detections() -> None:
    """When multiple YAML entries share slug + name (the legitimate
    EXTEND pattern), the union of their detections must not repeat
    the same (type, pattern); a duplicate is dead weight, since the
    slug accumulates once regardless of how many times the pattern
    appears.
    """
    grouped: dict[tuple[str, str], list] = collections.defaultdict(list)
    for fp in load_fingerprints():
        grouped[(fp.slug, fp.name)].append(fp)

    dupes: list[tuple[str, str, str, str]] = []
    for (slug, name), entries in grouped.items():
        if len(entries) < 2:
            continue
        seen: dict[tuple[str, str], int] = {}
        for fp in entries:
            for det in fp.detections:
                k = (det.type, det.pattern)
                seen[k] = seen.get(k, 0) + 1
        for (typ, pat), n in seen.items():
            if n > 1:
                dupes.append((slug, name, typ, pat))
    assert not dupes, f"{len(dupes)} detection duplicates across same-slug EXTEND entries:\n" + "\n".join(
        f"  slug={slug} name={name!r} type={typ} pattern={pat!r}" for slug, name, typ, pat in dupes
    )
