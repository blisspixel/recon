"""Validation hygiene guard regressions."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from scripts import check_validation_hygiene


def _write(root: Path, relative: str, text: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_file_inventory_includes_nonignored_untracked_files(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        assert argv == [
            *check_validation_hygiene.GIT_FILE_INVENTORY_ARGS,
        ]
        assert kwargs["cwd"] == tmp_path
        return subprocess.CompletedProcess(argv, 0, stdout="tracked.md\0untracked.md\0", stderr="")

    monkeypatch.setattr(check_validation_hygiene.subprocess, "run", fake_run)

    assert check_validation_hygiene._tracked_files(tmp_path) == ["tracked.md", "untracked.md"]


@pytest.mark.parametrize(
    "parts",
    [
        ("con", "toso"),
        ("fab", "rikam"),
        ("north", "wind"),
        ("north", "windtraders"),
        ("ada", "tum"),
        ("adventure", "-works"),
        ("tailspin", "toys"),
        ("wingtip", "toys"),
        ("woodgrove", "bank"),
        ("lit", "ware"),
        ("lucerne", " publishing"),
        ("pro", "ware"),
        ("humongous", " insurance"),
        ("trey", "research"),
        ("graphic design", " institute"),
        ("consolidated", " messenger"),
    ],
)
def test_retired_target_brand_fails_outside_validation(parts: tuple[str, str], tmp_path: Path) -> None:
    marker = "".join(parts)
    path = "docs/tutorial.md"
    _write(tmp_path, path, f"Run `recon {marker}.invalid` locally.\n")

    violations = check_validation_hygiene.find_violations(tmp_path, [path])

    assert [violation.detail for violation in violations] == ["retired target-example identity is tracked"]
    assert marker not in violations[0].render().casefold()


def test_retired_placeholder_name_fails_but_acme_protocol_passes(tmp_path: Path) -> None:
    placeholder = "".join(("Ac", "me"))
    target_path = "examples/sample.md"
    uppercase_target_path = "examples/uppercase-sample.md"
    protocol_path = "docs/protocol.md"
    _write(tmp_path, target_path, f"Display name: {placeholder} Corp\n")
    _write(tmp_path, uppercase_target_path, f"Display name: {placeholder.upper()} CORP\n")
    _write(
        tmp_path,
        protocol_path,
        "ACME validation uses `_acme-challenge` and `/.well-known/acme-challenge`.\n",
    )

    violations = check_validation_hygiene.find_violations(
        tmp_path,
        [target_path, uppercase_target_path, protocol_path],
    )

    assert [violation.path for violation in violations] == [target_path, uppercase_target_path]
    assert all(placeholder.casefold() not in violation.render().casefold() for violation in violations)


def test_retired_identity_in_path_is_redacted(tmp_path: Path) -> None:
    marker = "".join(("con", "toso"))
    path = f"docs/{marker}-sample.md"
    _write(tmp_path, path, "Reserved example only.\n")

    violations = check_validation_hygiene.find_violations(tmp_path, [path])

    assert [violation.render() for violation in violations] == [
        "[redacted]: retired target-example identity is tracked"
    ]


def test_private_run_paths_fail_even_if_forced_into_git(tmp_path: Path) -> None:
    paths = [
        "validation/live_runs/20260618/results.json",
        "validation/runs-private/20260618/results.json",
        "validation/corpus-private/saas.txt",
    ]

    violations = check_validation_hygiene.find_violations(tmp_path, paths)

    assert [violation.path for violation in violations] == paths
    assert all("private validation corpus or run output" in violation.detail for violation in violations)


def test_root_per_domain_json_dump_fails(tmp_path: Path) -> None:
    violations = check_validation_hygiene.find_violations(tmp_path, ["evaluated-target.localhost.json"])

    assert len(violations) == 1
    assert violations[0].path == "evaluated-target.localhost.json"
    assert "root per-domain JSON dump" in violations[0].detail


def test_generic_root_json_artifact_fails_closed(tmp_path: Path) -> None:
    _write(tmp_path, "report.json", '{"summary":"aggregate"}\n')

    violations = check_validation_hygiene.find_violations(tmp_path, ["report.json"])

    assert [violation.detail for violation in violations] == ["root per-domain JSON dump is tracked"]
    assert violations[0].render().startswith("[redacted]:")


def test_target_domain_fields_fail_in_committed_validation_artifact(tmp_path: Path) -> None:
    _write(tmp_path, "validation/new-calibration.md", "queried_domain: evaluated-target.localhost\n")

    violations = check_validation_hygiene.find_violations(tmp_path, ["validation/new-calibration.md"])

    assert len(violations) == 1
    assert violations[0].line == 1
    assert "target-domain field" in violations[0].detail
    assert "evaluated-target.localhost" not in violations[0].render()


def test_quoted_json_target_field_fails_in_synthetic_directory(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "validation/synthetic_corpus/fixtures/sample.json",
        '{"display_name": "Synthetic Scenario 001", "queried_domain": "evaluated-target.localhost"}\n',
    )

    violations = check_validation_hygiene.find_violations(
        tmp_path,
        ["validation/synthetic_corpus/fixtures/sample.json"],
    )

    assert any("queried_domain is not reserved or synthetic" in violation.detail for violation in violations)
    assert all("evaluated-target.localhost" not in violation.render() for violation in violations)


@pytest.mark.parametrize(
    "command",
    [
        "recon evaluated-target.localhost --json",
        "recon https://evaluated-target.localhost/path",
        "recon lookup evaluated-target.localhost",
        "recon delta evaluated-target.localhost",
        "recon cache show evaluated-target.localhost",
        "recon cache clear evaluated-target.localhost",
        "recon --plain evaluated-target.localhost",
        "python -m recon_tool evaluated-target.localhost",
        "uv run recon evaluated-target.localhost",
    ],
)
def test_recon_example_with_real_domain_fails(command: str, tmp_path: Path) -> None:
    _write(tmp_path, "validation/new-runbook.md", f"Run `{command}` locally.\n")

    violations = check_validation_hygiene.find_violations(tmp_path, ["validation/new-runbook.md"])

    assert len(violations) == 1
    assert "recon example uses a non-reserved domain" in violations[0].detail


def test_batch_file_command_is_not_misread_as_single_domain_lookup(tmp_path: Path) -> None:
    path = "validation/new-runbook.md"
    _write(tmp_path, path, "Run `recon batch domains.txt --json` locally.\n")

    assert check_validation_hygiene.find_violations(tmp_path, [path]) == []


@pytest.mark.parametrize("marker", ["\\", "`", "^"])
def test_multiline_recon_commands_cannot_hide_target_domain(
    marker: str,
    tmp_path: Path,
) -> None:
    path = "validation/new-runbook.md"
    _write(tmp_path, path, f"recon {marker}\n  target.localhost --json\n")

    violations = check_validation_hygiene.find_violations(tmp_path, [path])

    assert any("recon example uses a non-reserved domain" in item.detail for item in violations)
    assert all("target.localhost" not in item.render() for item in violations)


def test_validation_corpus_lines_must_be_reserved_or_synthetic(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "validation/corpus-example.txt",
        "scenario.example.invalid\nexample.org\nevaluated-target.localhost\n",
    )

    violations = check_validation_hygiene.find_violations(tmp_path, ["validation/corpus-example.txt"])

    assert len(violations) == 1
    assert "corpus line is not reserved or synthetic" in violations[0].detail
    assert "evaluated-target.localhost" not in violations[0].render()


def test_synthetic_and_reserved_validation_artifacts_pass(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "validation/new-calibration.md",
        "queried_domain: scenario.example.invalid\nRun `recon example.com`.\n",
    )
    _write(
        tmp_path,
        "validation/synthetic_corpus/fixtures/sample.json",
        '{"display_name": "Synthetic Scenario 001", "queried_domain": "sample.example.invalid", '
        '"tenant_id": "synthetic-scenario-001"}\n',
    )

    violations = check_validation_hygiene.find_violations(
        tmp_path,
        ["validation/new-calibration.md", "validation/synthetic_corpus/fixtures/sample.json"],
    )

    assert violations == []


def test_ndjson_identity_fields_are_parsed_structurally(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "validation/aggregate/sample.ndjson",
        '{"display_name":"Synthetic Scenario 001","queried_domain":"safe.example.invalid"}\n'
        '{"display_name":"Synthetic Delta Corp","queried_domain":"evaluated-target.localhost"}\n',
    )

    violations = check_validation_hygiene.find_violations(
        tmp_path,
        ["validation/aggregate/sample.ndjson"],
    )

    assert {violation.detail for violation in violations} >= {
        "display_name is not a constrained synthetic sentinel",
        "queried_domain is not reserved or synthetic",
    }
    assert all(
        "Synthetic Delta" not in violation.render() and "evaluated-target.localhost" not in violation.render()
        for violation in violations
    )


def test_malformed_structured_artifact_cannot_bypass_scan(tmp_path: Path) -> None:
    _write(tmp_path, "validation/aggregate/broken.json", '{"queried_domain":')

    violations = check_validation_hygiene.find_violations(
        tmp_path,
        ["validation/aggregate/broken.json"],
    )

    assert [violation.detail for violation in violations] == ["structured validation artifact is not valid JSON"]


def test_non_utf8_validation_artifact_cannot_bypass_scan(tmp_path: Path) -> None:
    path = "validation/aggregate/broken.json"
    full_path = tmp_path / path
    full_path.parent.mkdir(parents=True, exist_ok=True)
    full_path.write_bytes(b"\xff\xfe")

    violations = check_validation_hygiene.find_violations(tmp_path, [path])

    assert [violation.detail for violation in violations] == ["validation artifact is not valid UTF-8"]


def test_tenant_uuid_and_verification_values_fail_without_echo(tmp_path: Path) -> None:
    uuid_value = "12345678-1234-1234-1234-123456789abc"
    verification_value = "MS=ms12345678"
    _write(
        tmp_path,
        "validation/agentic_ux/fixtures/sample.json",
        "{\n"
        '  "display_name": "Synthetic Scenario 001",\n'
        '  "queried_domain": "sample.example.invalid",\n'
        f'  "tenant_id": "{uuid_value}",\n'
        f'  "evidence": [{{"raw_value": "{verification_value}"}}]\n'
        "}\n",
    )

    violations = check_validation_hygiene.find_violations(
        tmp_path,
        ["validation/agentic_ux/fixtures/sample.json"],
    )

    details = {violation.detail for violation in violations}
    assert "tenant_id is not a constrained synthetic sentinel" in details
    assert "UUID-shaped identifier is tracked" in details
    assert "verification-token-shaped value is tracked" in details
    assert all(
        uuid_value not in violation.render() and verification_value not in violation.render()
        for violation in violations
    )


def test_nonempty_site_verification_tokens_fail(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "validation/agentic_ux/fixtures/sample.json",
        '{"display_name":"Synthetic Scenario 001","queried_domain":"sample.example.invalid",'
        '"site_verification_tokens":["redacted"]}\n',
    )

    violations = check_validation_hygiene.find_violations(
        tmp_path,
        ["validation/agentic_ux/fixtures/sample.json"],
    )

    assert any("site_verification_tokens" in violation.detail for violation in violations)


def test_explicit_synthetic_verification_sentinel_is_allowed(tmp_path: Path) -> None:
    path = "validation/agentic_ux/fixtures/sample.json"
    _write(
        tmp_path,
        path,
        '{"display_name":"Synthetic Scenario 001","queried_domain":"sample.example.invalid",'
        '"evidence":[{"raw_value":"ms-domain-verification=synthetic-token-001"}]}\n',
    )

    assert check_validation_hygiene.find_violations(tmp_path, [path]) == []


def test_null_tenant_identifier_is_allowed(tmp_path: Path) -> None:
    path = "validation/aggregate/sample.ndjson"
    _write(
        tmp_path,
        path,
        '{"display_name":"Synthetic Scenario 001","queried_domain":"sample.example.invalid","tenant_id":null}\n',
    )

    assert check_validation_hygiene.find_violations(tmp_path, [path]) == []


def test_candidate_skip_domain_detail_fails_but_provider_table_passes(tmp_path: Path) -> None:
    path = "validation/v9.9.9-candidates-triage.md"
    _write(
        tmp_path,
        path,
        "## Provider additions\n\n"
        "| Vendor | Pattern |\n"
        "|---|---|\n"
        "| Example CDN | provider.example.net |\n\n"
        "### SKIP (generic / ambiguous)\n\n"
        "one-off.target.localhost (1)\n",
    )

    violations = check_validation_hygiene.find_violations(tmp_path, [path])

    assert [violation.detail for violation in violations] == ["candidate SKIP detail retains a domain-shaped value"]


def test_candidate_skip_aggregate_reason_passes(tmp_path: Path) -> None:
    path = "validation/v9.9.9-candidates-triage.md"
    _write(
        tmp_path,
        path,
        "### SKIP\n\nIndividual candidates are not retained. Aggregate reasons: one-off 3, ambiguous 2.\n",
    )

    assert check_validation_hygiene.find_violations(tmp_path, [path]) == []


def test_csv_domain_column_is_checked_structurally(tmp_path: Path) -> None:
    path = "validation/aggregate/synthetic_groups.csv"
    _write(
        tmp_path,
        path,
        "domain,label\nscenario.example.invalid,fintech\nevaluated-target.localhost,healthcare\n",
    )

    violations = check_validation_hygiene.find_violations(tmp_path, [path])

    assert [violation.detail for violation in violations] == ["domain is not reserved or synthetic"]
    assert all("evaluated-target.localhost" not in violation.render() for violation in violations)


def test_csv_extra_column_cannot_bypass_domain_column_check(tmp_path: Path) -> None:
    path = "validation/aggregate/synthetic_groups.csv"
    _write(tmp_path, path, "domain,label\nscenario.example.invalid,fintech,evaluated-target.localhost\n")

    violations = check_validation_hygiene.find_violations(tmp_path, [path])

    assert [violation.detail for violation in violations] == [
        "structured validation artifact has an invalid CSV row",
    ]
    assert all("evaluated-target.localhost" not in violation.render() for violation in violations)


def test_nested_certificate_names_and_raw_domains_fail(tmp_path: Path) -> None:
    path = "validation/agentic_ux/fixtures/sample.json"
    _write(
        tmp_path,
        path,
        '{"display_name":"Synthetic Scenario 001","queried_domain":"sample.example.invalid",'
        '"cert_summary":{"deployment_bursts":[{"names":["target.localhost"]}]},'
        '"evidence":[{"raw_value":"10 target.localhost"}]}\n',
    )

    violations = check_validation_hygiene.find_violations(tmp_path, [path])

    assert {violation.detail for violation in violations} == {
        "names contains a non-reserved domain",
        "raw_value contains a non-reserved domain",
    }
    assert all("target.localhost" not in violation.render() for violation in violations)


def test_nested_mapping_inside_domain_list_cannot_bypass_scan(tmp_path: Path) -> None:
    path = "validation/agentic_ux/fixtures/sample.json"
    _write(
        tmp_path,
        path,
        '{"display_name":"Synthetic Scenario 001","queried_domain":"sample.example.invalid",'
        '"cert_summary":{"deployment_bursts":[{"names":[{"value":"target.localhost"}]}]}}\n',
    )

    violations = check_validation_hygiene.find_violations(tmp_path, [path])

    assert "names contains a non-reserved domain" in {violation.detail for violation in violations}
    assert all("target.localhost" not in violation.render() for violation in violations)


def test_whitespace_padded_structured_key_cannot_bypass_scan(tmp_path: Path) -> None:
    path = "validation/aggregate/sample.json"
    _write(tmp_path, path, '{" domain ":"target.localhost"}\n')

    violations = check_validation_hygiene.find_violations(tmp_path, [path])

    assert [violation.detail for violation in violations] == ["domain is not reserved or synthetic"]


@pytest.mark.parametrize(
    "path",
    [
        "target.localhost.json",
        "sub.target.localhost.json",
        "deep.target.localhost.json",
        "TARGET.LOCALHOST.JSON",
        "sc-private-result.json",
    ],
)
def test_root_domain_and_scan_dump_filename_shapes_fail_without_echo(path: str, tmp_path: Path) -> None:
    violations = check_validation_hygiene.find_violations(tmp_path, [path])

    assert any("root per-domain JSON dump" in violation.detail for violation in violations)
    assert all("target" not in violation.render().casefold() for violation in violations)


def test_case_variant_private_path_and_target_filename_fail_without_echo(tmp_path: Path) -> None:
    paths = [
        "Validation/Corpus-Private/private-target.txt",
        "validation/target.localhost.md",
    ]

    violations = check_validation_hygiene.find_violations(tmp_path, paths)

    assert {violation.detail for violation in violations} == {
        "private validation corpus or run output is tracked",
        "validation artifact path contains a non-reserved domain",
    }
    assert all("private-target" not in violation.render() for violation in violations)
    assert all("target.localhost" not in violation.render() for violation in violations)


def test_yaml_identity_lists_are_parsed_structurally(tmp_path: Path) -> None:
    path = "validation/aggregate/sample.yaml"
    _write(tmp_path, path, "tenant_domains:\n  - safe.example.invalid\n  - target.localhost\n")

    violations = check_validation_hygiene.find_violations(tmp_path, [path])

    assert "tenant_domains contains a non-reserved domain" in {violation.detail for violation in violations}


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        ('{"target_domain":"target.localhost"}\n', "target_domain is not reserved or synthetic"),
        ('{"members":"target.localhost"}\n', "members contains a non-reserved domain"),
        (
            '{"organization_name":"Actual Organization"}\n',
            "organization_name retains nonpublishable organization detail",
        ),
        (
            '{"bimi_identity":{"organization":"Actual Organization"}}\n',
            "bimi_identity retains nonpublishable identity detail",
        ),
        ('{"bimi_org":"Actual Organization"}\n', "bimi_org retains nonpublishable organization detail"),
        (
            '{"shared_verification_tokens":[{"token":"opaque","peer":"target.localhost"}]}\n',
            "shared_verification_tokens retains nonpublishable identity detail",
        ),
        (
            '{"shared_display_name":{"peers":["target.localhost"]}}\n',
            "shared_display_name retains nonpublishable identity detail",
        ),
        (
            '{"unclassified_dns_observations":[{"value":"opaque-target-record"}]}\n',
            "unclassified_dns_observations retains nonpublishable identity detail",
        ),
        (
            '{"unclassified_cname_chains":[["safe.example.invalid"]]}\n',
            "unclassified_cname_chains retains nonpublishable identity detail",
        ),
        (
            '{"evidence_conflicts":[{"display_name":"Nonpublishable Target Label"}]}\n',
            "evidence_conflicts retains nonpublishable identity detail",
        ),
        (
            '{"lexical_observations":[{"label":"nonpublishable-target-label"}]}\n',
            "lexical_observations retains nonpublishable identity detail",
        ),
        ('{"chain":["safe.example.invalid","target.localhost"]}\n', "chain contains a non-reserved domain"),
        ('{"display_name":"Synthetic Actual Organization"}\n', "display_name is not a constrained synthetic sentinel"),
        ('{"tenant_id":"synthetic-actual-tenant"}\n', "tenant_id is not a constrained synthetic sentinel"),
    ],
)
def test_structured_identity_surfaces_fail_closed(payload: str, expected: str, tmp_path: Path) -> None:
    path = "validation/aggregate/sample.json"
    _write(tmp_path, path, payload)

    violations = check_validation_hygiene.find_violations(tmp_path, [path])

    assert expected in {violation.detail for violation in violations}


@pytest.mark.parametrize(
    ("key", "value", "expected_fragment"),
    [
        ("queriedDomain", "target.localhost", "queried_domain"),
        ("tenantId", "actual-tenant", "tenant_id"),
        ("oidcTenantId", "actual-tenant", "tenant_id"),
        ("displayName", "Actual Organization", "display_name"),
        ("organization-name", "Actual Organization", "organization_name"),
        ("siteVerificationTokens", ["opaque"], "site_verification_tokens"),
    ],
)
def test_identity_key_variants_are_canonicalized(
    key: str,
    value: object,
    expected_fragment: str,
    tmp_path: Path,
) -> None:
    path = "validation/aggregate/sample.json"
    _write(tmp_path, path, json.dumps({key: value}) + "\n")

    violations = check_validation_hygiene.find_violations(tmp_path, [path])

    assert any(expected_fragment in violation.detail for violation in violations)


@pytest.mark.parametrize("key", ["queried_domain", "raw_value"])
def test_identity_scalar_keys_reject_collection_shapes(key: str, tmp_path: Path) -> None:
    path = "validation/aggregate/sample.json"
    _write(tmp_path, path, json.dumps({key: ["target.localhost"]}) + "\n")

    assert check_validation_hygiene.find_violations(tmp_path, [path])


@pytest.mark.parametrize(
    ("payload", "should_fail"),
    [
        ({"raw_value": "203.0.113.10"}, False),
        ({"ip": "2001:db8::10"}, False),
        ({"raw_value": "198.18.0.1"}, True),
        ({"addresses": ["2001:4860:4860::8888"]}, True),
    ],
)
def test_structured_ip_records_allow_only_documentation_ranges(
    payload: dict[str, object],
    should_fail: bool,
    tmp_path: Path,
) -> None:
    path = "validation/aggregate/sample.json"
    _write(tmp_path, path, json.dumps(payload) + "\n")

    violations = check_validation_hygiene.find_violations(tmp_path, [path])

    assert bool(violations) is should_fail


def test_unknown_structured_field_rejects_non_documentation_ip_without_echo(tmp_path: Path) -> None:
    path = "validation/aggregate/sample.json"
    address = "198.18.0.99"
    _write(tmp_path, path, json.dumps({"observation": address}) + "\n")

    violations = check_validation_hygiene.find_violations(tmp_path, [path])

    assert any("structured field contains a non-documentation IP address" in item.detail for item in violations)
    assert all(address not in item.render() for item in violations)


@pytest.mark.parametrize(
    "value",
    [
        "198.18.0.99:443",
        "https://198.18.0.99:443/path",
        "10 mx 198.18.0.99:25",
    ],
)
def test_structured_ip_endpoints_cannot_bypass_address_checks(value: str, tmp_path: Path) -> None:
    path = "validation/aggregate/sample.json"
    _write(tmp_path, path, json.dumps({"value": value}) + "\n")

    violations = check_validation_hygiene.find_violations(tmp_path, [path])

    assert any("non-documentation IP address" in item.detail for item in violations)
    assert all("198.18.0.99" not in item.render() for item in violations)


def test_prose_address_with_port_is_checked(tmp_path: Path) -> None:
    path = "validation/new-review.md"
    _write(tmp_path, path, "address: 198.18.0.99:443\n")

    violations = check_validation_hygiene.find_violations(tmp_path, [path])

    assert any("address contains a non-documentation IP address" in item.detail for item in violations)


def test_documentation_ip_endpoint_is_allowed(tmp_path: Path) -> None:
    path = "validation/aggregate/sample.json"
    _write(tmp_path, path, '{"value":"https://203.0.113.10:443/path"}\n')

    assert check_validation_hygiene.find_violations(tmp_path, [path]) == []


@pytest.mark.parametrize(
    ("raw_value", "should_fail"),
    [
        ("v=DMARC1; p=reject", False),
        ("safe.example.invalid", False),
        ("opaque-account-binding-value", True),
        ("synthetic-nonpublishable-tenant-alias", True),
    ],
)
def test_raw_values_use_a_disclosure_safe_allowlist(
    raw_value: str,
    should_fail: bool,
    tmp_path: Path,
) -> None:
    path = "validation/aggregate/sample.json"
    _write(tmp_path, path, json.dumps({"raw_value": raw_value}) + "\n")

    violations = check_validation_hygiene.find_violations(tmp_path, [path])

    assert bool(violations) is should_fail


def test_multiple_values_on_one_line_cannot_mask_unsafe_values(tmp_path: Path) -> None:
    path = "validation/new-review.md"
    _write(
        tmp_path,
        path,
        "queried_domain: example.com; domain: target.localhost; "
        "tenant_id: synthetic-scenario-001; tenant_id: actual-alias; "
        "MS=synthetic-safe; MS=actual-token; "
        "recon example.com; recon target.localhost\n",
    )

    details = {violation.detail for violation in check_validation_hygiene.find_violations(tmp_path, [path])}

    assert details >= {
        "target-domain field is not reserved or synthetic",
        "tenant identifier value is not an explicit synthetic sentinel",
        "verification-token-shaped value is tracked",
        "recon example uses a non-reserved domain",
    }


@pytest.mark.parametrize("heading", ["## SKIP", "### SKIP with qualifier"])
def test_candidate_skip_sections_fail_in_any_review_file_and_heading_level(
    heading: str,
    tmp_path: Path,
) -> None:
    path = "validation/renamed-review.md"
    _write(tmp_path, path, f"{heading}\n\ntarget.localhost\n")

    violations = check_validation_hygiene.find_violations(tmp_path, [path])

    assert any("candidate SKIP detail" in violation.detail for violation in violations)


@pytest.mark.parametrize(
    "csv_text",
    [
        "target.localhost\n",
        "target.localhost\nsibling.localhost\n",
        "customer,label\ntarget.localhost,fintech\n",
        "members,label\ntarget.localhost,fintech\n",
        "\ufeffdomain,label\ntarget.localhost,fintech\n",
    ],
)
def test_csv_header_and_schema_bypasses_fail(csv_text: str, tmp_path: Path) -> None:
    path = "validation/aggregate/synthetic_groups.csv"
    _write(tmp_path, path, csv_text)

    assert check_validation_hygiene.find_violations(tmp_path, [path])


def test_python_literal_target_field_is_scanned_without_expression_false_positive(tmp_path: Path) -> None:
    unsafe_path = "validation/sample.py"
    safe_path = "validation/expression.py"
    _write(tmp_path, unsafe_path, 'queried_domain = "target.localhost"\n')
    _write(tmp_path, safe_path, 'domain = payload.get("domain")\n')

    assert check_validation_hygiene.find_violations(tmp_path, [unsafe_path])
    assert check_validation_hygiene.find_violations(tmp_path, [safe_path]) == []


def test_dns_arrow_owner_and_prose_identity_fields_are_checked(tmp_path: Path) -> None:
    path = "validation/new-review.md"
    _write(
        tmp_path,
        path,
        "target.localhost -> provider.example.net\n"
        "display_name: Actual Organization\n"
        "organization_name: Actual Organization\n",
    )

    details = {violation.detail for violation in check_validation_hygiene.find_violations(tmp_path, [path])}

    assert details >= {
        "DNS example owner is not reserved or synthetic",
        "display_name is not a constrained synthetic sentinel",
        "organization field retains nonpublishable identity detail",
    }


def test_dns_record_table_checks_owner_and_opaque_value_without_echo(tmp_path: Path) -> None:
    path = "validation/new-review.md"
    _write(
        tmp_path,
        path,
        "| Owner | Type | Value |\n|---|---|---|\n| target.localhost | TXT | opaque-target-token |\n",
    )

    violations = check_validation_hygiene.find_violations(tmp_path, [path])

    assert {item.detail for item in violations} >= {
        "DNS record owner is not reserved or synthetic",
        "DNS record value is outside the disclosure-safe grammar",
    }
    assert all(
        "target.localhost" not in item.render() and "opaque-target-token" not in item.render() for item in violations
    )


@pytest.mark.parametrize(
    "row",
    [
        "target.localhost. 300 IN MX 10 mail.example.invalid",
        "target.localhost MX 10 mail.example.invalid",
        "TXT opaque-target-token",
    ],
)
def test_plain_dns_record_rows_fail_closed(row: str, tmp_path: Path) -> None:
    path = "validation/new-review.md"
    _write(tmp_path, path, row + "\n")

    assert check_validation_hygiene.find_violations(tmp_path, [path])


def test_reserved_dns_record_table_uses_disclosure_safe_values(tmp_path: Path) -> None:
    path = "validation/new-review.md"
    _write(
        tmp_path,
        path,
        "| Owner | Type | Value |\n"
        "|---|---|---|\n"
        "| scenario.example.invalid | MX | 10 mail.example.invalid |\n"
        "| scenario.example.invalid | TXT | MS=synthetic-ms-token-001 |\n",
    )

    assert check_validation_hygiene.find_violations(tmp_path, [path]) == []


@pytest.mark.parametrize(
    ("path", "payload"),
    [
        (
            "validation/aggregate/sample.json",
            '{"queried_domain":"target.localhost","queried_domain":"safe.example.invalid"}\n',
        ),
        (
            "validation/aggregate/sample.ndjson",
            '{"display_name":"Actual Organization","display_name":"Synthetic Scenario 001"}\n',
        ),
        (
            "validation/aggregate/sample.yaml",
            "tenant_domains: [target.localhost]\ntenant_domains: [safe.example.invalid]\n",
        ),
    ],
)
def test_duplicate_structured_keys_cannot_hide_identity(path: str, payload: str, tmp_path: Path) -> None:
    _write(tmp_path, path, payload)

    violations = check_validation_hygiene.find_violations(tmp_path, [path])

    assert any("duplicate mapping key" in violation.detail for violation in violations)


@pytest.mark.parametrize(
    ("path", "payload"),
    [
        ("validation/aggregate/sample.json", '["target.localhost"]\n'),
        ("validation/aggregate/sample.ndjson", '"target.localhost"\n'),
        ("validation/aggregate/sample.yaml", "- target.localhost\n"),
    ],
)
def test_unkeyed_structured_corpora_fail_closed(path: str, payload: str, tmp_path: Path) -> None:
    _write(tmp_path, path, payload)

    violations = check_validation_hygiene.find_violations(tmp_path, [path])

    assert any("root is not mapping records" in violation.detail for violation in violations)


@pytest.mark.parametrize(
    "path", ["validation/report.html", "validation/report.log", "validation/report.tsv", "validation/report"]
)
def test_unapproved_validation_extensions_fail(path: str, tmp_path: Path) -> None:
    _write(tmp_path, path, "target.localhost\n")

    violations = check_validation_hygiene.find_violations(tmp_path, [path])

    assert any("extension is not approved" in violation.detail for violation in violations)


def test_validation_symlinks_fail_before_content_read(tmp_path: Path) -> None:
    target = tmp_path / "outside.json"
    target.write_text('{"queried_domain":"target.localhost"}\n', encoding="utf-8")
    link = tmp_path / "validation" / "linked.json"
    link.parent.mkdir(parents=True, exist_ok=True)
    try:
        link.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")

    violations = check_validation_hygiene.find_violations(tmp_path, ["validation/linked.json"])

    assert [violation.detail for violation in violations] == ["validation artifact must not be a symbolic link"]


def test_repeated_structural_findings_are_collapsed(tmp_path: Path) -> None:
    path = "validation/aggregate/sample.ndjson"
    _write(
        tmp_path,
        path,
        '{"display_name":"Synthetic Delta One","queried_domain":"one.localhost"}\n'
        '{"display_name":"Synthetic Delta Two","queried_domain":"two.localhost"}\n',
    )

    violations = check_validation_hygiene.find_violations(tmp_path, [path])

    assert [violation.detail for violation in violations] == [
        "display_name is not a constrained synthetic sentinel",
        "queried_domain is not reserved or synthetic",
    ]


def test_case_variant_validation_content_is_scanned(tmp_path: Path) -> None:
    path = "Validation/new-review.md"
    _write(tmp_path, path, "queriedDomain: target.localhost\n")

    violations = check_validation_hygiene.find_violations(tmp_path, [path])

    assert any("target-domain field" in violation.detail for violation in violations)


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        ('display_name = "Nonpublishable Target Label"\n', "display_name"),
        ('{"organizationName": "Nonpublishable Target Label"}\n', "organization field"),
    ],
)
def test_python_identity_literals_are_scanned(
    payload: str,
    expected: str,
    tmp_path: Path,
) -> None:
    path = "validation/sample.py"
    _write(tmp_path, path, payload)

    violations = check_validation_hygiene.find_violations(tmp_path, [path])

    assert any(expected in violation.detail for violation in violations)


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        ('{"target.localhost": "value"}\n', "mapping key"),
        ('{"https://target.localhost/path": "value"}\n', "mapping key"),
        ('{"members": ["Nonpublishable Target Label"]}\n', "non-domain identity detail"),
        ('{"unrecognized": "target.localhost"}\n', "structured field contains"),
        (
            '{"unrecognized": ["target.localhost", {"count": 1}]}\n',
            "structured field contains",
        ),
    ],
)
def test_structured_unknown_identity_surfaces_fail_closed(
    payload: str,
    expected: str,
    tmp_path: Path,
) -> None:
    path = "validation/aggregate/sample.json"
    _write(tmp_path, path, payload)

    violations = check_validation_hygiene.find_violations(tmp_path, [path])

    assert any(expected in violation.detail for violation in violations)


def test_unknown_structured_key_and_value_are_not_echoed(tmp_path: Path) -> None:
    path = "validation/aggregate/sample.json"
    key = "NonpublishableTargetOrganization"
    value = "target.localhost"
    _write(tmp_path, path, json.dumps({key: value}) + "\n")

    violations = check_validation_hygiene.find_violations(tmp_path, [path])

    assert any("structured field contains a non-reserved domain" in item.detail for item in violations)
    assert all(key not in item.render() and value not in item.render() for item in violations)


def test_validation_violation_rendering_redacts_ordinary_basenames(tmp_path: Path) -> None:
    path = "validation/NonpublishableTarget/notes.md"
    _write(tmp_path, path, "queried_domain: target.localhost\n")

    violations = check_validation_hygiene.find_violations(tmp_path, [path])

    assert violations
    assert {violation.render().split(":", 1)[0] for violation in violations} == {"validation/[redacted]"}


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        ('payload = {\n    "queried_domain":\n        "target." "localhost",\n}\n', "queried_domain"),
        ('queried_domain = (\n    "target.localhost"\n)\n', "queried_domain"),
        ('payload["queried_domain"] = f"target.localhost"\n', "queried_domain"),
        ('oidc_tenant_id = "nonpublishable-alias"\n', "tenant_id"),
    ],
)
def test_python_ast_closes_multiline_identity_bypasses(
    payload: str,
    expected: str,
    tmp_path: Path,
) -> None:
    path = "validation/sample.py"
    _write(tmp_path, path, payload)

    violations = check_validation_hygiene.find_violations(tmp_path, [path])

    assert any(expected in violation.detail for violation in violations)


@pytest.mark.parametrize(
    "payload",
    [
        'value = "target.localhost"\nqueried_domain = value\n',
        'prefix = "target."\nsuffix = "localhost"\nqueried_domain = prefix + suffix\n',
        'suffix = "localhost"\nqueried_domain = f"target.{suffix}"\n',
        'value = "target.localhost"\nqueried_domain = value\nvalue = "safe.example.invalid"\n',
        'value = "target.localhost"; queried_domain = value\n',
        '(queried_domain := "target.localhost")\n',
        'queried_domain = (value := "target.localhost")\n',
    ],
)
def test_python_ast_resolves_prior_constant_bindings(payload: str, tmp_path: Path) -> None:
    path = "validation/sample.py"
    _write(tmp_path, path, payload)

    violations = check_validation_hygiene.find_violations(tmp_path, [path])

    assert any("queried_domain" in item.detail for item in violations)


def test_python_ast_does_not_apply_later_reassignment_to_earlier_use(tmp_path: Path) -> None:
    path = "validation/sample.py"
    _write(
        tmp_path,
        path,
        'value = "safe.example.invalid"\nqueried_domain = value\nvalue = "target.localhost"\n',
    )

    assert check_validation_hygiene.find_violations(tmp_path, [path]) == []


@pytest.mark.parametrize(
    "payload",
    [
        ('value = "target.localhost"\ndef inner():\n    value = "safe.example.invalid"\nqueried_domain = value\n'),
        ('value = "target.localhost"\nif enabled:\n    value = "safe.example.invalid"\nqueried_domain = value\n'),
        ('value = "safe.example.invalid"\nif enabled:\n    value = "target.localhost"\nqueried_domain = value\n'),
        'def render(value="target.localhost"):\n    queried_domain = value\n',
        'value = "target.localhost"\ndef render():\n    queried_domain = value\n',
    ],
)
def test_python_ast_respects_scope_defaults_and_conditional_paths(
    payload: str,
    tmp_path: Path,
) -> None:
    path = "validation/sample.py"
    _write(tmp_path, path, payload)

    violations = check_validation_hygiene.find_violations(tmp_path, [path])

    assert any("queried_domain" in item.detail for item in violations)


@pytest.mark.parametrize(
    ("field", "value", "expected"),
    [
        ("queriedDomain", "target.localhost", "queried_domain"),
        ("display_name", "Nonpublishable Target Label", "display_name"),
        ("tenant_id", "nonpublishable-alias", "tenant_id"),
        ("organizationName", "Nonpublishable Target Label", "organization_name"),
    ],
)
def test_prose_identity_values_cannot_move_to_the_next_line(
    field: str,
    value: str,
    expected: str,
    tmp_path: Path,
) -> None:
    path = "validation/new-review.md"
    _write(tmp_path, path, f"{field}:\n  {value}\n")

    violations = check_validation_hygiene.find_violations(tmp_path, [path])

    assert any(expected in violation.detail for violation in violations)


def test_prose_domain_field_rejects_a_same_line_non_domain_label(tmp_path: Path) -> None:
    path = "validation/new-review.md"
    _write(tmp_path, path, "queried_domain: Nonpublishable Target Label\n")

    violations = check_validation_hygiene.find_violations(tmp_path, [path])

    assert any("queried_domain has an invalid identity field shape" in item.detail for item in violations)


@pytest.mark.parametrize(
    ("field", "value", "expected"),
    [
        ("domain", "Nonpublishable Target Label", "domain has an invalid identity field shape"),
        ("host", "Nonpublishable Target Label", "host has an invalid identity field shape"),
        ("hostname", "Nonpublishable Target Label", "hostname has an invalid identity field shape"),
        ("target", "Nonpublishable Target Label", "target has an invalid identity field shape"),
        ("apex", "Nonpublishable Target Label", "apex has an invalid identity field shape"),
        ("oidc_tenant_id", "nonpublishable-alias", "tenant_id"),
        ("bimi_org", "Nonpublishable Target Label", "bimi_org"),
    ],
)
def test_same_line_prose_identity_fields_fail_closed(
    field: str,
    value: str,
    expected: str,
    tmp_path: Path,
) -> None:
    path = "validation/new-review.md"
    _write(tmp_path, path, f"{field}: {value}\n")

    violations = check_validation_hygiene.find_violations(tmp_path, [path])

    assert any(expected in item.detail for item in violations)


@pytest.mark.parametrize(
    "payload",
    [
        "Target: Nonpublishable Target Label\n",
        "**domain:** Nonpublishable Target Label\n",
        "| domain | Nonpublishable Target Label |\n",
    ],
)
def test_title_case_bold_and_table_identity_fields_fail_closed(payload: str, tmp_path: Path) -> None:
    path = "validation/new-review.md"
    _write(tmp_path, path, payload)

    assert check_validation_hygiene.find_violations(tmp_path, [path])


def test_markdown_domain_list_checks_every_item(tmp_path: Path) -> None:
    path = "validation/new-review.md"
    _write(
        tmp_path,
        path,
        "tenant_domains:\n- safe.example.invalid\n- target.localhost\n",
    )

    violations = check_validation_hygiene.find_violations(tmp_path, [path])

    assert any("tenant_domains contains a non-reserved domain" in item.detail for item in violations)


@pytest.mark.parametrize(
    "payload",
    [
        "1. queried_domain:\n   1) target.localhost\n",
        "> queried_domain:\n> target.localhost\n",
        "> - queried_domain:\n> - target.localhost\n",
    ],
)
def test_numbered_and_blockquoted_identity_continuations_are_checked(
    payload: str,
    tmp_path: Path,
) -> None:
    path = "validation/new-review.md"
    _write(tmp_path, path, payload)

    violations = check_validation_hygiene.find_violations(tmp_path, [path])

    assert any("queried_domain" in item.detail for item in violations)


@pytest.mark.parametrize(
    ("value", "should_fail"),
    [
        ("synthetic-ms-token-001", False),
        ("synthetic-domain-token-001", False),
        ("synthetic-token-001", False),
        ("synthetic-nonpublishable-target-token", True),
        ("synthetic-ms-token-001.suffix", True),
        ("synthetic-ms-token-001/suffix", True),
        ("synthetic-ms-token-001=suffix", True),
        ("synthetic-ms-token-001 suffix", True),
    ],
)
def test_verification_sentinels_use_a_constrained_grammar(
    value: str,
    should_fail: bool,
    tmp_path: Path,
) -> None:
    path = "validation/new-review.md"
    _write(tmp_path, path, f"MS={value}\n")

    violations = check_validation_hygiene.find_violations(tmp_path, [path])

    assert bool(violations) is should_fail


@pytest.mark.parametrize(
    ("record", "should_fail"),
    [
        ("vendor-domain-verification=synthetic-token-001", False),
        ("vendor-domain-verification=nonpublishable-token", True),
    ],
)
def test_catalog_wide_verification_prefixes_are_guarded(
    record: str,
    should_fail: bool,
    tmp_path: Path,
) -> None:
    path = "validation/new-review.md"
    _write(tmp_path, path, record + "\n")

    violations = check_validation_hygiene.find_violations(tmp_path, [path])

    assert bool(violations) is should_fail
