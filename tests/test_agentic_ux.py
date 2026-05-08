"""Tests for the v1.9.2 agentic UX validation harness.

These tests cover three things:

1. The provider adapter shape — that ``get_provider`` constructs each
   adapter with mocked SDK clients without ever calling the network.
2. The rubric scoring — that the binary regex/keyword scans correctly
   classify both positive and negative synthetic transcripts.
3. The runner / report writer — that ``run_matrix`` orchestrates the
   3 x 2 x 2 = 12 sessions, that fusion-stripping removes only the
   v1.9 fields, and that the markdown report is well-formed.

The tests inject a fake provider (no SDK imports, no network) so the
suite stays deterministic and runs in the default ``-m 'not integration'``
selection.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, ClassVar

import pytest

# Add repo root to path so we can import ``validation.agentic_ux`` without
# a packaging install. Keep this localized to the test module so other
# tests are not affected.
_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from validation.agentic_ux import providers, run, score  # noqa: I001 — sys.path bootstrap above


# --- Provider adapter --------------------------------------------------------


def test_estimate_cost_known_model() -> None:
    cost = providers.estimate_cost(1_000_000, 500_000, "claude-sonnet-4-6")
    # 1M * 3 + 0.5M * 15 = 3 + 7.5 = 10.5
    assert cost == pytest.approx(10.5)


def test_estimate_cost_unknown_model_returns_zero() -> None:
    assert providers.estimate_cost(1_000, 1_000, "no-such-model") == 0.0


def test_estimate_cost_overrides_take_precedence() -> None:
    cost = providers.estimate_cost(
        1_000_000,
        1_000_000,
        "claude-opus-4-7",
        input_price=2.0,
        output_price=4.0,
    )
    assert cost == pytest.approx(6.0)


def test_get_provider_unknown_raises() -> None:
    with pytest.raises(providers.ProviderError, match="unknown provider"):
        providers.get_provider("nope", "x")


def test_anthropic_provider_missing_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    fake_module = type(sys)("anthropic")
    fake_module.Anthropic = lambda **kwargs: object()  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "anthropic", fake_module)
    with pytest.raises(providers.ProviderError, match="ANTHROPIC_API_KEY"):
        providers.AnthropicProvider("claude-sonnet-4-6")


def test_anthropic_provider_normalizes_response(monkeypatch: pytest.MonkeyPatch) -> None:
    """A mocked anthropic SDK client returns a normalized ChatResponse."""

    class _Block:
        type = "text"

        def __init__(self, text: str) -> None:
            self.text = text

    class _Usage:
        input_tokens = 100
        output_tokens = 50

    class _Response:
        content: ClassVar[list[_Block]] = [_Block("hello world")]
        usage: ClassVar[_Usage] = _Usage()

    class _Messages:
        def create(self, **_kwargs: object) -> _Response:
            return _Response()

    class _Client:
        def __init__(self, **_kwargs: object) -> None:
            self.messages = _Messages()

    fake_module = type(sys)("anthropic")
    fake_module.Anthropic = _Client  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "anthropic", fake_module)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")

    provider = providers.AnthropicProvider("claude-sonnet-4-6")
    response = provider.chat(
        system="be brief",
        messages=[providers.ChatMessage(role="user", content="hi")],
        max_tokens=64,
    )
    assert response.text == "hello world"
    assert response.input_tokens == 100
    assert response.output_tokens == 50
    assert response.provider == "anthropic"
    # 100 in @ $3/M + 50 out @ $15/M = 0.0003 + 0.00075 = 0.00105
    assert response.cost_usd == pytest.approx(0.00105)


def test_openai_provider_normalizes_response(monkeypatch: pytest.MonkeyPatch) -> None:
    """A mocked openai SDK client returns a normalized ChatResponse."""

    class _Message:
        content = "ok"

    class _Choice:
        message: ClassVar[_Message] = _Message()

    class _Usage:
        prompt_tokens = 200
        completion_tokens = 100

    class _Response:
        choices: ClassVar[list[_Choice]] = [_Choice()]
        usage: ClassVar[_Usage] = _Usage()

    class _Completions:
        def create(self, **_kwargs: object) -> _Response:
            return _Response()

    class _Chat:
        completions: ClassVar[_Completions] = _Completions()

    class _Client:
        def __init__(self, **_kwargs: object) -> None:
            self.chat = _Chat()

    fake_module = type(sys)("openai")
    fake_module.OpenAI = _Client  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "openai", fake_module)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")

    provider = providers.OpenAIProvider("gpt-5")
    response = provider.chat(
        system="terse",
        messages=[providers.ChatMessage(role="user", content="hi")],
        max_tokens=64,
    )
    assert response.text == "ok"
    assert response.input_tokens == 200
    assert response.output_tokens == 100
    assert response.provider == "openai"


def test_xai_provider_uses_xai_base_url(monkeypatch: pytest.MonkeyPatch) -> None:
    """The xAI adapter passes the xAI base URL into the openai SDK client."""
    captured: dict[str, object] = {}

    class _Client:
        def __init__(self, **kwargs: object) -> None:
            captured.update(kwargs)
            self.chat: object = None

    fake_module = type(sys)("openai")
    fake_module.OpenAI = _Client  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "openai", fake_module)
    monkeypatch.setenv("XAI_API_KEY", "sk-grok")

    providers.XAIProvider("grok-4")
    assert captured.get("base_url") == "https://api.x.ai/v1"
    assert captured.get("api_key") == "sk-grok"


# --- Rubric scoring ----------------------------------------------------------


def test_score_session_negative_baseline() -> None:
    text = "This domain runs Microsoft 365. Email security looks normal."
    s = score.score_session("analyst", "contoso-dense", True, text)
    assert s.read_posterior_block is False
    assert s.cited_credible_interval is False
    assert s.mentioned_explain_dag is False
    assert s.hedge_count == 0


def test_score_session_detects_posterior_reference() -> None:
    text = "The posterior_observations entry for m365_tenant has n_eff = 5.0."
    s = score.score_session("analyst", "contoso-dense", True, text)
    assert s.read_posterior_block is True


def test_score_session_detects_credible_interval_phrase() -> None:
    text = "The credible interval [0.83, 1.0] suggests high confidence."
    s = score.score_session("ops", "contoso-dense", True, text)
    assert s.cited_credible_interval is True


def test_score_session_detects_numeric_interval() -> None:
    text = "Range looks like 0.21 to 0.95 which is wide."
    s = score.score_session("ops", "hardened-sparse", True, text)
    assert s.cited_credible_interval is True


def test_score_session_detects_explain_dag_invocation() -> None:
    text = "I would run recon contoso.com --explain-dag for the evidence DAG."
    s = score.score_session("researcher", "contoso-dense", True, text)
    assert s.mentioned_explain_dag is True


def test_score_session_counts_hedge_phrases() -> None:
    text = (
        "Limited evidence. Cannot confirm the email provider. The signal is sparse "
        "and the target appears hardened."
    )
    s = score.score_session("analyst", "hardened-sparse", True, text)
    assert s.hedge_count >= 3


def test_diff_sparse_vs_dense_positive() -> None:
    dense = score.score_session("analyst", "contoso-dense", True, "All clear, normal stack.")
    sparse = score.score_session(
        "analyst",
        "hardened-sparse",
        True,
        "Limited evidence; cannot confirm. The target looks hardened with sparse signals.",
    )
    diff = score.diff_sparse_vs_dense(
        dense,
        sparse,
        dense_text="All clear, normal stack.",
        sparse_text="Limited evidence; cannot confirm. The target looks hardened with sparse signals.",
    )
    assert diff.differed is True


def test_diff_sparse_vs_dense_negative_when_identical_tone() -> None:
    text = "Microsoft 365 with normal posture."
    dense = score.score_session("ops", "contoso-dense", True, text)
    sparse = score.score_session("ops", "hardened-sparse", True, text)
    diff = score.diff_sparse_vs_dense(dense, sparse, dense_text=text, sparse_text=text)
    assert diff.differed is False


def test_diff_fusion_on_vs_off_positive() -> None:
    on_text = "Posterior 0.95 for m365_tenant — credible interval [0.83, 1.0]."
    off_text = "Microsoft 365 detected from the tenant ID."
    on_score = score.score_session("analyst", "contoso-dense", True, on_text)
    off_score = score.score_session("analyst", "contoso-dense", False, off_text)
    diff = score.diff_fusion_on_vs_off(on_score, off_score, on_text=on_text, off_text=off_text)
    assert diff.differed is True


def test_diff_fusion_on_vs_off_negative_when_neither_engages() -> None:
    text = "Microsoft 365 detected. Email looks fine."
    on_score = score.score_session("ops", "contoso-dense", True, text)
    off_score = score.score_session("ops", "contoso-dense", False, text)
    diff = score.diff_fusion_on_vs_off(on_score, off_score, on_text=text, off_text=text)
    assert diff.differed is False
    assert "did not engage" in diff.reason


# --- Runner orchestration ----------------------------------------------------


class _FakeProvider:
    """In-process provider that returns canned text without network."""

    name = "fake"
    model = "fake-model"

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def chat(
        self,
        system: str,
        messages: Any,
        *,
        max_tokens: int,
    ) -> providers.ChatResponse:
        msg_list = list(messages)
        user_text = msg_list[0].content if msg_list else ""
        self.calls.append({"system": system, "user": user_text, "max_tokens": max_tokens})
        # Synthesize a response that varies with whether the input has
        # the fusion fields, so the rubric exercises both arms.
        has_fusion = "posterior_observations" in user_text
        is_sparse = "northwindtraders.com" in user_text
        if has_fusion and not is_sparse:
            text = (
                "Reading posterior_observations: m365_tenant has a credible "
                "interval near 0.83 to 1.0. The evidence DAG (--explain-dag) "
                "would corroborate."
            )
        elif has_fusion and is_sparse:
            text = (
                "Limited evidence; the target looks hardened. The posterior is "
                "wide (interval 0.21 to 0.95) so I cannot confirm. Sparse signals."
            )
        elif is_sparse:
            text = "Limited evidence. Cannot confirm the email provider. Hardened target."
        else:
            text = "Microsoft 365 detected from the tenant ID. Normal stack."
        return providers.ChatResponse(
            text=text,
            input_tokens=200,
            output_tokens=80,
            cost_usd=0.001,
            model=self.model,
            provider=self.name,
        )


def test_run_session_strips_fusion_fields_when_off() -> None:
    fake = _FakeProvider()
    record = run.run_session(
        fake,
        "analyst",
        "contoso-dense",
        fusion=False,
        max_tokens=512,
    )
    assert record.fusion is False
    assert "posterior_observations" not in fake.calls[-1]["user"]
    assert "slug_confidences" not in fake.calls[-1]["user"]


def test_run_session_includes_fusion_fields_when_on() -> None:
    fake = _FakeProvider()
    record = run.run_session(
        fake,
        "analyst",
        "contoso-dense",
        fusion=True,
        max_tokens=512,
    )
    assert record.fusion is True
    assert "posterior_observations" in fake.calls[-1]["user"]


def test_run_matrix_produces_12_sessions() -> None:
    fake = _FakeProvider()
    records = run.run_matrix(fake, max_tokens=256)
    assert len(records) == 12
    keys = {(r.persona, r.fixture, r.fusion) for r in records}
    assert len(keys) == 12


def test_score_records_emits_both_diff_kinds() -> None:
    fake = _FakeProvider()
    records = run.run_matrix(fake, max_tokens=256)
    summary = run.score_records(records)
    # Three personas, two diff kinds each = six diffs.
    assert len(summary.diffs) == 6
    labels = {d.label for d in summary.diffs}
    assert labels == {"sparse_vs_dense", "fusion_on_vs_off"}


def test_render_report_contains_required_sections(tmp_path: Path) -> None:
    fake = _FakeProvider()
    records = run.run_matrix(fake, max_tokens=256)
    summary = run.score_records(records)
    started = datetime(2026, 5, 8, 12, 0, 0, tzinfo=timezone.utc)
    finished = datetime(2026, 5, 8, 12, 5, 0, tzinfo=timezone.utc)
    body = run.render_report(records, summary, started_at=started, finished_at=finished)
    assert "# Agentic UX Validation — v1.9.2" in body
    assert "## Methodology" in body
    assert "## Rubric — per-session" in body
    assert "## Rubric — cross-session diffs" in body
    assert "## Transcripts" in body
    assert "fusion=on" in body
    assert "fusion=off" in body
    # Cost line uses 4-decimal precision so a $0.001 fake call is visible.
    assert "$0.0120" in body  # 12 sessions x $0.001 fake cost
    out = tmp_path / "out.md"
    out.write_text(body, encoding="utf-8")
    assert out.read_text(encoding="utf-8") == body


def test_main_writes_output_with_fake_provider(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """The main entrypoint should write a report when given a fake provider."""

    def _fake_get_provider(*args: object, **kwargs: object) -> _FakeProvider:
        return _FakeProvider()

    monkeypatch.setattr(run, "get_provider", _fake_get_provider)
    output = tmp_path / "out.md"
    records_json = tmp_path / "records.json"
    rc = run.main(
        [
            "--provider",
            "anthropic",
            "--model",
            "fake",
            "--output",
            str(output),
            "--records-json",
            str(records_json),
        ],
    )
    assert rc == 0
    assert output.exists()
    body = output.read_text(encoding="utf-8")
    assert "# Agentic UX Validation — v1.9.2" in body
    payload = json.loads(records_json.read_text(encoding="utf-8"))
    assert len(payload) == 12
    assert all("response_text" in entry for entry in payload)


def test_main_returns_nonzero_on_provider_error(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def _raises(*args: object, **kwargs: object) -> None:
        raise providers.ProviderError("missing key")

    monkeypatch.setattr(run, "get_provider", _raises)
    rc = run.main(
        [
            "--provider",
            "anthropic",
            "--model",
            "x",
            "--output",
            str(tmp_path / "x.md"),
        ],
    )
    assert rc == 2


# --- Fixture sanity ----------------------------------------------------------


def test_committed_fixtures_have_expected_shape() -> None:
    """The committed fixtures must round-trip through the runner's loader."""
    dense = run._load_fixture("contoso-dense")
    sparse = run._load_fixture("hardened-sparse")
    assert dense["queried_domain"] == "contoso.com"
    assert sparse["queried_domain"] == "northwindtraders.com"
    # Fictional brands only — see feedback_no_real_company_data.md
    assert "posterior_observations" in dense
    assert "posterior_observations" in sparse
    # Sparse fixture should report sparse=true on at least one node, by design.
    assert any(p.get("sparse") for p in sparse["posterior_observations"])
