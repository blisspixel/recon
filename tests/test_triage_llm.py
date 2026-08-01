"""Security-contract tests for the optional LLM triage helper."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from validation import triage_llm


@pytest.mark.parametrize(
    "arguments",
    [
        ["--api-key", "super-secret-cli-value"],
        ["--api-key=super-secret-cli-value"],
    ],
)
def test_main_rejects_cli_api_key_without_echoing_secret(
    arguments: list[str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    rc = triage_llm.main(arguments)

    assert rc == 2
    stderr = capsys.readouterr().err
    assert "--api-key is not supported" in stderr
    assert "ANTHROPIC_API_KEY" in stderr
    assert "super-secret-cli-value" not in stderr
