"""Comment-preserving Codex config edits. No client binary and no network."""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import cast

import pytest

from recon_tool.mcp_client.codex_config import (
    CodexConfigError,
    extract_recon_block,
    plan_codex_text,
    read_text_file,
    render_recon_table,
    toml_basic_string,
)

_BLOCK: dict[str, object] = {
    "command": "/usr/bin/python3",
    "args": ["-c", "code"],
    "env": {"PYTHONSAFEPATH": "1"},
}


def _document(text: str) -> dict[str, object]:
    return cast(dict[str, object], tomllib.loads(text))


def _recon(text: str) -> dict[str, object]:
    servers = _document(text)["mcp_servers"]
    assert isinstance(servers, dict)
    recon = cast(dict[str, object], servers)["recon"]
    assert isinstance(recon, dict)
    return cast(dict[str, object], recon)


def test_append_preserves_prefix_bytes_and_comments() -> None:
    existing = '# café header\nmodel = "keep"\n\n[other]\ncommand = "sibling"\n'
    planned = plan_codex_text(existing, _BLOCK, force=False)

    assert planned.action == "merge"
    assert planned.text.startswith(existing + "\n")
    assert _recon(planned.text)["command"] == "/usr/bin/python3"
    assert "tool_timeout_sec" not in planned.text
    assert "default_tools_approval_mode" not in planned.text


def test_crlf_sibling_survives_append() -> None:
    existing = 'model = "keep"\r\n\r\n[other]\r\ncommand = "sibling"\r\n'
    planned = plan_codex_text(existing, _BLOCK, force=False)

    assert 'model = "keep"\r\n\r\n[other]\r\ncommand = "sibling"\r\n' in planned.text
    assert _recon(planned.text)["args"] == ["-c", "code"]


def test_multiline_string_hides_a_fake_header() -> None:
    existing = 'note = """\n[mcp_servers.recon]\ncommand = "fake"\n"""\n\n[real]\nvalue = "1"\n'
    assert extract_recon_block(existing) is None

    planned = plan_codex_text(existing, _BLOCK, force=False)

    assert planned.text.startswith(existing)
    assert '[mcp_servers.recon]\ncommand = "fake"' in planned.text
    assert _recon(planned.text)["command"] == "/usr/bin/python3"


def test_quoted_dotted_header_is_not_the_recon_table() -> None:
    existing = '["mcp_servers.recon"]\ncommand = "old"\nargs = ["mcp"]\n'
    assert extract_recon_block(existing) is None

    planned = plan_codex_text(existing, _BLOCK, force=False)

    assert '["mcp_servers.recon"]' in planned.text
    assert _recon(planned.text)["command"] == "/usr/bin/python3"


def test_quoted_recon_header_is_detected() -> None:
    existing = '[mcp_servers."recon"]\ncommand = "old"\nargs = ["mcp"]\n'
    block = extract_recon_block(existing)

    assert block is not None
    assert block["command"] == "old"
    assert block["args"] == ["mcp"]


def test_whitespace_around_dots_is_the_recon_table() -> None:
    existing = '[ mcp_servers . recon ]\ncommand = "old"\nargs = ["mcp"]\n'
    block = extract_recon_block(existing)

    assert block is not None
    assert block["command"] == "old"


def test_matching_command_and_args_keep_the_file_byte_for_byte() -> None:
    existing = (
        "[mcp_servers.recon]\n"
        'command = "/usr/bin/python3"\n'
        'args = ["-c", "code"]\n'
        "# keep me\n"
        'extra = "stay"\n'
        "\n"
        "[other]\n"
        'command = "sibling"\n'
    )
    planned = plan_codex_text(existing, _BLOCK, force=True)

    assert planned.unchanged
    assert planned.action == "merge"
    assert planned.text == existing


def test_multiline_args_with_a_comment_still_match() -> None:
    existing = '[mcp_servers.recon]\ncommand = "/usr/bin/python3"\nargs = [\n  # launcher\n  "-c",\n  "code",\n]\n'
    planned = plan_codex_text(existing, _BLOCK, force=False)

    assert planned.unchanged
    assert planned.text == existing


def test_differing_table_without_force_is_refused() -> None:
    existing = '[mcp_servers.recon]\ncommand = "old"\nargs = ["mcp"]\n'
    with pytest.raises(CodexConfigError, match=r"would change"):
        plan_codex_text(existing, _BLOCK, force=False)


def test_force_replaces_only_the_recon_span() -> None:
    existing = (
        "# café header\n"
        'model = "keep"\n'
        "\n"
        "[mcp_servers.other]\n"
        'command = "sibling"\n'
        "\n"
        "[mcp_servers.recon]\n"
        "# inside\n"
        'command = "old"\n'
        'args = ["mcp"]\n'
        'extra = "drop"\n'
        "\n"
        "# belongs to next\n"
        "[keep]\n"
        'value = "1"\n'
    )
    planned = plan_codex_text(existing, _BLOCK, force=True)

    assert planned.action == "replace"
    assert "# café header" in planned.text
    assert 'command = "sibling"' in planned.text
    assert "# belongs to next" in planned.text
    assert '[keep]\nvalue = "1"\n' in planned.text
    assert "# inside" not in planned.text
    assert 'extra = "drop"' not in planned.text
    assert 'command = "old"' not in planned.text
    assert _recon(planned.text)["command"] == "/usr/bin/python3"
    assert "tool_timeout_sec" not in planned.text


def test_force_removes_a_later_recon_span_and_keeps_the_sibling() -> None:
    existing = (
        "[mcp_servers.recon]\n"
        'command = "first"\n'
        'args = ["a"]\n'
        "\n"
        "[other]\n"
        'command = "sibling"\n'
        "\n"
        "[mcp_servers.recon]\n"
        'command = "second"\n'
        'args = ["b"]\n'
    )
    assert extract_recon_block(existing) == {"command": "second", "args": ["b"]}

    planned = plan_codex_text(existing, _BLOCK, force=True)

    assert planned.text.count("[mcp_servers.recon]") == 1
    assert 'command = "sibling"' in planned.text
    assert 'command = "second"' not in planned.text
    assert _recon(planned.text)["command"] == "/usr/bin/python3"


def test_array_table_and_inline_assignment_are_refused() -> None:
    with pytest.raises(CodexConfigError, match=r"array of tables"):
        plan_codex_text("[[mcp_servers.recon]]\n", _BLOCK, force=True)
    with pytest.raises(CodexConfigError, match=r"inline assignment"):
        plan_codex_text('mcp_servers.recon.command = "x"\n', _BLOCK, force=True)


def test_unclosed_string_and_header_trailer_are_refused() -> None:
    with pytest.raises(CodexConfigError, match=r"not closed"):
        plan_codex_text('note = "oops\n', _BLOCK, force=False)
    with pytest.raises(CodexConfigError, match=r"trailing text"):
        extract_recon_block('[mcp_servers.recon] command = "x"\n')


def test_render_omits_timeout_and_approval_and_escapes_windows_paths() -> None:
    rendered = render_recon_table(_BLOCK)
    assert rendered.startswith("[mcp_servers.recon]\n")
    assert "[mcp_servers.recon.env]\n" in rendered
    assert "tool_timeout_sec" not in rendered
    assert "default_tools_approval_mode" not in rendered
    assert "autoApprove" not in rendered
    assert toml_basic_string("C:\\Python\\python.exe") == '"C:\\\\Python\\\\python.exe"'
    assert _document(rendered)["mcp_servers"]


def test_missing_file_plans_a_create_and_invalid_utf8_is_refused(tmp_path: Path) -> None:
    planned = plan_codex_text(None, _BLOCK, force=False)
    assert planned.action == "create"
    assert planned.text == render_recon_table(_BLOCK)

    target = tmp_path / "config.toml"
    target.write_bytes(b"\xff")
    state, _text, detail = read_text_file(target)
    assert state == "invalid"
    assert "UTF-8" in detail
