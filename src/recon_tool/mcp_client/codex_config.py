"""Comment-preserving edits for a Codex ``config.toml``.

Codex stores one MCP server in a ``[mcp_servers.<name>]`` table. This editor
appends ``[mcp_servers.recon]`` or replaces only that table and its child
tables. Bytes outside those spans, including comments and sibling tables,
stay as they were. It does not write ``tool_timeout_sec`` or
``default_tools_approval_mode``.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast

from recon_tool.json_limits import DirectoryFile, read_bounded_regular_file
from recon_tool.mcp_client.config_json import MAX_CLIENT_CONFIG_BYTES

RECON_TABLE = "mcp_servers.recon"
ENV_TABLE = "mcp_servers.recon.env"
CODEX_OPERATOR_NOTE = (
    "Codex tool_timeout_sec defaults to 60 seconds. chain_lookup can take longer; "
    "set tool_timeout_sec above 60 on [mcp_servers.recon] if those lookups time out. "
    'default_tools_approval_mode = "writes" prompts only for tools that are not marked '
    "read-only. recon mcp install does not write either setting."
)

_ReadState = Literal["missing", "invalid", "ok"]


class CodexConfigError(ValueError):
    """The Codex file has a recon entry this editor will not rewrite."""


@dataclass(frozen=True)
class CodexTextPlan:
    """Full document text after one recon-table edit."""

    action: Literal["create", "merge", "replace"]
    text: str
    unchanged: bool
    existing_block: dict[str, object] | None


@dataclass(frozen=True)
class _Header:
    parts: tuple[str, ...]
    array: bool


@dataclass(frozen=True)
class _Scan:
    headers: tuple[tuple[int, _Header], ...]
    multiline_at_start: tuple[bool, ...]


@dataclass(frozen=True)
class _Parsed:
    command: str | None
    args: tuple[str, ...] | None
    complete: bool
    env: dict[str, str]


def read_text_file(
    path: Path,
    *,
    allow_symlinks: bool = True,
    directory_fd: int | None = None,
) -> tuple[_ReadState, str, str]:
    """Read one bounded UTF-8 config file. A missing file is not an error."""
    if directory_fd is None:
        refusal = _path_refusal(path, allow_symlinks=allow_symlinks)
        if refusal is not None:
            return refusal

    try:
        source: Path | DirectoryFile = path if directory_fd is None else DirectoryFile(path, directory_fd)
        raw_bytes, _, _ = read_bounded_regular_file(
            source,
            maximum_bytes=MAX_CLIENT_CONFIG_BYTES,
            allow_symlinks=allow_symlinks,
            future_mtime_tolerance_seconds=None,
        )
    except FileNotFoundError:
        return "missing", "", "not found"
    except OSError as exc:
        return "invalid", "", f"cannot read: {exc}"
    except ValueError as exc:
        detail = "exceeds maximum size of 1 MiB" if "byte limit" in str(exc) else f"cannot read: {exc}"
        return "invalid", "", detail

    try:
        return "ok", raw_bytes.decode("utf-8-sig"), "read"
    except UnicodeDecodeError as exc:
        return "invalid", "", f"is not valid UTF-8 at byte {exc.start}"


def read_codex_document(path: Path) -> tuple[_ReadState, dict[str, object] | None, str]:
    """Return a JSON-shaped ``mcp_servers.recon`` object, or no recon entry."""
    state, text, detail = read_text_file(path)
    if state != "ok":
        return state, None, detail
    try:
        block = extract_recon_block(text)
    except CodexConfigError as exc:
        return "invalid", None, str(exc)
    if block is None:
        return "ok", {}, "parsed"
    return "ok", {"mcp_servers": {"recon": block}}, "parsed"


def extract_recon_block(text: str) -> dict[str, object] | None:
    """Return the parsed recon command, args, and env, or None when absent."""
    lines = _lines(text)
    scan = _scan(lines)
    spans = _recon_spans(lines, scan)
    if not spans:
        return None
    parsed = _parse_spans(lines, scan, spans)
    block: dict[str, object] = {}
    if parsed.command is not None:
        block["command"] = parsed.command
    if parsed.args is not None:
        block["args"] = list(parsed.args)
    if parsed.env:
        block["env"] = dict(parsed.env)
    return block


def render_recon_table(block: Mapping[str, object]) -> str:
    """Render the canonical recon tables. Timeout and approval stay absent."""
    command = block.get("command")
    args = _string_list(block.get("args"))
    if not isinstance(command, str) or args is None:
        raise CodexConfigError("recon block is missing a string command and string args")
    rows = [
        f"[{RECON_TABLE}]",
        f"command = {toml_basic_string(command)}",
        "args = [" + ", ".join(toml_basic_string(item) for item in args) + "]",
    ]
    env = _string_dict(block.get("env"))
    if env:
        rows.append("")
        rows.append(f"[{ENV_TABLE}]")
        rows.extend(f"{_toml_key(key)} = {toml_basic_string(value)}" for key, value in env.items())
    return "\n".join(rows) + "\n"


def plan_codex_text(
    existing: str | None,
    block: Mapping[str, object],
    *,
    force: bool,
) -> CodexTextPlan:
    """Plan an append or a span replacement. Matching command and args are a no-op."""
    rendered = render_recon_table(block)
    if existing is None:
        return CodexTextPlan("create", rendered, False, None)

    lines = _lines(existing)
    scan = _scan(lines)
    spans = _recon_spans(lines, scan)
    if not spans:
        prefix = existing if existing.endswith("\n") or existing == "" else existing + "\n"
        if prefix and not prefix.endswith("\n\n"):
            prefix += "\n"
        return CodexTextPlan("merge", prefix + rendered, False, None)

    parsed = _parse_spans(lines, scan, spans)
    if _matches(parsed, block):
        return CodexTextPlan("merge", existing, True, None)
    if not force:
        raise CodexConfigError(
            "mcp_servers.recon would change. Pass --force to replace that table span "
            "(sibling tables and comments outside it are kept)"
        )
    previous: dict[str, object] = {}
    if parsed.command is not None:
        previous["command"] = parsed.command
    if parsed.args is not None:
        previous["args"] = list(parsed.args)
    return CodexTextPlan("replace", _splice(lines, spans, rendered), False, previous or {"present": True})


def toml_basic_string(value: str) -> str:
    """Encode one TOML basic string."""
    parts = ['"']
    for char in value:
        parts.append(_escaped(char))
    parts.append('"')
    return "".join(parts)


def _path_refusal(path: Path, *, allow_symlinks: bool) -> tuple[_ReadState, str, str] | None:
    if not allow_symlinks and path.is_symlink():
        return "invalid", "", "cannot read: config file must not be a symbolic link"
    if not path.exists():
        return "missing", "", "not found"
    if path.is_dir():
        return "invalid", "", "is a directory, not a config file"
    return None


def _lines(text: str) -> list[str]:
    return text.splitlines(keepends=True)


_RECON_PARTS = ("mcp_servers", "recon")
_ENV_PARTS = ("mcp_servers", "recon", "env")


def _is_recon_parts(parts: tuple[str, ...]) -> bool:
    """True for the recon table and its children, not a single dotted key."""
    return parts[:2] == _RECON_PARTS


def _scan(lines: list[str]) -> _Scan:
    multiline: str | None = None
    headers: list[tuple[int, _Header]] = []
    flags: list[bool] = []
    seen_table = False
    for index, line in enumerate(lines):
        flags.append(multiline is not None)
        multiline, header = _consume_line(line, multiline)
        if header is not None:
            if header.array and _is_recon_parts(header.parts):
                raise CodexConfigError("mcp_servers.recon is an array of tables; edit that table by hand")
            headers.append((index, header))
            seen_table = True
            continue
        if not seen_table:
            _refuse_inline_recon(line)
    if multiline is not None:
        raise CodexConfigError("a multiline string is not closed")
    return _Scan(tuple(headers), tuple(flags))


def _refuse_inline_recon(line: str) -> None:
    parts = _assignment_parts(line)
    if parts is not None and _is_recon_parts(parts):
        raise CodexConfigError("mcp_servers.recon is an inline assignment; edit that entry by hand")


def _recon_spans(lines: list[str], scan: _Scan) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    headers = scan.headers
    for position, (start, header) in enumerate(headers):
        if not _is_recon_parts(header.parts):
            continue
        following = headers[position + 1][0] if position + 1 < len(headers) else len(lines)
        spans.append((start, _trim_trailing(lines, scan, start, following)))
    return spans


def _trim_trailing(lines: list[str], scan: _Scan, start: int, end: int) -> int:
    while end - 1 > start and _is_outside_comment(lines, scan, end - 1):
        end -= 1
    return end


def _is_outside_comment(lines: list[str], scan: _Scan, index: int) -> bool:
    if scan.multiline_at_start[index]:
        return False
    stripped = lines[index].strip()
    return stripped == "" or stripped.startswith("#")


def _parse_spans(lines: list[str], scan: _Scan, spans: list[tuple[int, int]]) -> _Parsed:
    command: str | None = None
    args: tuple[str, ...] | None = None
    complete = True
    env: dict[str, str] = {}
    headers = dict(scan.headers)
    for start, end in spans:
        header = headers[start]
        assignments, parsed_ok = _assignments(lines[start + 1 : end])
        if header.parts == _RECON_PARTS:
            command, args, complete = _parent_fields(assignments, parsed_ok)
        elif header.parts == _ENV_PARTS:
            env = _env_fields(assignments)
    return _Parsed(command, args, complete, env)


def _parent_fields(
    assignments: dict[str, object],
    parsed_ok: bool,
) -> tuple[str | None, tuple[str, ...] | None, bool]:
    command_text = assignments.get("command")
    command = command_text if isinstance(command_text, str) else None
    arg_list = _string_tuple(assignments.get("args"))
    complete = parsed_ok and command is not None and arg_list is not None
    return command, arg_list, complete


def _env_fields(assignments: dict[str, object]) -> dict[str, str]:
    env: dict[str, str] = {}
    for key, value in assignments.items():
        if isinstance(value, str):
            env[key] = value
    return env


def _matches(parsed: _Parsed, block: Mapping[str, object]) -> bool:
    args = _string_list(block.get("args"))
    same_command = parsed.command == block.get("command")
    return parsed.complete and same_command and args is not None and parsed.args == tuple(args)


def _splice(lines: list[str], spans: list[tuple[int, int]], rendered: str) -> str:
    covered = _covered(spans)
    rendered_lines = _lines(rendered)
    output: list[str] = []
    index = 0
    while index < len(lines):
        if index == spans[0][0]:
            output.extend(rendered_lines)
            index = spans[0][1]
            continue
        if index in covered:
            index += 1
            continue
        output.append(lines[index])
        index += 1
    return "".join(output)


def _covered(spans: list[tuple[int, int]]) -> set[int]:
    indexes: set[int] = set()
    for start, end in spans:
        indexes.update(range(start, end))
    return indexes


def _assignments(body: list[str]) -> tuple[dict[str, object], bool]:
    values: dict[str, object] = {}
    pending: list[str] = []
    ok = True
    for line in body:
        pending.append(line.rstrip("\r\n"))
        joined = "\n".join(pending)
        if not _value_complete(joined):
            continue
        key, value, parsed = _one_assignment(joined)
        pending = []
        if key is None:
            continue
        if not parsed or value is None:
            ok = False
            continue
        values[key] = value
    if pending:
        ok = False
    return values, ok


def _one_assignment(text: str) -> tuple[str | None, object | None, bool]:
    stripped = text.strip()
    if not stripped or stripped.startswith("#"):
        return None, None, True
    equals = _equals_index(stripped)
    if equals is None:
        return None, None, False
    try:
        key = _normalize_key(stripped[:equals].strip())
    except CodexConfigError:
        return None, None, False
    value, parsed = _parse_value(stripped[equals + 1 :].strip())
    return key, value, parsed


def _value_complete(text: str) -> bool:
    stripped = text.strip()
    if not stripped or stripped.startswith("#"):
        return True
    equals = _equals_index(stripped)
    if equals is None:
        return False
    return _expression_closed(stripped[equals + 1 :])


def _consume_line(line: str, multiline: str | None) -> tuple[str | None, _Header | None]:
    content = line.rstrip("\r\n")
    if multiline is not None:
        closed = _find_multiline_end(content, 0, multiline)
        if closed is None:
            return multiline, None
        _scan_code(content, closed, header_allowed=False, fail_on_bracket=True)
        return None, None
    return _scan_code(content, 0, header_allowed=True, fail_on_bracket=False)


def _scan_code(
    content: str,
    index: int,
    *,
    header_allowed: bool,
    fail_on_bracket: bool,
) -> tuple[str | None, _Header | None]:
    index = _skip_ws(content, index)
    if index >= len(content) or content[index] == "#":
        return None, None
    if header_allowed and content[index] == "[":
        header, index = _parse_header(content, index)
        _require_trailer(content, index)
        return None, header
    return _scan_strings(content, index, fail_on_bracket=fail_on_bracket), None


def _require_trailer(content: str, index: int) -> None:
    index = _skip_ws(content, index)
    if index < len(content) and content[index] != "#":
        raise CodexConfigError("a table header line has trailing text")


def _scan_strings(content: str, index: int, *, fail_on_bracket: bool) -> str | None:
    while index < len(content):
        char = content[index]
        if char == "#":
            return None
        if fail_on_bracket and char == "[":
            raise CodexConfigError("a table header shares a line with another value")
        if char in {'"', "'"}:
            opened = _open_string(content, index)
            if opened is None:
                index += 1
                continue
            kind, resume = opened
            if kind in {'"""', "'''"} and resume is None:
                return kind
            index = resume if resume is not None else index + 1
            continue
        index += 1
    return None


def _open_string(content: str, index: int) -> tuple[str, int | None] | None:
    char = content[index]
    if content.startswith(char * 3, index):
        closed = _find_multiline_end(content, index + 3, char * 3)
        return char * 3, None if closed is None else closed
    return char, _skip_single_string(content, index)


def _parse_header(content: str, index: int) -> tuple[_Header, int]:
    array = content.startswith("[[", index)
    marker = "]]" if array else "]"
    index += 2 if array else 1
    parts, index = _parse_dotted_name(content, index)
    if not content.startswith(marker, index):
        raise CodexConfigError("a table header is not closed")
    return _Header(parts, array), index + len(marker)


def _parse_dotted_name(content: str, index: int) -> tuple[tuple[str, ...], int]:
    parts: list[str] = []
    while index < len(content):
        index = _skip_ws(content, index)
        if index >= len(content) or content[index] in "].#":
            break
        part, index = _parse_name_part(content, index)
        parts.append(part)
        index = _skip_ws(content, index)
        if index < len(content) and content[index] == ".":
            index += 1
            continue
        break
    if not parts:
        raise CodexConfigError("a table name is empty")
    return tuple(parts), index


def _parse_name_part(content: str, index: int) -> tuple[str, int]:
    if content[index] in {'"', "'"}:
        return _parse_quoted_key(content, index)
    start = index
    while index < len(content) and (content[index].isalnum() or content[index] in "_-"):
        index += 1
    if start == index:
        raise CodexConfigError("a table name could not be read")
    return content[start:index], index


def _assignment_parts(line: str) -> tuple[str, ...] | None:
    content = line.strip()
    if not content or content.startswith("#"):
        return None
    equals = _equals_index(content)
    if equals is None:
        return None
    try:
        return _key_parts(content[:equals].strip())
    except CodexConfigError:
        return None


def _normalize_key(raw: str) -> str:
    return ".".join(_key_parts(raw))


def _key_parts(raw: str) -> tuple[str, ...]:
    if not raw:
        raise CodexConfigError("an assignment key is empty")
    parts: list[str] = []
    index = 0
    while index < len(raw):
        index = _skip_ws(raw, index)
        if index >= len(raw):
            break
        part, index = _parse_name_part(raw, index)
        parts.append(part)
        index = _skip_ws(raw, index)
        if index < len(raw) and raw[index] == ".":
            index += 1
            continue
        if index != len(raw):
            raise CodexConfigError("an assignment key could not be read")
        break
    if not parts:
        raise CodexConfigError("an assignment key is empty")
    return tuple(parts)


def _equals_index(content: str) -> int | None:
    index = 0
    while index < len(content):
        char = content[index]
        if char == "=":
            return index
        if char in {'"', "'"}:
            opened = _open_string(content, index)
            if opened is None:
                return None
            _, resume = opened
            if resume is None:
                return None
            index = resume
            continue
        index += 1
    return None


def _expression_closed(expression: str) -> bool:
    index = 0
    depth = 0
    while index < len(expression):
        char = expression[index]
        if char in {'"', "'"}:
            opened = _open_string(expression, index)
            if opened is None:
                return False
            _, resume = opened
            if resume is None:
                return False
            index = resume
            continue
        if char == "#":
            newline = expression.find("\n", index)
            if newline < 0:
                break
            index = newline + 1
            continue
        if char == "[":
            depth += 1
        elif char == "]":
            depth -= 1
        index += 1
    return depth <= 0


def _parse_value(raw: str) -> tuple[object | None, bool]:
    if raw.startswith("["):
        return _parse_string_array(raw)
    if raw.startswith(('"', "'")):
        try:
            text, _resume = _parse_quoted_key(raw, 0)
        except CodexConfigError:
            return None, False
        return text, True
    return None, False


def _parse_string_array(raw: str) -> tuple[tuple[str, ...] | None, bool]:
    if not raw.startswith("["):
        return None, False
    items: list[str] = []
    index = _skip_array_gap(raw, 1)
    while index < len(raw):
        if raw[index] == "]":
            return tuple(items), True
        if raw[index] == ",":
            index = _skip_array_gap(raw, index + 1)
            continue
        if raw[index] not in {'"', "'"}:
            return None, False
        try:
            item, index = _parse_quoted_key(raw, index)
        except CodexConfigError:
            return None, False
        items.append(item)
        index = _skip_array_gap(raw, index)
    return None, False


def _skip_array_gap(raw: str, index: int) -> int:
    """Skip whitespace and comments between array items, including newlines."""
    while index < len(raw):
        char = raw[index]
        if char in " \t\r\n":
            index += 1
            continue
        if char == "#":
            newline = raw.find("\n", index)
            if newline < 0:
                return len(raw)
            index = newline + 1
            continue
        break
    return index


def _parse_quoted_key(content: str, index: int) -> tuple[str, int]:
    if content.startswith('"""', index) or content.startswith("'''", index):
        raise CodexConfigError("a multiline string is not a supported key or value here")
    quote = content[index]
    end = _skip_single_string(content, index)
    inner = content[index + 1 : end - 1]
    if quote == "'":
        return inner, end
    decoded = _unescape_basic(inner)
    if decoded is None:
        raise CodexConfigError("a string escape could not be read")
    return decoded, end


def _skip_single_string(content: str, index: int) -> int:
    quote = content[index]
    index += 1
    while index < len(content):
        char = content[index]
        if quote == '"' and char == "\\":
            index += 2
            continue
        if char == quote:
            return index + 1
        index += 1
    raise CodexConfigError("a string is not closed")


def _find_multiline_end(content: str, index: int, delim: str) -> int | None:
    quote = delim[0]
    if quote == "'":
        found = content.find(delim, index)
        return None if found < 0 else found + 3
    while index < len(content):
        if content[index] == "\\":
            index += 2
            continue
        if content.startswith(delim, index):
            return index + 3
        index += 1
    return None


def _unescape_basic(raw: str) -> str | None:
    parts: list[str] = []
    index = 0
    simple = {"b": "\b", "t": "\t", "n": "\n", "f": "\f", "r": "\r", '"': '"', "\\": "\\"}
    while index < len(raw):
        char = raw[index]
        if char != "\\":
            parts.append(char)
            index += 1
            continue
        decoded, resume = _decode_escape(raw, index + 1, simple)
        if decoded is None or resume is None:
            return None
        parts.append(decoded)
        index = resume
    return "".join(parts)


def _decode_escape(raw: str, index: int, simple: dict[str, str]) -> tuple[str | None, int | None]:
    if index >= len(raw):
        return None, None
    char = raw[index]
    if char in simple:
        return simple[char], index + 1
    width = 4 if char == "u" else 8 if char == "U" else 0
    if width == 0 or index + 1 + width > len(raw):
        return None, None
    hex_digits = raw[index + 1 : index + 1 + width]
    try:
        return chr(int(hex_digits, 16)), index + 1 + width
    except ValueError:
        return None, None


def _escaped(char: str) -> str:
    mapping = {"\\": "\\\\", '"': '\\"', "\b": "\\b", "\t": "\\t", "\n": "\\n", "\f": "\\f", "\r": "\\r"}
    if char in mapping:
        return mapping[char]
    if ord(char) < 32:
        return f"\\u{ord(char):04x}"
    return char


def _toml_key(key: str) -> str:
    if key and key[0].isalpha() and key.replace("_", "").replace("-", "").isalnum():
        return key
    return toml_basic_string(key)


def _skip_ws(content: str, index: int) -> int:
    while index < len(content) and content[index] in " \t":
        index += 1
    return index


def _string_tuple(value: object) -> tuple[str, ...] | None:
    if not isinstance(value, tuple):
        return None
    items: list[str] = []
    for item in cast(tuple[object, ...], value):
        if not isinstance(item, str):
            return None
        items.append(item)
    return tuple(items)


def _string_list(value: object) -> list[str] | None:
    if not isinstance(value, list):
        return None
    items: list[str] = []
    for item in cast(list[object], value):
        if not isinstance(item, str):
            return None
        items.append(item)
    return items


def _string_dict(value: object) -> dict[str, str] | None:
    mapping = _as_object_dict(value)
    if mapping is None:
        return None
    env: dict[str, str] = {}
    for key, item in mapping.items():
        if not isinstance(item, str):
            return None
        env[key] = item
    return env


def _as_object_dict(value: object) -> dict[str, object] | None:
    if not isinstance(value, dict):
        return None
    return cast(dict[str, object], value)
