from __future__ import annotations

from dataclasses import dataclass
from typing import Any, cast

import httpx
import pytest
from starlette.types import Receive, Scope, Send

import recon_tool.remote_server as remote_server
from recon_tool.mcp_client import sdk_compat
from recon_tool.remote_server import (
    RemoteConfig,
    RemoteConfigurationError,
    RemoteSecurityMiddleware,
    build_remote_application,
    prepare_remote_mcp,
)

TOKEN = "a" * 48


def _config(**overrides: Any) -> RemoteConfig:
    values: dict[str, Any] = {
        "auth_mode": "static-bearer",
        "bearer_token": TOKEN,
        "bind_host": "0.0.0.0",  # noqa: S104
        "port": 8080,
        "max_request_bytes": 1024,
        "allowed_hosts": frozenset(),
        "allowed_origins": frozenset(),
    }
    values.update(overrides)
    return RemoteConfig(**values)


async def _echo_app(scope: Scope, receive: Receive, send: Send) -> None:
    body = b""
    if scope["type"] == "http":
        message = await receive()
        if message["type"] == "http.request":
            body = message.get("body", b"")
    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"application/octet-stream")],
        }
    )
    await send({"type": "http.response.body", "body": body})


def test_remote_config_requires_a_strong_static_bearer() -> None:
    with pytest.raises(RemoteConfigurationError, match="required"):
        RemoteConfig.from_environ({})
    with pytest.raises(RemoteConfigurationError, match="at least 32 bytes"):
        RemoteConfig.from_environ({"RECON_REMOTE_BEARER_TOKEN": "short"})
    with pytest.raises(RemoteConfigurationError, match="without whitespace"):
        RemoteConfig.from_environ({"RECON_REMOTE_BEARER_TOKEN": "a" * 31 + " "})


def test_remote_config_reads_a_valid_static_bearer_from_the_process_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("RECON_REMOTE_BEARER_TOKEN", TOKEN)

    config = RemoteConfig.from_environ()

    assert config.auth_mode == "static-bearer"
    assert config.bearer_token == TOKEN
    assert "bearer_token" not in repr(config)
    assert config.port == 8080
    assert config.max_request_bytes == 1024 * 1024


def test_remote_config_supports_explicit_trusted_platform_auth() -> None:
    config = RemoteConfig.from_environ(
        {
            "RECON_REMOTE_AUTH_MODE": "trusted-platform",
            "RECON_REMOTE_HOST": "127.0.0.1",
            "RECON_REMOTE_PORT": "8000",
            "RECON_REMOTE_MAX_REQUEST_BYTES": "2048",
            "RECON_REMOTE_ALLOWED_HOSTS": "recon.example,recon.example:443",
            "RECON_REMOTE_ALLOWED_ORIGINS": "https://console.example/",
        }
    )

    assert config.auth_mode == "trusted-platform"
    assert config.bearer_token is None
    assert config.bind_host == "127.0.0.1"
    assert config.port == 8000
    assert config.max_request_bytes == 2048
    assert config.allowed_hosts == frozenset({"recon.example", "recon.example:443"})
    assert config.allowed_origins == frozenset({"https://console.example"})


@pytest.mark.parametrize(
    ("environment", "message"),
    [
        ({"RECON_REMOTE_AUTH_MODE": "none"}, "AUTH_MODE"),
        (
            {"RECON_REMOTE_AUTH_MODE": "trusted-platform", "RECON_REMOTE_BEARER_TOKEN": TOKEN},
            "must be unset",
        ),
        ({"RECON_REMOTE_AUTH_MODE": "trusted-platform", "RECON_REMOTE_PORT": "NaN"}, "integer"),
        ({"RECON_REMOTE_AUTH_MODE": "trusted-platform", "RECON_REMOTE_HOST": "bad host"}, "HOST"),
        (
            {"RECON_REMOTE_AUTH_MODE": "trusted-platform", "RECON_REMOTE_MAX_REQUEST_BYTES": "999"},
            "between 1024",
        ),
        ({"RECON_REMOTE_AUTH_MODE": "trusted-platform", "RECON_REMOTE_PORT": "0"}, "between 1 and 65535"),
        (
            {"RECON_REMOTE_AUTH_MODE": "trusted-platform", "RECON_REMOTE_ALLOWED_HOSTS": "https://bad.example"},
            "exact host values",
        ),
        (
            {"RECON_REMOTE_AUTH_MODE": "trusted-platform", "RECON_REMOTE_ALLOWED_ORIGINS": "https://example.com/path"},
            "without paths",
        ),
    ],
)
def test_remote_config_rejects_ambiguous_or_malformed_values(
    environment: dict[str, str],
    message: str,
) -> None:
    with pytest.raises(RemoteConfigurationError, match=message):
        RemoteConfig.from_environ(environment)


@pytest.mark.parametrize(
    "origin",
    [
        "ftp://example.com",
        "https:///missing-host",
        "https://user@example.com",
        "https://user:password@example.com",
        "https://example.com/path",
        "https://example.com?query=yes",
        "https://example.com#fragment",
    ],
)
def test_remote_config_rejects_non_origin_urls(origin: str) -> None:
    with pytest.raises(RemoteConfigurationError, match="without paths"):
        RemoteConfig.from_environ(
            {
                "RECON_REMOTE_AUTH_MODE": "trusted-platform",
                "RECON_REMOTE_ALLOWED_ORIGINS": origin,
            }
        )


def test_remote_config_rejects_non_ascii_bearers_and_whitespace_hosts() -> None:
    with pytest.raises(RemoteConfigurationError, match="ASCII bearer"):
        RemoteConfig.from_environ({"RECON_REMOTE_BEARER_TOKEN": "a" * 31 + "é"})
    with pytest.raises(RemoteConfigurationError, match="exact host"):
        RemoteConfig.from_environ(
            {
                "RECON_REMOTE_AUTH_MODE": "trusted-platform",
                "RECON_REMOTE_ALLOWED_HOSTS": "bad host",
            }
        )


@pytest.mark.asyncio
async def test_health_is_unauthenticated_but_has_security_headers() -> None:
    app = RemoteSecurityMiddleware(_echo_app, _config())
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://recon.example") as client:
        response = await client.get("/health")

    assert response.status_code == 200
    assert response.text == "ok\n"
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://recon.example") as client:
        head = await client.head("/health")

    assert head.status_code == 200
    assert head.content == b""


@pytest.mark.asyncio
async def test_static_bearer_fails_closed_and_authorized_body_is_replayed() -> None:
    app = RemoteSecurityMiddleware(_echo_app, _config())
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://recon.example") as client:
        missing = await client.post("/mcp", content=b"request")
        wrong = await client.post("/mcp", content=b"request", headers={"Authorization": "Bearer wrong"})
        malformed = await client.post("/mcp", content=b"request", headers={"Authorization": TOKEN})
        accepted = await client.post(
            "/mcp",
            content=b"request",
            headers={"Authorization": f"Bearer {TOKEN}"},
        )
        authorized_get = await client.get("/mcp", headers={"Authorization": f"Bearer {TOKEN}"})

    assert missing.status_code == 401
    assert missing.headers["www-authenticate"] == "Bearer"
    assert wrong.status_code == 401
    assert malformed.status_code == 401
    assert accepted.status_code == 200
    assert accepted.content == b"request"
    assert accepted.headers["referrer-policy"] == "no-referrer"
    assert authorized_get.status_code == 200


@pytest.mark.asyncio
async def test_host_origin_method_and_size_guards_reject_before_dispatch() -> None:
    config = _config(
        allowed_hosts=frozenset({"recon.example"}),
        allowed_origins=frozenset({"https://console.example"}),
    )
    app = RemoteSecurityMiddleware(_echo_app, config)
    auth = {"Authorization": f"Bearer {TOKEN}"}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://recon.example") as client:
        wrong_host = await client.post("https://other.example/mcp", content=b"x", headers=auth)
        wrong_origin = await client.post(
            "/mcp",
            content=b"x",
            headers={**auth, "Origin": "https://other.example"},
        )
        allowed_origin = await client.post(
            "/mcp",
            content=b"x",
            headers={**auth, "Origin": "https://console.example"},
        )
        health_post = await client.post("/health")
        oversized = await client.post("/mcp", content=b"x" * 1025, headers=auth)

    assert wrong_host.status_code == 421
    assert wrong_origin.status_code == 403
    assert allowed_origin.status_code == 200
    assert health_post.status_code == 405
    assert health_post.headers["allow"] == "GET, HEAD"
    assert oversized.status_code == 413


@pytest.mark.asyncio
async def test_trusted_platform_mode_relies_on_the_outer_ingress() -> None:
    app = RemoteSecurityMiddleware(
        _echo_app,
        _config(auth_mode="trusted-platform", bearer_token=None),
    )
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://recon.example") as client:
        response = await client.post("/mcp", content=b"platform-authenticated")

    assert response.status_code == 200
    assert response.content == b"platform-authenticated"


def _scope(*, headers: list[tuple[bytes, bytes]], method: str = "POST") -> Scope:
    return cast(
        Scope,
        {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": method,
            "scheme": "https",
            "path": "/mcp",
            "raw_path": b"/mcp",
            "query_string": b"",
            "root_path": "",
            "headers": headers,
            "client": ("127.0.0.1", 1234),
            "server": ("recon.example", 443),
        },
    )


async def _invoke(
    app: RemoteSecurityMiddleware,
    scope: Scope,
    incoming: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    messages = list(incoming)
    sent: list[dict[str, Any]] = []

    async def receive() -> Any:
        return messages.pop(0)

    async def send(message: Any) -> None:
        sent.append(message)

    await app(scope, receive, send)
    return sent


@pytest.mark.asyncio
async def test_duplicate_security_headers_and_invalid_content_lengths_fail_closed() -> None:
    app = RemoteSecurityMiddleware(_echo_app, _config())
    auth = (b"authorization", f"Bearer {TOKEN}".encode())
    host = (b"host", b"recon.example")
    cases = [
        ([(b"host", b""), auth], 400),
        ([host, (b"origin", b"https://one.example"), (b"origin", b"https://two.example"), auth], 403),
        ([host, auth, auth], 401),
        ([host, auth, (b"content-length", b"1"), (b"content-length", b"1")], 400),
        ([host, auth, (b"content-length", b"NaN")], 400),
        ([host, auth, (b"content-length", b"-1")], 400),
    ]

    for headers, expected_status in cases:
        sent = await _invoke(
            app,
            _scope(headers=headers),
            [{"type": "http.request", "body": b"x", "more_body": False}],
        )
        assert sent[0]["status"] == expected_status


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("incoming", "expected_status"),
    [
        ([{"type": "http.disconnect"}], 400),
        ([{"type": "http.request", "body": "not-bytes", "more_body": False}], 400),
        (
            [
                {"type": "extension.message"},
                {"type": "http.request", "body": b"x" * 700, "more_body": True},
                {"type": "http.request", "body": b"x" * 400, "more_body": False},
            ],
            413,
        ),
    ],
)
async def test_streamed_body_errors_fail_closed(
    incoming: list[dict[str, Any]],
    expected_status: int,
) -> None:
    app = RemoteSecurityMiddleware(_echo_app, _config())
    sent = await _invoke(
        app,
        _scope(
            headers=[
                (b"host", b"recon.example"),
                (b"authorization", f"Bearer {TOKEN}".encode()),
            ]
        ),
        incoming,
    )

    assert sent[0]["status"] == expected_status


@pytest.mark.asyncio
async def test_replayed_request_disconnects_after_its_single_body() -> None:
    receive = remote_server._replay_receive(b"request")

    first = await receive()
    second = await receive()

    assert first == {"type": "http.request", "body": b"request", "more_body": False}
    assert second == {"type": "http.disconnect"}


@pytest.mark.asyncio
async def test_non_http_scopes_preserve_lifespan_but_reject_websockets() -> None:
    dispatched: list[str] = []

    async def recording_app(scope: Scope, receive: Receive, send: Send) -> None:
        dispatched.append(scope["type"])

    async def receive() -> Any:
        return {"type": "lifespan.shutdown"}

    sent: list[dict[str, Any]] = []

    async def send(message: Any) -> None:
        sent.append(message)

    app = RemoteSecurityMiddleware(recording_app, _config())
    lifespan_scope = cast(Scope, {"type": "lifespan", "asgi": {"version": "3.0"}, "state": {}})
    websocket_scope = cast(
        Scope,
        {
            "type": "websocket",
            "asgi": {"version": "3.0"},
            "scheme": "wss",
            "path": "/mcp",
            "raw_path": b"/mcp",
            "query_string": b"",
            "root_path": "",
            "headers": [],
            "client": ("127.0.0.1", 1234),
            "server": ("recon.example", 443),
            "subprotocols": [],
        },
    )

    await app(lifespan_scope, receive, send)
    await app(websocket_scope, receive, send)

    assert dispatched == ["lifespan"]
    assert sent == [{"type": "websocket.close", "code": 1008, "reason": "unsupported"}]


@dataclass
class _Annotations:
    """v1-shaped annotations: the hint is the camelCase attribute itself."""

    readOnlyHint: bool | None


@dataclass
class _ModernAnnotations:
    """v2-shaped annotations: the hint is snake_case and camelCase is only an alias.

    The two generations expose disjoint attribute names, so reading one spelling
    returns nothing on the other generation. For this allow-list that meant every
    tool looked non-read-only and the remote surface came up empty.
    """

    read_only_hint: bool | None


@dataclass
class _Tool:
    name: str
    annotations: _Annotations | None


@dataclass
class _Settings:
    host: str = "127.0.0.1"
    json_response: bool = False
    stateless_http: bool = False
    transport_security: object | None = object()


class _FakeMCP:
    def __init__(self) -> None:
        self.settings = _Settings()
        self.removed: list[str] = []
        self.application = _echo_app
        self.tools = [
            _Tool("lookup_tenant", _Annotations(True)),
            _Tool("inject_ephemeral_fingerprint", _Annotations(False)),
            _Tool("list_ephemeral_fingerprints", _Annotations(True)),
            _Tool("unannotated", None),
        ]

    async def list_tools(self) -> list[_Tool]:
        return self.tools

    def remove_tool(self, name: str) -> None:
        self.removed.append(name)

    def streamable_http_app(self) -> Any:
        return self.application


class _ModernFakeMCP:
    """v2-shaped application: no settings object, transport options are kwargs."""

    def __init__(self) -> None:
        self.removed: list[str] = []
        self.application = _echo_app
        self.transport_kwargs: dict[str, Any] = {}
        self.tools = [
            _Tool("lookup_tenant", _ModernAnnotations(True)),
            _Tool("inject_ephemeral_fingerprint", _ModernAnnotations(False)),
            _Tool("list_ephemeral_fingerprints", _ModernAnnotations(True)),
            _Tool("unannotated", None),
        ]

    async def list_tools(self) -> list[_Tool]:
        return self.tools

    def remove_tool(self, name: str) -> None:
        self.removed.append(name)

    def streamable_http_app(self, **kwargs: Any) -> Any:
        self.transport_kwargs = kwargs
        return self.application


@pytest.mark.asyncio
async def test_remote_mcp_is_stateless_and_exposes_only_useful_read_only_tools(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sdk_compat, "SDK_FAMILY", "v1")
    fake = _FakeMCP()

    application = await prepare_remote_mcp(fake)

    assert application is _echo_app
    assert fake.removed == [
        "inject_ephemeral_fingerprint",
        "list_ephemeral_fingerprints",
        "unannotated",
    ]
    assert fake.settings.host == "0.0.0.0"  # noqa: S104
    assert fake.settings.json_response is True
    assert fake.settings.stateless_http is True
    assert fake.settings.transport_security is None


def test_build_remote_application_wraps_the_filtered_mcp(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sdk_compat, "SDK_FAMILY", "v1")
    application = build_remote_application(_config(), _FakeMCP())

    assert isinstance(application, RemoteSecurityMiddleware)


@pytest.mark.asyncio
async def test_remote_mcp_reads_read_only_hints_on_the_modern_sdk(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The allow-list must survive the SDK generation split.

    v1 exposes `readOnlyHint` and v2 exposes `read_only_hint`, with no attribute
    under the other spelling. Reading only the v1 name made every tool look
    non-read-only on v2, so the adapter would have removed all of them and
    served an empty surface rather than a restricted one.
    """
    monkeypatch.setattr(sdk_compat, "SDK_FAMILY", "v2")
    fake = _ModernFakeMCP()

    application = await prepare_remote_mcp(fake)

    assert application is _echo_app
    assert fake.removed == [
        "inject_ephemeral_fingerprint",
        "list_ephemeral_fingerprints",
        "unannotated",
    ]
    assert "lookup_tenant" not in fake.removed


@pytest.mark.asyncio
async def test_modern_sdk_receives_transport_options_as_arguments(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """v2 removed the mutable settings object these values used to be set on."""
    monkeypatch.setattr(sdk_compat, "SDK_FAMILY", "v2")
    fake = _ModernFakeMCP()

    await prepare_remote_mcp(fake)

    assert fake.transport_kwargs == {
        "host": "0.0.0.0",  # noqa: S104
        "json_response": True,
        "stateless_http": True,
        "transport_security": None,
    }
