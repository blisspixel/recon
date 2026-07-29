"""Optional authenticated Streamable HTTP entry point for recon's MCP server.

The supported product default remains the local stdio server. This module is a
small deployment adapter for operators who deliberately choose to run recon in
an authenticated container or managed runtime.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Literal, cast
from urllib.parse import urlsplit

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from recon_tool.mcp_client.sdk_compat import SDK_FAMILY
from recon_tool.server import mcp as default_mcp

AuthMode = Literal["static-bearer", "trusted-platform"]

_BODY_METHODS = frozenset({"PATCH", "POST", "PUT"})
_DEFAULT_MAX_REQUEST_BYTES = 1024 * 1024
_MAX_REQUEST_BYTES = 16 * 1024 * 1024
_MIN_BEARER_TOKEN_BYTES = 32
_REMOTE_ONLY_USELESS_TOOLS = frozenset({"list_ephemeral_fingerprints"})
_SECURITY_HEADERS = (
    (b"cache-control", b"no-store"),
    (b"referrer-policy", b"no-referrer"),
    (b"x-content-type-options", b"nosniff"),
)
_INVALID_CONTENT_LENGTH = (400, b'{"error":"invalid content length"}')
_REQUEST_TOO_LARGE = (413, b'{"error":"request too large"}')


class RemoteConfigurationError(ValueError):
    """Raised when the optional remote process is not configured safely."""


def _parse_int(name: str, value: str, *, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise RemoteConfigurationError(f"{name} must be an integer") from exc
    if not minimum <= parsed <= maximum:
        raise RemoteConfigurationError(f"{name} must be between {minimum} and {maximum}")
    return parsed


def _parse_csv(value: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in value.split(",") if item.strip())


def _validate_bind_host(value: str) -> str:
    host = value.strip()
    if not host or any(character.isspace() or ord(character) < 0x20 for character in host):
        raise RemoteConfigurationError("RECON_REMOTE_HOST must be a non-empty host without whitespace")
    return host


def _validate_allowed_hosts(value: str) -> frozenset[str]:
    hosts = _parse_csv(value)
    if any("/" in host or any(character.isspace() for character in host) for host in hosts):
        raise RemoteConfigurationError("RECON_REMOTE_ALLOWED_HOSTS must contain exact host values")
    return frozenset(host.casefold() for host in hosts)


def _validate_allowed_origins(value: str) -> frozenset[str]:
    origins = _parse_csv(value)
    for origin in origins:
        parsed = urlsplit(origin)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise RemoteConfigurationError(
                "RECON_REMOTE_ALLOWED_ORIGINS must contain exact HTTP or HTTPS origins without paths"
            )
    return frozenset(origin.rstrip("/").casefold() for origin in origins)


def _validate_bearer_token(value: str | None) -> str:
    if value is None or not value:
        raise RemoteConfigurationError("RECON_REMOTE_BEARER_TOKEN is required for static-bearer mode")
    if not value.isascii() or any(character.isspace() or ord(character) < 0x21 for character in value):
        raise RemoteConfigurationError("RECON_REMOTE_BEARER_TOKEN must be an ASCII bearer value without whitespace")
    if len(value.encode("ascii")) < _MIN_BEARER_TOKEN_BYTES:
        raise RemoteConfigurationError(
            f"RECON_REMOTE_BEARER_TOKEN must contain at least {_MIN_BEARER_TOKEN_BYTES} bytes"
        )
    return value


@dataclass(frozen=True, slots=True)
class RemoteConfig:
    """Validated process configuration for the optional remote entry point."""

    auth_mode: AuthMode
    bearer_token: str | None = field(repr=False)
    bind_host: str
    port: int
    max_request_bytes: int
    allowed_hosts: frozenset[str]
    allowed_origins: frozenset[str]

    @classmethod
    def from_environ(cls, environ: Mapping[str, str] | None = None) -> RemoteConfig:
        values = os.environ if environ is None else environ
        raw_auth_mode = values.get("RECON_REMOTE_AUTH_MODE", "static-bearer").strip().casefold()
        if raw_auth_mode not in {"static-bearer", "trusted-platform"}:
            raise RemoteConfigurationError("RECON_REMOTE_AUTH_MODE must be static-bearer or trusted-platform")
        auth_mode = cast(AuthMode, raw_auth_mode)

        raw_token = values.get("RECON_REMOTE_BEARER_TOKEN")
        if auth_mode == "static-bearer":
            bearer_token = _validate_bearer_token(raw_token)
        else:
            if raw_token:
                raise RemoteConfigurationError(
                    "RECON_REMOTE_BEARER_TOKEN must be unset when trusted-platform mode is selected"
                )
            bearer_token = None

        bind_host = _validate_bind_host(values.get("RECON_REMOTE_HOST", "0.0.0.0"))  # noqa: S104
        port = _parse_int(
            "RECON_REMOTE_PORT",
            values.get("RECON_REMOTE_PORT", "8080"),
            minimum=1,
            maximum=65535,
        )
        max_request_bytes = _parse_int(
            "RECON_REMOTE_MAX_REQUEST_BYTES",
            values.get("RECON_REMOTE_MAX_REQUEST_BYTES", str(_DEFAULT_MAX_REQUEST_BYTES)),
            minimum=1024,
            maximum=_MAX_REQUEST_BYTES,
        )

        return cls(
            auth_mode=auth_mode,
            bearer_token=bearer_token,
            bind_host=bind_host,
            port=port,
            max_request_bytes=max_request_bytes,
            allowed_hosts=_validate_allowed_hosts(values.get("RECON_REMOTE_ALLOWED_HOSTS", "")),
            allowed_origins=_validate_allowed_origins(values.get("RECON_REMOTE_ALLOWED_ORIGINS", "")),
        )


def _header_values(scope: Scope, name: bytes) -> tuple[str, ...]:
    raw_headers = cast(list[tuple[bytes, bytes]], scope.get("headers", []))
    return tuple(value.decode("latin-1") for key, value in raw_headers if key.lower() == name)


def _single_header(scope: Scope, name: bytes) -> str | None:
    values = _header_values(scope, name)
    if len(values) != 1:
        return None
    return values[0]


def _authorized(scope: Scope, token_digest: bytes) -> bool:
    authorization = _single_header(scope, b"authorization")
    if authorization is None:
        return False
    scheme, separator, credential = authorization.partition(" ")
    if separator != " " or scheme.casefold() != "bearer" or not credential:
        return False
    candidate_digest = hashlib.sha256(credential.encode("utf-8", errors="surrogatepass")).digest()
    return hmac.compare_digest(candidate_digest, token_digest)


async def _read_bounded_body(receive: Receive, limit: int) -> tuple[bytes | None, int | None]:
    parts: list[bytes] = []
    size = 0
    while True:
        message = await receive()
        if message["type"] == "http.disconnect":
            return None, 400
        if message["type"] != "http.request":
            continue
        body = message.get("body", b"")
        if not isinstance(body, bytes):
            return None, 400
        size += len(body)
        if size > limit:
            return None, 413
        parts.append(body)
        if not message.get("more_body", False):
            return b"".join(parts), None


def _replay_receive(body: bytes) -> Receive:
    delivered = False

    async def receive() -> Message:
        nonlocal delivered
        if delivered:
            return {"type": "http.disconnect"}
        delivered = True
        return {"type": "http.request", "body": body, "more_body": False}

    return receive


def _secured_send(send: Send) -> Send:
    async def secured(message: Message) -> None:
        if message["type"] == "http.response.start":
            headers = list(cast(list[tuple[bytes, bytes]], message.get("headers", [])))
            existing = {name.lower() for name, _ in headers}
            headers.extend(header for header in _SECURITY_HEADERS if header[0] not in existing)
            message = {**message, "headers": headers}
        await send(message)

    return secured


async def _send_response(
    scope: Scope,
    send: Send,
    response: tuple[int, bytes],
    *,
    content_type: bytes = b"application/json",
    extra_headers: tuple[tuple[bytes, bytes], ...] = (),
) -> None:
    status, body = response
    headers = [(b"content-type", content_type), (b"content-length", str(len(body)).encode("ascii"))]
    headers.extend(extra_headers)
    secured = _secured_send(send)
    await secured({"type": "http.response.start", "status": status, "headers": headers})
    response_body = b"" if scope.get("method") == "HEAD" else body
    await secured({"type": "http.response.body", "body": response_body})


async def _guard_host_and_origin(scope: Scope, send: Send, config: RemoteConfig) -> bool:
    host_values = _header_values(scope, b"host")
    if len(host_values) != 1 or not host_values[0].strip():
        await _send_response(scope, send, (400, b'{"error":"invalid host"}'))
        return False
    if config.allowed_hosts and host_values[0].casefold() not in config.allowed_hosts:
        await _send_response(scope, send, (421, b'{"error":"host not allowed"}'))
        return False

    origin_values = _header_values(scope, b"origin")
    if len(origin_values) > 1:
        await _send_response(scope, send, (403, b'{"error":"origin not allowed"}'))
        return False
    if origin_values:
        origin = origin_values[0].rstrip("/").casefold()
        if origin not in config.allowed_origins:
            await _send_response(scope, send, (403, b'{"error":"origin not allowed"}'))
            return False
    return True


async def _serve_health_if_requested(scope: Scope, send: Send) -> bool:
    if scope.get("path") != "/health":
        return False
    if scope.get("method") not in {"GET", "HEAD"}:
        await _send_response(
            scope,
            send,
            (405, b'{"error":"method not allowed"}'),
            extra_headers=((b"allow", b"GET, HEAD"),),
        )
        return True
    await _send_response(scope, send, (200, b"ok\n"), content_type=b"text/plain; charset=utf-8")
    return True


async def _guard_authentication(
    scope: Scope,
    send: Send,
    config: RemoteConfig,
    token_digest: bytes | None,
) -> bool:
    if config.auth_mode != "static-bearer":
        return True
    if token_digest is not None and _authorized(scope, token_digest):
        return True
    await _send_response(
        scope,
        send,
        (401, b'{"error":"unauthorized"}'),
        extra_headers=((b"www-authenticate", b"Bearer"),),
    )
    return False


def _content_length_error(scope: Scope, limit: int) -> tuple[int, bytes] | None:
    content_length_values = _header_values(scope, b"content-length")
    if len(content_length_values) > 1:
        return _INVALID_CONTENT_LENGTH
    if not content_length_values:
        return None
    try:
        content_length = int(content_length_values[0])
    except ValueError:
        return _INVALID_CONTENT_LENGTH
    if content_length < 0:
        return _INVALID_CONTENT_LENGTH
    if content_length > limit:
        return _REQUEST_TOO_LARGE
    return None


async def _bounded_request_receive(
    scope: Scope,
    receive: Receive,
    send: Send,
    limit: int,
) -> Receive | None:
    method = cast(str, scope.get("method", "GET")).upper()
    if method not in _BODY_METHODS:
        return receive

    content_length_error = _content_length_error(scope, limit)
    if content_length_error is not None:
        await _send_response(scope, send, content_length_error)
        return None

    body, body_error = await _read_bounded_body(receive, limit)
    if body_error is not None or body is None:
        status = 413 if body_error == 413 else 400
        detail = b'{"error":"request too large"}' if status == 413 else b'{"error":"invalid request body"}'
        await _send_response(scope, send, (status, detail))
        return None
    return _replay_receive(body)


class RemoteSecurityMiddleware:
    """Fail-closed HTTP boundary for the optional remote MCP application."""

    def __init__(self, app: ASGIApp, config: RemoteConfig) -> None:
        self.app = app
        self.config = config
        self._token_digest = (
            hashlib.sha256(config.bearer_token.encode("ascii")).digest() if config.bearer_token is not None else None
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "lifespan":
            await self.app(scope, receive, send)
            return
        if scope["type"] != "http":
            if scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 1008, "reason": "unsupported"})
            return
        if not await _guard_host_and_origin(scope, send, self.config):
            return
        if await _serve_health_if_requested(scope, send):
            return
        if not await _guard_authentication(scope, send, self.config, self._token_digest):
            return
        bounded_receive = await _bounded_request_receive(
            scope,
            receive,
            send,
            self.config.max_request_bytes,
        )
        if bounded_receive is None:
            return
        await self.app(scope, bounded_receive, _secured_send(send))


async def prepare_remote_mcp(mcp_app: Any) -> ASGIApp:
    """Restrict one MCP application to explicit read-only tools and HTTP."""
    tools = await mcp_app.list_tools()
    for tool in tools:
        annotations = getattr(tool, "annotations", None)
        is_explicitly_read_only = getattr(annotations, "readOnlyHint", None) is True
        if not is_explicitly_read_only or tool.name in _REMOTE_ONLY_USELESS_TOOLS:
            mcp_app.remove_tool(tool.name)

    mcp_app.settings.host = "0.0.0.0"  # noqa: S104
    mcp_app.settings.json_response = True
    mcp_app.settings.stateless_http = True
    # RemoteSecurityMiddleware owns Host and Origin validation. The SDK's
    # localhost-only defaults would reject managed-service hostnames.
    mcp_app.settings.transport_security = None
    return cast(ASGIApp, mcp_app.streamable_http_app())


def build_remote_application(config: RemoteConfig, mcp_app: Any | None = None) -> ASGIApp:
    """Build the optional remote ASGI application in a fresh server process."""
    if SDK_FAMILY != "v1":
        raise RemoteConfigurationError(
            "The optional remote adapter currently requires the supported MCP v1 production SDK"
        )
    active_mcp = default_mcp if mcp_app is None else mcp_app
    base_app = asyncio.run(prepare_remote_mcp(active_mcp))
    return RemoteSecurityMiddleware(base_app, config)


def main() -> None:  # pragma: no cover - exercised through container smoke tests
    """Run the optional remote MCP process."""
    import uvicorn

    config = RemoteConfig.from_environ()
    application = build_remote_application(config)
    uvicorn.run(
        application,
        host=config.bind_host,
        port=config.port,
        log_level="info",
        access_log=False,
        server_header=False,
    )


if __name__ == "__main__":  # pragma: no cover
    main()
