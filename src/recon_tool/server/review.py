"""Fresh single-namespace ReviewBundle MCP tool."""

from __future__ import annotations

import asyncio
import logging
import math
import time
import uuid
from datetime import UTC, datetime
from typing import Any, Literal, cast

from typing_extensions import TypedDict

from recon_tool.mcp_client.sdk_compat import ToolError, tool_annotations
from recon_tool.models import ReconLookupError
from recon_tool.review_bundle import (
    ReviewCollectionContext,
    build_review_error_bundle,
)
from recon_tool.review_bundle import build_review_bundle as build_review_bundle_from_info
from recon_tool.server import app as server_app
from recon_tool.server.app import mcp
from recon_tool.server.runtime import log_structured, log_validation_failed, rate_limit_try_acquire
from recon_tool.validator import validate_domain

logger = logging.getLogger("recon")


class ReviewBundleResult(TypedDict):
    """Top-level structured result; the resource publishes the exact schema."""

    record_type: Literal["review_bundle"]
    schema_version: Literal["1.0"]
    generated_at: str
    generator: dict[str, Any]
    interpretation_context: dict[str, Any]
    scope: dict[str, Any]
    collection: dict[str, Any]
    source_opportunities: list[dict[str, Any]]
    workflow: dict[str, Any]
    result: dict[str, Any]
    scope_statement: str
    limitations: list[str]
    content_digest: str


def _review_timeout(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
        raise ToolError("Error: timeout_seconds must be a finite positive number")
    if value > 600:
        raise ToolError("Error: timeout_seconds must not exceed 600 seconds")
    return float(value)


def _failure_kind(error: ReconLookupError) -> Literal["lookup", "timeout"]:
    return "timeout" if error.error_type == "timeout" else "lookup"


@mcp.tool(
    annotations=tool_annotations(
        read_only=True,
        destructive=False,
        idempotent=True,
        open_world=True,
    ),
)
async def build_review_bundle(
    domain: str,
    no_ct: bool = False,
    timeout_seconds: float = 120.0,
) -> ReviewBundleResult:
    """Build one fresh, evidence-linked NamespaceReviewBundle artifact.

    The tool bypasses recon's lookup-result cache and performs exactly one
    ordinary passive resolution for the caller-supplied namespace. Direct
    probes are always disabled. Certificate-transparency collection remains on
    by default and can be disabled with ``no_ct``. The explained lookup,
    source-opportunity states, evidence ledger, and review candidates all
    derive from the same in-memory result.

    The returned artifact is a public-metadata handoff, not a security score,
    vulnerability finding, compliance result, ownership conclusion, or proof
    of active product use. Its digest detects modification but is not a digital
    signature or collector authentication.

    Args:
        domain: Namespace coordinate to reduce to its registrable apex.
        no_ct: Skip certificate-transparency providers when true.
        timeout_seconds: Aggregate resolution timeout, greater than zero and at
            most 600 seconds.

    Returns:
        A schema-version-1 ReviewBundle success or typed collection failure.
    """
    request_id = uuid.uuid4().hex[:12]
    timeout = _review_timeout(timeout_seconds)
    try:
        validated = validate_domain(domain)
    except ValueError as exc:
        log_validation_failed(request_id)
        raise ToolError(server_app.invalid_domain_message(exc)) from exc

    if not rate_limit_try_acquire(validated):
        raise ToolError(f"Rate limited: {validated} was collected recently. Try again in a few seconds.")

    # The recorded observation window begins only when the fresh resolver is
    # about to run. Local argument validation and rate-limit admission are not
    # collection opportunities and must not inflate the artifact window.
    started_at = datetime.now(UTC)
    started_monotonic = time.monotonic()
    try:
        info, results = await server_app.resolve_tenant(
            validated,
            timeout=timeout,
            skip_ct=no_ct,
            active_probes=False,
        )
    except ReconLookupError as exc:
        ended_at = datetime.now(UTC)
        try:
            bundle = build_review_error_bundle(
                domain,
                ReviewCollectionContext(
                    started_at=started_at,
                    ended_at=ended_at,
                    ct_enabled=not no_ct,
                    timeout_seconds=timeout,
                    vantage="mcp-server",
                ),
                _failure_kind(exc),
                (source for source, _detail in exc.source_errors),
            )
        except Exception as composition_error:
            logger.exception(
                "Unexpected error composing a failed review bundle for %s (request_id=%s)",
                validated,
                request_id,
            )
            detail = server_app.internal_lookup_error(
                validated,
                request_id,
                composition_error,
                "composing a failed review bundle for",
            )
            raise ToolError(detail) from composition_error
        log_structured(
            logging.INFO,
            "review_failed",
            request_id=request_id,
            domain=validated,
            elapsed_s=round(time.monotonic() - started_monotonic, 2),
            error_type=exc.error_type,
        )
        return cast(ReviewBundleResult, bundle)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        logger.exception(
            "Unexpected error building a review bundle for %s (request_id=%s)",
            validated,
            request_id,
        )
        detail = server_app.internal_lookup_error(validated, request_id, exc, "building a review bundle for")
        raise ToolError(detail) from exc

    ended_at = datetime.now(UTC)
    try:
        bundle = build_review_bundle_from_info(
            info,
            results,
            domain,
            ReviewCollectionContext(
                started_at=started_at,
                ended_at=ended_at,
                ct_enabled=not no_ct,
                timeout_seconds=timeout,
                vantage="mcp-server",
            ),
        )
    except Exception as exc:
        logger.exception(
            "Unexpected error composing a review bundle for %s (request_id=%s)",
            validated,
            request_id,
        )
        detail = server_app.internal_lookup_error(validated, request_id, exc, "composing a review bundle for")
        raise ToolError(detail) from exc

    log_structured(
        logging.INFO,
        "review_built",
        request_id=request_id,
        domain=validated,
        elapsed_s=round(time.monotonic() - started_monotonic, 2),
        collection_validity=bundle["workflow"]["collection_validity"],
    )
    return cast(ReviewBundleResult, bundle)
