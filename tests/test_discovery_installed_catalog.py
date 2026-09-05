"""Discovery uses the installed effective catalog, never source-only YAML."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from recon_tool.discovery import find_candidates, load_existing_patterns

_ROOT = Path(__file__).resolve().parents[1]
_INSTALLED_PROBE = r"""
import asyncio
import importlib
import json
import socket
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

site = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(site))
import recon_tool
assert Path(recon_tool.__file__).resolve().parent == site / "recon_tool"
assert not (site / "recon_tool/data/fingerprints").exists()
assert (site / "recon_tool/data/fingerprints.generated.json").is_file()

from recon_tool.discovery import load_runtime_patterns
from recon_tool.fingerprints import DetectionRule, Fingerprint, clear_ephemeral, inject_ephemeral
from recon_tool.models import TenantInfo, UnclassifiedCnameChain

assert "cloudfront.net" in load_runtime_patterns()
assert "custom.vendor.invalid" in load_runtime_patterns()
assert "root-only.vendor.invalid" not in load_runtime_patterns()
info = TenantInfo(
    tenant_id=None,
    display_name="Synthetic Alpha",
    default_domain="alpha.invalid",
    queried_domain="alpha.invalid",
    unclassified_cname_chains=tuple(
        UnclassifiedCnameChain(subdomain=f"portal{index}.alpha.invalid", chain=(host,))
        for index, host in enumerate((
            "tenant.cloudfront.net",
            "tenant.custom.vendor.invalid",
            "tenant.ephemeral.vendor.invalid",
            "tenant.unclassified.vendor.invalid",
        ))
    ),
)

def run_discovery():
    if sys.argv[2] == "cli":
        from typer.testing import CliRunner
        from recon_tool.cli import app
        resolver = AsyncMock(return_value=(info, []))
        with patch("recon_tool.resolver.resolve_tenant", resolver):
            result = CliRunner().invoke(app, ["discover", "alpha.invalid"])
        assert result.exit_code == 0, result.output
        resolver.assert_awaited_once()
        return json.loads(result.stdout)
    introspection = importlib.import_module("recon_tool.server.introspection")
    resolver = AsyncMock(side_effect=AssertionError("cached discovery must not collect"))
    with patch.object(introspection, "cache_get", return_value=(info, [])), patch.object(
        introspection.server_app, "resolve_tenant", resolver
    ):
        result = asyncio.run(introspection.discover_fingerprint_candidates("alpha.invalid"))
    resolver.assert_not_awaited()
    return result

original_connect = socket.socket.connect
def local_connect(sock, address):
    # Windows event loops use a loopback socketpair for their self-pipe.
    if isinstance(address, tuple) and address[0] in {"127.0.0.1", "::1"}:
        return original_connect(sock, address)
    raise AssertionError("external network disabled")

with patch.object(socket.socket, "connect", local_connect):
    before = run_discovery()
    inject_ephemeral(Fingerprint(
        name="Synthetic Ephemeral Provider", slug="synthetic-ephemeral-provider",
        category="SaaS", confidence="high", m365=False,
        detections=(DetectionRule(type="cname_target", pattern="ephemeral.vendor.invalid"),),
    ))
    during = run_discovery()
    clear_ephemeral()
    after = run_discovery()

assert [row["suffix"] for row in before] == ["ephemeral.vendor.invalid", "unclassified.vendor.invalid"]
assert [row["suffix"] for row in during] == ["unclassified.vendor.invalid"]
assert after == before
print(json.dumps({"before": len(before), "during": len(during), "after": len(after)}))
"""


@pytest.fixture(scope="module")
def installed_layout(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    root = tmp_path_factory.mktemp("discovery-installed-layout")
    site = root / "site"
    # Reproduce the wheel's package layout without a build dependency or a
    # checkout import: source fingerprint YAML is intentionally not shipped.
    shutil.copytree(
        _ROOT / "src/recon_tool",
        site / "recon_tool",
        ignore=shutil.ignore_patterns("__pycache__", "fingerprints"),
    )
    config = root / "config"
    config.mkdir()
    (config / "fingerprints.yaml").write_text(
        "fingerprints:\n"
        "- name: Synthetic Custom Provider\n"
        "  slug: synthetic-custom-provider\n"
        "  category: SaaS\n"
        "  confidence: high\n"
        "  detections:\n"
        "  - type: cname_target\n"
        "    pattern: custom.vendor.invalid\n"
        "  - type: cname\n"
        "    pattern: root-only.vendor.invalid\n",
        encoding="utf-8",
    )
    return site, config


@pytest.mark.parametrize("caller", ["cli", "mcp"])
def test_installed_discovery_uses_builtin_custom_and_current_ephemeral_patterns(
    installed_layout: tuple[Path, Path], caller: str
) -> None:
    site, config = installed_layout
    env = os.environ.copy()
    env["RECON_CONFIG_DIR"] = str(config)
    result = subprocess.run(  # noqa: S603 - fixed isolated Python probe with reserved fixtures.
        [sys.executable, "-I", "-c", _INSTALLED_PROBE, str(site), caller],
        cwd=site.parent,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"before": 2, "during": 1, "after": 2}


def test_explicit_yaml_directory_does_not_fall_back_to_runtime_catalog(tmp_path: Path) -> None:
    runs = [("alpha.invalid", [{"subdomain": "portal.alpha.invalid", "chain": ["tenant.cloudfront.net"]}])]
    selected = tmp_path / "selected-catalog"
    selected.mkdir()
    (selected / "fingerprints.yaml").write_text(
        "fingerprints:\n- detections:\n  - type: cname_target\n    pattern: selected.vendor.invalid\n",
        encoding="utf-8",
    )

    assert load_existing_patterns(selected) == {"selected.vendor.invalid"}
    assert len(find_candidates(runs, fingerprints_dir=selected)) == 1
    assert load_existing_patterns(tmp_path / "missing") == set()
    assert len(find_candidates(runs, fingerprints_dir=tmp_path / "missing")) == 1
