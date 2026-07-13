"""Package artifact invariants for recon's intentionally small box.

These tests build a local wheel and inspect the archive directly. They pin the
traceability-matrix invariant that the package ships only the intended data
catalogs, and that runtime dependencies stay lean and free of ML, GeoIP, ASN, or
paid-vendor SDK surfaces.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tarfile
import zipfile
from email.parser import Parser
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]

_EXPECTED_DATA_FILES = {
    "recon_tool/data/bayesian_network.yaml",
    "recon_tool/data/fingerprints.generated.json",
    "recon_tool/data/motifs.yaml",
    "recon_tool/data/posture.yaml",
    "recon_tool/data/profiles/fintech.yaml",
    "recon_tool/data/profiles/healthcare.yaml",
    "recon_tool/data/profiles/high-value-target.yaml",
    "recon_tool/data/profiles/higher-ed.yaml",
    "recon_tool/data/profiles/public-sector.yaml",
    "recon_tool/data/profiles/saas-b2b.yaml",
    "recon_tool/data/recon-schema.json",
    "recon_tool/data/signals.yaml",
    "recon_tool/data/surface-inventory.json",
}

_CANONICAL_FINGERPRINT_SOURCES = {
    "ai.yaml",
    "crm-marketing.yaml",
    "data-analytics.yaml",
    "discovered-signals.yaml",
    "email.yaml",
    "infrastructure.yaml",
    "productivity.yaml",
    "security.yaml",
    "surface.yaml",
    "verifications.yaml",
    "verticals.yaml",
}

_EXPECTED_RUNTIME_DEPENDENCIES = {
    "deal",
    "defusedxml",
    "dnspython",
    "httpx",
    "mcp",
    "networkx",
    "publicsuffixlist",
    "python-multipart",
    "pyyaml",
    "rich",
    "typer",
}

_FORBIDDEN_DATA_SUFFIXES = {
    ".bin",
    ".csv",
    ".db",
    ".feather",
    ".geojson",
    ".joblib",
    ".mmdb",
    ".npy",
    ".npz",
    ".onnx",
    ".parquet",
    ".pickle",
    ".pkl",
    ".pt",
    ".pth",
    ".sqlite",
    ".sqlite3",
}

_FORBIDDEN_RUNTIME_DEPENDENCIES = {
    "azure-identity",
    "azure-mgmt-resource",
    "boto3",
    "botocore",
    "geoip2",
    "google-cloud",
    "google-cloud-compute",
    "maxminddb",
    "numpy",
    "pandas",
    "pyarrow",
    "pyasn",
    "pymc",
    "scikit-learn",
    "scipy",
    "sklearn",
    "stan",
    "tensorflow",
    "torch",
}


def _build_wheel(tmp_path: Path) -> Path:
    out_dir = tmp_path / "dist"
    uv_exe = shutil.which("uv")
    assert uv_exe is not None, "uv is required to build the wheel"
    result = subprocess.run(  # noqa: S603 - fixed dev-tool argv, no shell.
        [uv_exe, "build", "--out-dir", str(out_dir)],
        cwd=_REPO_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    wheels = sorted(out_dir.glob("*.whl"))
    assert len(wheels) == 1
    return wheels[0]


def _build_sdist(tmp_path: Path) -> Path:
    out_dir = tmp_path / "dist"
    uv_exe = shutil.which("uv")
    assert uv_exe is not None, "uv is required to build the sdist"
    result = subprocess.run(  # noqa: S603 - fixed dev-tool argv, no shell.
        [uv_exe, "build", "--sdist", "--out-dir", str(out_dir)],
        cwd=_REPO_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    sdists = sorted(out_dir.glob("*.tar.gz"))
    assert len(sdists) == 1
    return sdists[0]


def _runtime_dependency_names(metadata_text: str) -> set[str]:
    metadata = Parser().parsestr(metadata_text)
    names: set[str] = set()
    for requirement in metadata.get_all("Requires-Dist") or []:
        match = re.match(r"\s*([A-Za-z0-9_.-]+)", requirement)
        assert match is not None, f"could not parse Requires-Dist: {requirement!r}"
        names.add(match.group(1).replace("_", "-").lower())
    return names


def test_wheel_ships_only_expected_catalog_data(tmp_path: Path) -> None:
    wheel = _build_wheel(tmp_path)
    assert wheel.name.endswith("-py3-none-any.whl")
    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())

    data_files = {name for name in names if name.startswith("recon_tool/data/") and not name.endswith("/")}
    assert data_files == _EXPECTED_DATA_FILES

    forbidden_data = {
        name for name in data_files if Path(name).suffix.lower() in _FORBIDDEN_DATA_SUFFIXES
    }
    assert forbidden_data == set()

    unexpected_top_levels = {
        name.split("/", 1)[0]
        for name in names
        if "/" in name and not name.startswith("recon_tool/") and ".dist-info" not in name.split("/", 1)[0]
    }
    assert unexpected_top_levels == set()


def test_sdist_retains_canonical_fingerprint_sources_and_generated_artifact(tmp_path: Path) -> None:
    sdist = _build_sdist(tmp_path)
    with tarfile.open(sdist, "r:gz") as archive:
        names = {Path(name).as_posix() for name in archive.getnames()}

    fingerprint_sources = {
        Path(name).name
        for name in names
        if "/src/recon_tool/data/fingerprints/" in name and name.endswith(".yaml")
    }
    assert fingerprint_sources == _CANONICAL_FINGERPRINT_SOURCES
    assert any(name.endswith("/src/recon_tool/data/fingerprints.generated.json") for name in names)


def test_wheel_runtime_dependencies_stay_lean(tmp_path: Path) -> None:
    wheel = _build_wheel(tmp_path)
    with zipfile.ZipFile(wheel) as archive:
        metadata_name = next(name for name in archive.namelist() if name.endswith(".dist-info/METADATA"))
        metadata_text = archive.read(metadata_name).decode("utf-8")

    dependency_names = _runtime_dependency_names(metadata_text)
    assert dependency_names == _EXPECTED_RUNTIME_DEPENDENCIES
    assert dependency_names.isdisjoint(_FORBIDDEN_RUNTIME_DEPENDENCIES)
