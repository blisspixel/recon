from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any, cast

import yaml

ROOT = Path(__file__).resolve().parents[1]


def _load_fuzzer() -> Any:
    spec = importlib.util.spec_from_file_location(
        "recon_input_fuzzer",
        ROOT / "fuzz" / "recon_input_fuzzer.py",
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    cast(Any, spec.loader).exec_module(module)
    return module


def test_clusterfuzzlite_project_is_python() -> None:
    payload = yaml.safe_load((ROOT / ".clusterfuzzlite" / "project.yaml").read_text(encoding="utf-8"))

    assert payload == {"language": "python"}


def test_clusterfuzzlite_builder_image_is_digest_pinned() -> None:
    dockerfile = (ROOT / ".clusterfuzzlite" / "Dockerfile").read_text(encoding="utf-8")

    assert "FROM gcr.io/oss-fuzz-base/base-builder-python@sha256:" in dockerfile
    assert ":latest" not in dockerfile


def test_clusterfuzzlite_python_dependencies_are_hash_pinned() -> None:
    build_script = (ROOT / ".clusterfuzzlite" / "build.sh").read_text(encoding="utf-8")
    requirements = (ROOT / ".clusterfuzzlite" / "requirements.txt").read_text(encoding="utf-8")

    assert "--require-hashes -r \"$SRC/recon/.clusterfuzzlite/requirements.txt\"" in build_script
    assert build_script.count("pip install") == 1
    assert "export PYTHONPATH=\"$SRC/recon/src${PYTHONPATH:+:$PYTHONPATH}\"" in build_script
    assert "--hidden-import recon_tool.formatter.serialize" in build_script
    assert "--hash=sha256:" in requirements


def test_clusterfuzzlite_workflow_is_bounded_and_pinned() -> None:
    workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "clusterfuzzlite.yml").read_text(encoding="utf-8"))
    job = workflow["jobs"]["pr-fuzz"]
    steps = job["steps"]

    assert workflow["permissions"] == {"contents": "read"}
    assert job["timeout-minutes"] == 25
    assert steps[0]["with"]["persist-credentials"] is False
    assert steps[1]["uses"] == "google/clusterfuzzlite/actions/build_fuzzers@884713a6c30a92e5e8544c39945cd7cb630abcd1"
    assert steps[2]["uses"] == "google/clusterfuzzlite/actions/run_fuzzers@884713a6c30a92e5e8544c39945cd7cb630abcd1"
    assert steps[2]["with"]["fuzz-seconds"] == 180
    assert steps[2]["with"]["mode"] == "code-change"


def test_recon_input_fuzzer_accepts_seed_inputs() -> None:
    module = _load_fuzzer()

    for seed in (b"", b"https://www.contoso.example/path?q=1", b"\x1b[31m_bad\nvalue", b"xn--mnchen-3ya.de"):
        module.TestOneInput(seed)
