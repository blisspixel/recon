"""Doctor row for a RECON_CONFIG_DIR value recon will not use."""

from __future__ import annotations

from recon_tool.cli.doctor_report import DoctorCheck
from recon_tool.paths import ignored_config_dir


def config_directory_check() -> DoctorCheck | None:
    """Warn when ``RECON_CONFIG_DIR`` cannot name a durable directory.

    An absolute path keeps today's row set. A placeholder or relative value
    is ignored by ``paths.py``; this row names the placeholder token and not
    the resolved fallback path.
    """
    ignored = ignored_config_dir()
    if ignored is None:
        return None
    kind, token = ignored
    if kind == "placeholder":
        return DoctorCheck(
            "Config directory",
            "warn",
            f"ignoring RECON_CONFIG_DIR because it contains unexpanded {token}",
            "Set RECON_CONFIG_DIR to an absolute directory, or unset it.",
        )
    return DoctorCheck(
        "Config directory",
        "warn",
        "ignoring RECON_CONFIG_DIR because it is not an absolute path",
        "Set RECON_CONFIG_DIR to an absolute directory, or unset it.",
    )
