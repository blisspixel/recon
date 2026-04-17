"""Domain intelligence CLI and MCP server — tech stack, email security, and signal intelligence from DNS."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("recon-tool")
except PackageNotFoundError:
    # Fallback for editable installs without metadata — kept in sync with
    # pyproject.toml. For true single-source versioning, consider hatch-vcs.
    __version__ = "1.0.0"
