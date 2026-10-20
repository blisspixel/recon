"""Qualifiers that must read the same on every human surface.

Two caveats travel with a lookup result wherever it is shown: the panel,
``--plain``, ``--md`` and the MCP text format. Each surface takes its wording
from here, so a qualifier cannot survive on one surface and drop off another
(``docs/design-language.md``).

* The display name is provider-reported. It comes from an identity endpoint
  (for Microsoft 365, the GetUserRealm federation brand name), which the tenant
  administrator sets and anyone can request. recon never verifies it, so every
  human surface marks it ``(unverified)``. When no provider name was observed
  the display name falls back to the queried domain, which is not a provider
  claim and carries no qualifier.
* A reserved special-use name (``example.com``, ``.test``, ``.invalid`` and the
  rest of :data:`recon_tool.validator.SPECIAL_USE_SUFFIXES`) can still return
  public DNS and identity answers. Those answers are residue, so the result
  says so before anything else.
"""

from __future__ import annotations

from typing import Final

from rich.text import Text

from recon_tool.formatter.theme import MUTED
from recon_tool.models import TenantInfo
from recon_tool.validator import is_special_use_name

DISPLAY_NAME_QUALIFIER: Final = "(unverified)"
RESERVED_NAME_STATEMENT: Final = "Reserved name: results are public residue, not an organization."


def display_name_is_reported(info: TenantInfo) -> bool:
    """True when the display name is a provider-reported string, not the domain fallback."""
    return bool(info.display_name) and info.display_name != info.queried_domain


def qualified_display_name(info: TenantInfo) -> str:
    """The display name with its ``(unverified)`` qualifier when provider-reported."""
    if display_name_is_reported(info):
        return f"{info.display_name} {DISPLAY_NAME_QUALIFIER}"
    return info.display_name


def is_reserved_name(info: TenantInfo) -> bool:
    """True when the queried name is a reserved special-use name."""
    return is_special_use_name(info.queried_domain)


def reserved_name_statement(info: TenantInfo) -> str | None:
    """The reserved-name note for a reserved queried name, otherwise ``None``."""
    return RESERVED_NAME_STATEMENT if is_reserved_name(info) else None


def render_panel_title(info: TenantInfo) -> Text:
    """The panel's title block: display name, queried domain, reserved note.

    When the display name falls back to the queried namespace it renders once,
    bold, instead of the same string twice. A provider-reported name carries the
    ``(unverified)`` word in the muted role: the word is the carrier, the color
    only quiets it. A reserved queried name adds one line under the title.
    """
    header = Text()
    header.append(info.display_name, style="bold")
    if display_name_is_reported(info):
        header.append(f" {DISPLAY_NAME_QUALIFIER}", style=MUTED)
    if info.queried_domain != info.display_name:
        header.append("\n")
        header.append(info.queried_domain, style=MUTED)
    statement = reserved_name_statement(info)
    if statement is not None:
        label, _, rest = statement.partition(":")
        header.append("\n")
        header.append(f"{label}:", style="bold")
        header.append(rest)
    return header
