"""Registrable-domain (apex) reduction via the Public Suffix List.

recon's signal is apex-level: tenant resolution, MX, SPF/``_dmarc``, DKIM,
MTA-STS, and certificate-transparency discovery all live at, or are keyed off,
the registrable domain (eTLD+1) rather than an arbitrary sub-host. So a pasted
browser URL like ``https://mail.example.co.uk/login`` should be analyzed as
``example.co.uk``.

Finding the eTLD+1 correctly requires the Public Suffix List: a naive
"last two labels" rule mis-handles ``co.uk``, ``com.au``, and every other
multi-label public suffix. ``publicsuffixlist`` carries the real list, is
pure-Python with zero required runtime dependencies, and bundles its own
updater, so this stays within recon's lean, offline dependency floor.
"""

from __future__ import annotations

from publicsuffixlist import PublicSuffixList

# Parse the bundled suffix list once. Construction reads and indexes the
# packaged data file, so a module-level singleton avoids re-parsing it on every
# lookup. Importing this module is what pays that one-time cost, which is why
# validator.py imports psl lazily (only when apex reduction is actually needed).
_PSL = PublicSuffixList()


def to_apex(host: str) -> str:
    """Reduce *host* to its registrable domain (eTLD+1).

    ``mail.example.co.uk`` -> ``example.co.uk``; ``www.example.com`` ->
    ``example.com``; an unknown TLD degrades gracefully (the bundled list
    treats it as a single-label suffix, so ``foo.bar.newtld`` ->
    ``bar.newtld``).

    Returns *host* unchanged when it has no registrable part above the public
    suffix (the input is itself a public suffix such as ``co.uk``), so the
    caller always gets a usable, already-validated value to fall back on rather
    than ``None``.

    Expects an already-normalized lowercase host (punycode for IDNs), as
    produced by the earlier stages of ``recon_tool.validator.validate_domain``.
    """
    return _PSL.privatesuffix(host) or host
