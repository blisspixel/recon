#!/usr/bin/env bash
# Installer / updater for recon (macOS / Linux).
#
# Review this file from a release-tag checkout, then install or update with:
#   bash scripts/install.sh
#
# Uninstall:
#   uv tool uninstall recon-tool   # or: pipx uninstall recon-tool
#
# Preserves the manager that already owns recon. For a clean install, prefers
# uv (fast, manages its own Python) and falls back to pipx. The reviewed helper
# installs the exact release version represented by this source tag.

set -euo pipefail

PACKAGE="recon-tool"
VERSION="2.19.0"
SPEC="${PACKAGE}==${VERSION}"
CLI="recon"

have() { command -v "$1" >/dev/null 2>&1; }

package_owned_by() {
    local manager="$1"
    shift
    local output
    if ! output=$("$@" 2>&1); then
        echo "Error: could not inspect $manager ownership for $PACKAGE." >&2
        printf '%s\n' "$output" >&2
        return 2
    fi
    printf '%s\n' "$output" | grep -Eq "(^|[^[:alnum:]_-])${PACKAGE}([^[:alnum:]_-]|$)"
}

install_exact_uv() {
    echo "==> Installing reviewed $SPEC with uv ..."
    if ! uv tool install --force "$SPEC"; then
        echo "Error: uv could not install $SPEC." >&2
        exit 1
    fi
}

install_exact_pipx() {
    echo "==> Installing reviewed $SPEC with pipx ..."
    if ! pipx install --force "$SPEC"; then
        echo "Error: pipx could not install $SPEC." >&2
        exit 1
    fi
}

fail_missing_tool() {
    echo "Error: install uv or pipx first, then re-run this installer." >&2
    echo "Recommended:" >&2
    echo "  https://docs.astral.sh/uv/getting-started/installation/" >&2
    echo "Alternative:" >&2
    echo "  https://pipx.pypa.io/stable/installation/" >&2
    exit 1
}

cli_candidates() {
    # Bash's type -a -P returns executable PATH candidates in resolution order.
    # Deduplicate and cap diagnostics so a hostile or accidental PATH cannot
    # flood installer output.
    type -a -P "$CLI" 2>/dev/null | awk '!seen[$0]++' | sed -n '1,20p' || :
}

print_cli_diagnostics() {
    local resolved="$1"
    local candidates="$2"
    if [ -n "$resolved" ]; then
        printf 'Resolved launcher: %s\n' "$resolved" >&2
    else
        echo "Resolved launcher: (not found)" >&2
    fi
    echo "Discovered candidates:" >&2
    if [ -n "$candidates" ]; then
        while IFS= read -r candidate; do
            printf '  %s\n' "${candidate:0:1024}" >&2
        done <<< "$candidates"
    else
        echo "  (none)" >&2
    fi
}

verify_installed_cli() {
    local candidates resolved output bounded_output status expected
    hash -r
    candidates="$(cli_candidates)"
    resolved="${candidates%%$'\n'*}"
    expected="recon $VERSION"

    if [ -z "$resolved" ]; then
        echo "Error: $SPEC was installed, but no '$CLI' launcher resolves on PATH." >&2
        print_cli_diagnostics "$resolved" "$candidates"
        return 1
    fi

    if output=$("$resolved" --version 2>&1); then
        status=0
    else
        status=$?
    fi
    if [ "$status" -ne 0 ]; then
        echo "Error: $SPEC was installed, but '$resolved --version' exited $status." >&2
        print_cli_diagnostics "$resolved" "$candidates"
        return 1
    fi
    if [ "$output" = "$expected" ]; then
        echo "==> Verified $resolved reports $expected."
        return 0
    fi
    bounded_output="${output:0:512}"
    if [[ "$output" =~ ^recon[[:space:]]+[^[:space:]]+$ ]]; then
        printf "Error: %s was installed, but '%s --version' reported %q; expected %q.\n" \
            "$SPEC" "$resolved" "$bounded_output" "$expected" >&2
    else
        printf "Error: %s was installed, but '%s --version' returned malformed output %q; expected %q.\n" \
            "$SPEC" "$resolved" "$bounded_output" "$expected" >&2
    fi
    print_cli_diagnostics "$resolved" "$candidates"
    return 1
}

UV_AVAILABLE=false
PIPX_AVAILABLE=false
UV_OWNS=false
PIPX_OWNS=false

if have uv; then
    UV_AVAILABLE=true
    if package_owned_by uv uv tool list; then
        UV_OWNS=true
    elif [ "$?" -eq 2 ]; then
        exit 1
    fi
fi
if have pipx; then
    PIPX_AVAILABLE=true
    if package_owned_by pipx pipx list; then
        PIPX_OWNS=true
    elif [ "$?" -eq 2 ]; then
        exit 1
    fi
fi

if [ "$UV_AVAILABLE" = false ] && [ "$PIPX_AVAILABLE" = false ]; then
    fail_missing_tool
fi

if [ "$UV_OWNS" = true ] && [ "$PIPX_OWNS" = true ]; then
    echo "Error: both uv and pipx report an installed $PACKAGE." >&2
    echo "Uninstall one copy, confirm which 'recon' resolves on PATH, then re-run this helper." >&2
    exit 1
fi
if [ "$UV_OWNS" = false ] && [ "$PIPX_OWNS" = false ] && have "$CLI"; then
    echo "Error: an existing '$CLI' command is not owned by uv or pipx." >&2
    echo "Use 'recon update', or uninstall that copy before running this helper." >&2
    exit 1
fi

if [ "$UV_OWNS" = true ]; then
    MANAGER="uv"
    install_exact_uv
elif [ "$PIPX_OWNS" = true ]; then
    MANAGER="pipx"
    install_exact_pipx
elif [ "$UV_AVAILABLE" = true ]; then
    MANAGER="uv"
    install_exact_uv
elif [ "$PIPX_AVAILABLE" = true ]; then
    MANAGER="pipx"
    install_exact_pipx
else
    fail_missing_tool
fi

verify_installed_cli

echo ""
echo "==> Done. $SPEC installed with $MANAGER."
echo ""
echo "Next steps:"
echo "  1. Open a new terminal (so PATH updates take effect)"
echo "  2. Offline install check: $CLI --version"
echo "  3. Optional online source connectivity: $CLI doctor"
echo ""
echo "Quick start:"
echo "  DNS infrastructure may observe lookup queries; the only default"
echo "  target-owned HTTP request is the MTA-STS policy fetch. Google CSE"
echo "  and BIMI direct probes run only with --direct-probes."
echo "  $CLI \"<domain-you-want-to-review>\""
echo "  $CLI \"<domain-you-want-to-review>\" --json"
echo "  Syntax-only reserved example (live stray residue): $CLI example.com"
echo ""
echo "Optional: enable tab-completion with  $CLI --install-completion"
echo ""
echo "Update later: review and run the helper from the newer release tag."
echo "Uninstall:    uv tool uninstall $PACKAGE   (or: pipx uninstall $PACKAGE)"
echo ""
