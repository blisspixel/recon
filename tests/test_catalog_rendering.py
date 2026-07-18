"""Copy-safe narrow rendering for catalog fields."""

from __future__ import annotations

from io import StringIO

from rich.console import Console

from recon_tool.cli.catalog_rendering import MAX_CATALOG_DISPLAY_LENGTH, print_field, print_indented


def test_long_catalog_values_remain_exact_and_indented() -> None:
    stream = StringIO()
    console = Console(file=stream, width=20, no_color=True)
    reference = "https://docs.example.invalid/a/long/authentication/reference"
    pattern = "^an-unbroken-catalog-pattern-[a-z0-9]{32}$"

    print_field(console, "Reference", reference, indent=4)
    print_indented(console, pattern, indent=6)

    output = stream.getvalue()
    assert reference in output
    assert pattern in output
    assert all(not line or line.startswith("    ") for line in output.splitlines())


def test_field_stacks_when_label_would_leave_an_impractical_value_column() -> None:
    stream = StringIO()
    console = Console(file=stream, width=40, no_color=True)

    print_field(
        console,
        "Catalog description",
        "An existing public record description remains readable",
        indent=9,
    )

    assert stream.getvalue().splitlines() == [
        "         Catalog description:",
        "           An existing public record",
        "           description remains readable",
    ]


def test_catalog_values_strip_terminal_controls_and_report_truncation() -> None:
    stream = StringIO()
    console = Console(file=stream, width=80, no_color=True)
    hostile = "visible\x1b[31m\a\n\u202e" + ("x" * (MAX_CATALOG_DISPLAY_LENGTH + 20))

    print_field(console, "Catalog description", hostile, indent=2)

    output = stream.getvalue()
    assert "\x1b" not in output
    assert "\a" not in output
    assert "\u202e" not in output
    assert "[truncated after 1024 characters]" in output
    assert output.count("x") < MAX_CATALOG_DISPLAY_LENGTH + 20
