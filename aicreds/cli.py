"""CLI entry point for AIHound."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from aicreds import __version__
from aicreds.core.platform import detect_platform
from aicreds.scanners import get_all_scanners
from aicreds.output.table import print_banner, print_results
from aicreds.output.json_export import export_json
from aicreds.output.html_report import export_html

# Resolve the banner image path relative to the project root
_PACKAGE_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _PACKAGE_DIR.parent
_DEFAULT_BANNER = _PROJECT_ROOT / "aihound.png"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aihound",
        description="AIHound - AI Credential & Secrets Scanner",
    )
    parser.add_argument(
        "--version", action="version", version=f"aihound {__version__}"
    )
    parser.add_argument(
        "--show-secrets",
        action="store_true",
        help="Show actual credential values (USE WITH CAUTION)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Output results as JSON to stdout",
    )
    parser.add_argument(
        "--json-file",
        type=str,
        metavar="PATH",
        help="Write JSON report to file",
    )
    parser.add_argument(
        "--html-file",
        type=str,
        metavar="PATH",
        help="Write HTML report to file",
    )
    parser.add_argument(
        "--banner",
        type=str,
        metavar="PATH",
        help="Custom banner image for HTML report (default: aihound.png)",
    )
    parser.add_argument(
        "--tools",
        nargs="+",
        metavar="TOOL",
        help="Only scan specific tools (use slugs from --list-tools)",
    )
    parser.add_argument(
        "--list-tools",
        action="store_true",
        help="List all available scanners and exit",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show debug output (paths checked, errors, notes)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    scanners = get_all_scanners()

    # --list-tools
    if args.list_tools:
        print("Available scanners:")
        for s in scanners:
            applicable = "yes" if s.is_applicable() else "no (not applicable on this platform)"
            print(f"  {s.slug():<20} {s.name():<30} Applicable: {applicable}")
        return 0

    # --show-secrets safety gate
    show_secrets = False
    if args.show_secrets:
        if sys.stdin.isatty():
            print(
                "\nWARNING: --show-secrets will display raw credential values.\n"
                "This should only be used on YOUR OWN machine for research purposes.\n"
            )
            try:
                confirm = input("Type 'YES' to confirm: ")
                if confirm.strip() != "YES":
                    print("Aborted.")
                    return 1
            except (EOFError, KeyboardInterrupt):
                print("\nAborted.")
                return 1
        show_secrets = True

    # Filter scanners
    if args.tools:
        tool_slugs = set(args.tools)
        scanners = [s for s in scanners if s.slug() in tool_slugs]
        if not scanners:
            print(f"No scanners matched: {args.tools}", file=sys.stderr)
            print("Use --list-tools to see available scanners.", file=sys.stderr)
            return 1

    # Filter by platform applicability
    scanners = [s for s in scanners if s.is_applicable()]

    # Print banner (unless JSON-only output)
    if not args.json_output:
        plat = detect_platform()
        print_banner(no_color=args.no_color)
        print(f"Platform: {plat.value}")
        if plat.value == "wsl":
            print("WSL detected - scanning both Linux and Windows credential paths\n")
        else:
            print()

    # Run scanners
    results = []
    for scanner in scanners:
        if args.verbose and not args.json_output:
            print(f"Scanning: {scanner.name()}...")
        result = scanner.run(show_secrets=show_secrets)
        results.append(result)

    # Output
    if args.json_output:
        export_json(results, file=sys.stdout)
    else:
        print_results(results, no_color=args.no_color, verbose=args.verbose)

    if args.json_file:
        export_json(results, filepath=args.json_file)
        print(f"\nJSON report written to: {args.json_file}")

    if args.html_file:
        banner = Path(args.banner) if args.banner else _DEFAULT_BANNER
        export_html(results, filepath=args.html_file, banner_path=banner)
        print(f"HTML report written to: {args.html_file}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
