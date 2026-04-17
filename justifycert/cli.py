"""Command line interface for justifycert."""

from __future__ import annotations

import argparse
import json

from .core import analyze_domain, analyze_pem_file


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="justifycert", description="Analyze a TLS certificate for common issues.")
    parser.add_argument("domain", nargs="?", help="Domain name to inspect over TLS")
    parser.add_argument("--file", dest="pem_file", help="Path to a PEM-encoded certificate")
    parser.add_argument("--json", action="store_true", help="Print JSON output")
    parser.add_argument("--port", type=int, default=443, help="TLS port for domain analysis")
    parser.add_argument("--timeout", type=float, default=5.0, help="Socket timeout in seconds")
    return parser


def format_human(result: dict) -> str:
    if result["valid"]:
        return "✔ Valid certificate"

    lines = ["✖ Issues found:"]
    for issue in result["issues"]:
        lines.append(f"- {issue['message']}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if bool(args.domain) == bool(args.pem_file):
        parser.error("Provide either a domain or --file, but not both.")

    if args.pem_file:
        result = analyze_pem_file(args.pem_file)
    else:
        result = analyze_domain(args.domain, port=args.port, timeout=args.timeout)

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(format_human(result))

    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
