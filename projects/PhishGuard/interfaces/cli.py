"""CLI entrypoint for PhishGuard URL threat analysis."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.scorer import analyze_url

LOGGER = logging.getLogger(__name__)


def configure_logging(verbose: bool) -> None:
    """Configure process-wide logging."""
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )


def build_parser() -> argparse.ArgumentParser:
    """Build argument parser for CLI interface."""
    parser = argparse.ArgumentParser(
        description="PhishGuard - Automated URL Threat Analyzer",
    )
    parser.add_argument("--url", required=True, help="URL to analyze")
    parser.add_argument("--json", action="store_true", help="Output raw JSON report")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    return parser


def print_human_report(report: dict[str, object]) -> None:
    """Print human-readable analysis report."""
    print("PhishGuard URL Threat Analysis")
    print("=" * 32)
    print(f"URL           : {report['url']}")
    print(f"Risk Score    : {report['risk_score']}/100")
    print(f"Classification: {report['classification']}")
    print(f"Confidence    : {float(report['confidence']) * 100:.1f}%")
    print()
    print("Detected Signals")
    print("-" * 32)

    signals = report.get("signals_detected", [])
    if not isinstance(signals, list) or not signals:
        print("No signals detected.")
        return

    for signal in signals:
        if not isinstance(signal, dict):
            continue
        print(
            f"[{signal.get('tier')}] {signal.get('description')} "
            f"({signal.get('impact', 0):+d})"
        )
        print(f"  id      : {signal.get('id')}")
        print(f"  evidence: {signal.get('evidence')}")


def main() -> int:
    """Run CLI analyzer and return process exit code."""
    parser = build_parser()
    args = parser.parse_args()

    configure_logging(args.verbose)

    try:
        report = analyze_url(args.url).to_dict()
    except Exception as exc:  # pragma: no cover - defensive boundary
        LOGGER.exception("Unexpected analysis failure")
        print(f"Analysis failed: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report, indent=2))
        return 0

    print_human_report(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())