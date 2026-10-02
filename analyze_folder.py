"""Analyze the single-event XML files in the lab's evidence folder."""

import json
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

from parse_event import read_event
from detect_event import analyze

ROOT = Path(__file__).resolve().parent
EVIDENCE = ROOT / "evidence"
REPORTS = ROOT / "reports"


def main():
    if not EVIDENCE.is_dir():
        print(f"Evidence folder not found: {EVIDENCE}", file=sys.stderr)
        return 1

    files = sorted(EVIDENCE.glob("*.xml"))
    if not files:
        print("No XML evidence files found.", file=sys.stderr)
        return 1

    summary = {
        "files_found": len(files),
        "files_analyzed": 0,
        "matches": 0,
        "non_matches": 0,
        "inconclusive": 0,
        "errors": 0,
    }
    results = []
    errors = []

    for path in files:
        try:
            result = analyze(read_event(path))
        except (OSError, ET.ParseError, ValueError) as error:
            errors.append({
                "source_file": path.name,
                "error": str(error),
            })
            summary["errors"] += 1
            continue

        result["source_file"] = path.name
        results.append(result)
        summary["files_analyzed"] += 1

        if result["matched"] is True:
            summary["matches"] += 1
        elif result["matched"] is False:
            summary["non_matches"] += 1
        else:
            summary["inconclusive"] += 1

    now = datetime.now(timezone.utc)
    report = {
        "report_schema_version": "1.0",
        "generated_at_utc": now.isoformat(),
        "scope": "ENDPOINT-001 applied to saved single-event XML files",
        "counting_unit": "files; duplicate events are not deduplicated",
        "summary": summary,
        "results": results,
        "errors": errors,
        "notes": [
            "A match is an indicator for review, not proof of an attack.",
            "A non-match is not a safety verdict.",
            "Inconclusive results and errors require separate review.",
            "Source evidence files are read without modification.",
        ],
    }

    try:
        REPORTS.mkdir(parents=True, exist_ok=True)
        filename = now.strftime("analysis-%Y%m%dT%H%M%S-%fZ.json")
        destination = REPORTS / filename

        # Exclusive creation prevents overwriting an existing report.
        with destination.open("x", encoding="utf-8") as output:
            json.dump(report, output, indent=2)
            output.write("\n")
    except OSError as error:
        print(f"Could not save report: {error}", file=sys.stderr)
        return 1

    print(json.dumps(summary, indent=2))
    print(f"\nReport saved: {destination}")

    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())