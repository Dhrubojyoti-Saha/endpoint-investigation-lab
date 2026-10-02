"""Link process events collected from this single-host lab."""

import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

from parse_event import read_event

EVIDENCE = Path(__file__).resolve().parent / "evidence"


def correlate(events):
    by_guid = {}

    for event in events:
        guid = event["ProcessGuid"].lower()

        if guid in by_guid:
            raise ValueError(
                f"Duplicate ProcessGuid found: {guid}. "
                "Resolve duplicate evidence before correlation."
            )

        by_guid[guid] = event

    relationships = []
    missing_parents = []

    for child in events:
        parent_guid = child["ParentProcessGuid"].lower()

        if parent_guid == child["ProcessGuid"].lower():
            raise ValueError("An event incorrectly references itself as parent.")

        parent = by_guid.get(parent_guid)

        if parent is None:
            missing_parents.append({
                "source_file": child["source_file"],
                "process_guid": child["ProcessGuid"],
                "parent_process_guid": child["ParentProcessGuid"],
                "status": "Parent event is not in the supplied evidence.",
            })
            continue

        relationships.append({
            "parent_file": parent["source_file"],
            "parent_process_guid": parent["ProcessGuid"],
            "parent_image": parent["Image"],
            "parent_pid": parent["ProcessId"],
            "child_file": child["source_file"],
            "child_process_guid": child["ProcessGuid"],
            "child_image": child["Image"],
            "child_pid": child["ProcessId"],
            "child_command_line": child["CommandLine"],
        })

    return {
        "scope": "Saved process events from one lab computer",
        "events_loaded": len(events),
        "relationships_found": len(relationships),
        "events_without_parent_record": len(missing_parents),
        "relationships": relationships,
        "missing_parents": missing_parents,
        "limitations": [
            "Do not mix evidence from different computers in this version.",
            "Missing parent records indicate incomplete supplied evidence.",
            "A recorded relationship alone does not establish maliciousness.",
        ],
    }


def main():
    try:
        files = sorted(EVIDENCE.glob("*.xml"))
        if not files:
            raise ValueError("No XML evidence files found.")

        events = []
        for path in files:
            event = read_event(path)
            event["source_file"] = path.name
            events.append(event)

        report = correlate(events)

    except (OSError, ET.ParseError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1

    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())