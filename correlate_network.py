"""Correlate one Sysmon network event with one process-creation event.

Reads saved XML only. Makes no network requests or system changes.
"""

import argparse
import json
import sys
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
CANDIDATE_WINDOW_SECONDS = 120


def read_event(path, expected_id):
    root = ET.parse(path).getroot()
    provider = root.find("e:System/e:Provider", NS)
    event_id = root.findtext("e:System/e:EventID", namespaces=NS)
    computer = root.findtext("e:System/e:Computer", namespaces=NS)

    if provider is None or provider.get("Name") != "Microsoft-Windows-Sysmon":
        raise ValueError(f"{path.name}: expected a Sysmon event.")

    if event_id != str(expected_id):
        raise ValueError(f"{path.name}: expected Event ID {expected_id}.")

    if not computer or not computer.strip():
        raise ValueError(f"{path.name}: missing computer name.")

    fields = {
        node.get("Name"): node.text or ""
        for node in root.findall("e:EventData/e:Data", NS)
    }

    required = ["UtcTime", "ProcessId"]
    if expected_id == 1:
        required += ["Image", "ProcessGuid", "CommandLine"]
    else:
        required += ["Protocol", "DestinationIp", "DestinationPort"]

    for name in required:
        if not fields.get(name):
            raise ValueError(f"{path.name}: missing {name}.")

    # Validate values before using them for correlation.
    datetime.fromisoformat(fields["UtcTime"])
    int(fields["ProcessId"])

    return {
        "source_file": path.name,
        "event_id": expected_id,
        "record_id": root.findtext(
            "e:System/e:EventRecordID", namespaces=NS
        ),
        "computer": computer.strip(),
        "fields": fields,
    }


def usable_guid(value):
    if not value or value.strip() in {"", "-"}:
        return None
    try:
        parsed = uuid.UUID(value.strip().strip("{}"))
    except ValueError as error:
        raise ValueError("Invalid ProcessGuid in supplied evidence.") from error
    return str(parsed) if parsed.int != 0 else None


def correlate(process, network):
    p = process["fields"]
    n = network["fields"]

    process_time = datetime.fromisoformat(p["UtcTime"])
    network_time = datetime.fromisoformat(n["UtcTime"])
    elapsed = (network_time - process_time).total_seconds()

    process_guid = usable_guid(p.get("ProcessGuid"))
    network_guid = usable_guid(n.get("ProcessGuid"))

    same_host = process["computer"].casefold() == network["computer"].casefold()
    same_pid = int(p["ProcessId"]) == int(n["ProcessId"])

    status = "unattributed"
    reason = "The supplied process does not meet the correlation criteria."

    if not same_host:
        reason = "Computer names differ; correlation rejected."
    elif elapsed < 0:
        reason = "Network activity predates this process creation."
    elif process_guid and network_guid:
        if process_guid != network_guid:
            reason = "Nonzero ProcessGuids differ; PID fallback is rejected."
        elif not same_pid:
            reason = "GUIDs match but PIDs conflict; review evidence consistency."
        else:
            status = "guid_match"
            reason = "Computer, nonzero ProcessGuid, and PID match."
    elif same_pid and elapsed <= CANDIDATE_WINDOW_SECONDS:
        status = "candidate_pid_time"
        reason = (
            "Same computer and PID within the candidate time window, "
            "but a usable GUID is missing. Attribution remains unconfirmed."
        )
    else:
        reason = (
            "No usable GUID match, and the PID/time candidate criteria "
            "were not met."
        )

    return {
        "schema_version": "1.0",
        "status": status,
        "reason": reason,
        "seconds_after_process_creation": round(elapsed, 3),
        "candidate_window_seconds": CANDIDATE_WINDOW_SECONDS,
        "process_evidence": process,
        "network_evidence": network,
        "limitations": [
            "Examines only the two supplied events.",
            "The 120-second window is a lab heuristic, not proof.",
            "Does not check process termination or intervening PID reuse.",
            "Does not search for competing process candidates.",
            "Computer names are compared as recorded, without alias resolution.",
            "A GUID match establishes a recorded link, not malicious intent.",
            "Missing attribution does not establish malicious activity.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(
        description="Compare saved Sysmon process and network XML events."
    )
    parser.add_argument("process_xml", type=Path)
    parser.add_argument("network_xml", type=Path)
    args = parser.parse_args()

    try:
        process = read_event(args.process_xml, 1)
        network = read_event(args.network_xml, 3)
        report = correlate(process, network)
    except (OSError, ET.ParseError, ValueError, TypeError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1

    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())