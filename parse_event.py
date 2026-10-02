"""Read one exported Sysmon process-creation event."""

import argparse
import json
import sys
import xml.etree.ElementTree as ET

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

FIELDS = (
    "UtcTime",
    "ProcessGuid",
    "ProcessId",
    "Image",
    "CommandLine",
    "ParentProcessGuid",
    "ParentProcessId",
    "ParentImage",
    "IntegrityLevel",
)


def read_event(path):
    root = ET.parse(path).getroot()

    provider = root.find("e:System/e:Provider", NS)
    event_id = root.findtext("e:System/e:EventID", namespaces=NS)

    if provider is None or provider.get("Name") != "Microsoft-Windows-Sysmon":
        raise ValueError("Expected an exported Sysmon event.")

    if event_id != "1":
        raise ValueError("This parser currently supports Event ID 1 only.")

    data = {
        node.get("Name"): node.text or ""
        for node in root.findall("e:EventData/e:Data", NS)
    }

    missing = [name for name in FIELDS if not data.get(name)]
    if missing:
        raise ValueError("Missing required fields: " + ", ".join(missing))

    return {
        "EventID": 1,
        "EventRecordID": root.findtext(
            "e:System/e:EventRecordID", namespaces=NS
        ),
        **{name: data[name] for name in FIELDS},
    }


def main():
    parser = argparse.ArgumentParser(
        description="Summarize a Sysmon process-creation XML event."
    )
    parser.add_argument("file", help="Path to the exported XML event")
    args = parser.parse_args()

    try:
        result = read_event(args.file)
    except (OSError, ET.ParseError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1

    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())