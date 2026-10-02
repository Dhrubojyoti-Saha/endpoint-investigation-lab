"""Inspect a limited set of PowerShell startup arguments on Windows."""

import argparse
import ctypes
import json
import ntpath
import sys
import xml.etree.ElementTree as ET

from parse_event import read_event

RULE_ID = "ENDPOINT-001"

ENCODED_OPTIONS = {"-encodedcommand", "-enc"}
SCRIPT_OPTIONS = {"-command", "-c", "-file", "-f"}
SIMPLE_OPTIONS = {
    "-noprofile",
    "-nologo",
    "-noninteractive",
    "-noexit",
    "-sta",
    "-mta",
}


def split_windows_command_line(command_line):
    if sys.platform != "win32":
        raise ValueError("Version 0.2 requires Windows.")

    if not command_line.strip() or "\x00" in command_line:
        raise ValueError("Empty command line or embedded null character.")

    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    split = shell32.CommandLineToArgvW
    split.argtypes = [
        ctypes.c_wchar_p,
        ctypes.POINTER(ctypes.c_int),
    ]
    split.restype = ctypes.POINTER(ctypes.c_wchar_p)

    free = kernel32.LocalFree
    free.argtypes = [ctypes.c_void_p]
    free.restype = ctypes.c_void_p

    count = ctypes.c_int()
    arguments = split(command_line, ctypes.byref(count))
    if not arguments:
        raise ctypes.WinError(ctypes.get_last_error())

    try:
        return [arguments[index] for index in range(count.value)]
    finally:
        free(ctypes.cast(arguments, ctypes.c_void_p))


def inspect_options(arguments):
    # The first argument identifies the executable.
    for index in range(1, len(arguments)):
        option = arguments[index].lower()

        if option in SCRIPT_OPTIONS:
            return False, (
                "Reached -Command or -File before an encoded option; "
                "following script text is outside this rule's scope."
            )

        if option in ENCODED_OPTIONS:
            if index + 1 >= len(arguments) or not arguments[index + 1]:
                return None, "Encoded option has no argument."

            return True, (
                "Found an encoded-command option in the "
                "supported startup-argument sequence."
            )

        if option not in SIMPLE_OPTIONS:
            return None, (
                "Encountered an unsupported argument; "
                "manual review is needed."
            )

    return False, "No encoded-command option in the supported sequence."


def analyze(event):
    image_name = ntpath.basename(event["Image"]).lower()

    if image_name not in {"powershell.exe", "pwsh.exe"}:
        matched = False
        reason = "Process image is outside this rule's PowerShell scope."
    else:
        arguments = split_windows_command_line(event["CommandLine"])
        matched, reason = inspect_options(arguments)

    if matched is True:
        assessment = "Review required; malicious intent is not established."
    elif matched is False:
        assessment = "No match for this rule; this is not a safety verdict."
    else:
        assessment = "Inconclusive: unsupported or incomplete arguments."

    return {
        "rule_id": RULE_ID,
        "rule_name": "Encoded PowerShell command-line indicator",
        "rule_version": "0.2",
        "matched": matched,
        "assessment": assessment,
        "reason": reason,
        "evidence": event,
        "limitations": [
            "Supports a limited set of startup options and spellings.",
            "Unsupported argument sequences produce matched: null.",
            "Does not fully emulate PowerShell argument semantics.",
            "Does not inspect code inside -Command or script files.",
            "Does not validate, decode, or execute the encoded payload.",
            "A match does not prove successful or malicious execution.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(
        description="Check one exported Sysmon process event."
    )
    parser.add_argument("file", help="Path to the XML evidence file")
    args = parser.parse_args()

    try:
        report = analyze(read_event(args.file))
    except (OSError, ET.ParseError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1

    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())