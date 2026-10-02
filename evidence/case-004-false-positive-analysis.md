# Case 004: Printed text mistaken for encoded PowerShell execution

## Objective

Evaluate whether ENDPOINT-001 distinguishes an encoded-command

option from the same words appearing inside ordinary script text.

## Environment

- Windows 11 Pro

- Sysmon 15.22

- Python 3.14.7

- Locally collected Sysmon Event ID 1

> Publication copy: identifiers and addresses were sanitized. See [sanitization notes](SANITIZATION.md).

## Evidence

- File: [Sanitized event](case-004-quoted-flag.xml)

- Event record ID: 21998

- UTC timestamp: 2026-09-23 16:09:06.096

- Process: powershell.exe

- Parent process: powershell.exe

## Controlled activity

The test used:

powershell.exe -NoProfile -Command "Write-Output 'DHRUV-LAB-004 mentions -EncodedCommand as text'"

The process printed a message. It did not use an encoded-command

startup option.

## Initial finding

Rule version 0.1 returned matched: true.

Its regular expression searched the entire command line and

mistook text inside the script for a startup option. This was a

false positive for the behavior the rule intended to identify.

## Change

Version 0.2 splits the command line using Windows'

CommandLineToArgvW API and examines a limited set of startup options.

It stops at recognized -Command or -File options. Unsupported or

incomplete argument sequences return an inconclusive result.

## Observed validation

| Saved case | Version 0.2 result |
|---|---|
| 001: Ordinary Command Prompt echo | false |
| 002: Harmless encoded PowerShell command | true |
| 003: Ordinary PowerShell command | false |
| 004: Encoded-command flag mentioned in text | false |

All four regression tests passed.

## Assessment and limitations

The change corrected this demonstrated false positive while

preserving detection of the known encoded-command example.

All four activities were benign lab tests. These results do not

measure malware-detection accuracy or prove complete coverage.

The detector does not fully emulate PowerShell argument semantics,

inspect script contents, or establish malicious intent.

## Development disclosure

Developed with AI assistance and validated against locally

collected events.
