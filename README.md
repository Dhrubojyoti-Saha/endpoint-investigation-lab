# Endpoint Investigation Lab

A Windows blue-team lab for investigating Sysmon process and network events with Python.

Built by Dhrubojyoti Saha with AI assistance and validated through controlled local experiments.

## What it demonstrates

- Parsing exported Sysmon process-creation events.
- Detecting selected encoded PowerShell startup options.
- Investigating and correcting a demonstrated false positive.
- Linking parent and child processes using ProcessGuid.
- Distinguishing network GUID matches from weaker PID/time candidates.
- Documenting missing telemetry and investigation limitations.
- Preparing sanitized evidence for reproducible analysis.

This is an offline investigation toolkit with a limited lab dataset. It does not provide continuous monitoring or automated incident response.

## Investigation highlights

| Case | Controlled activity | Finding |
|---|---|---|
| 001 | Command Prompt prints a marker | Encoded PowerShell rule does not match |
| 002 | PowerShell runs a harmless encoded command | Rule matches; activity is known benign |
| 003 | PowerShell uses ordinary -Command arguments | Rule does not match |
| 004 | Script text mentions -EncodedCommand | Version 0.1 produced a false positive; version 0.2 corrected this case |
| 005 | Command Prompt starts another Command Prompt | GUID relationships reconstruct the parent-child chain |
| 006 | curl makes a controlled HTTPS request | Missing network GUID permits only candidate PID/time attribution |

Detailed investigations:

- [False-positive analysis](evidence/case-004-false-positive-analysis.md)
- [Missing network attribution](evidence/network/case-006.md)
- [Evidence sanitization](evidence/SANITIZATION.md)

## Requirements

Tested locally with Windows 11 Pro, Python 3.14.7 and Sysmon 15.22.

All scripts use Python's standard library. No pip packages are required.

The PowerShell detector uses the Windows CommandLineToArgvW API, so run the full test suite on Windows.

Analyzing the supplied XML files does not require an active Sysmon installation or administrator privileges.

## Quick start

Download and extract the repository. Open PowerShell in its root folder.

```powershell
python ./test_detection.py
python ./test_network_correlation.py
```

Observed results in the Windows publication copy:

- Four detection regression tests passed against sanitized XML fixtures.
- Eleven network-correlation tests passed against synthetic in-memory events.

These 15 checks do not measure malware-detection accuracy. The network tests exercise correlation decisions rather than XML parsing.

## Analyze process events

Parse one process event:

```powershell
python ./parse_event.py ./evidence/case-001-process-create.xml
```

Inspect the harmless encoded PowerShell example:

```powershell
python ./detect_event.py ./evidence/case-002-encoded-powershell.xml
```

Analyze the top-level process fixtures:

```powershell
python ./analyze_folder.py
```

The batch script writes a timestamped JSON report into `reports/`. It reads top-level XML files in `evidence/` without recursing into the network folder.

For the seven supplied top-level process fixtures, the expected summary is one match and six non-matches.

A match means a supported encoded-command indicator was found. It does not establish malicious intent or successful payload execution.

## Correlate parent and child processes

```powershell
python ./correlate_processes.py
```

The supplied top-level fixtures preserve four parent-child relationships. Three events have parent records absent from this evidence set.

An absent parent record indicates incomplete supplied evidence. It does not establish that the process was suspicious or parentless.

This correlator is scoped to evidence from one computer.

## Investigate a network connection

```powershell
python ./correlate_network.py ./evidence/network/case-006-curl-process.xml ./evidence/network/case-006-network-unknown.xml
```

The output should include these values:

```json
{
  "status": "candidate_pid_time",
  "seconds_after_process_creation": 4.072
}
```

| Status | Meaning |
|---|---|
| `guid_match` | Computer, nonzero ProcessGuid and PID agree, with consistent event order |
| `candidate_pid_time` | Same computer and PID within 120 seconds, but a usable GUID is missing |
| `unattributed` | The supplied pair does not meet the correlation criteria |

The 120-second window is a lab heuristic. The script does not check process termination, intervening PID reuse or competing candidates.

Case 006 contains a discrepancy between System/TimeCreated and EventData/UtcTime. Both original values are retained. The 4.072-second interval uses EventData/UtcTime in both records.

## Files

| File | Purpose |
|---|---|
| `parse_event.py` | Parse one Sysmon Event ID 1 XML export |
| `detect_event.py` | Apply the limited encoded PowerShell indicator rule |
| `analyze_folder.py` | Analyze top-level process fixtures and save JSON |
| `correlate_processes.py` | Link process-creation events by GUID |
| `correlate_network.py` | Compare one process event and one network event |
| `test_detection.py` | Four detection regression checks |
| `test_network_correlation.py` | Eleven synthetic correlation checks |
| `sysmon-lab.xml` | Lab collection configuration |
| `evidence/` | Sanitized process fixtures and investigation notes |
| `evidence/network/` | Sanitized process/network pair and case study |

## Collection configuration

The included Sysmon configuration retains process-creation logging, uses SHA256 executable hashing and includes network events matching the configured curl.exe image path.

It is a narrow lab configuration. Applying it replaces the active Sysmon configuration.

During Case 006, an image-filtered network event was not observed. Temporary broader collection captured an event with an unknown process image and a zero ProcessGuid. The original configuration was restored afterward.

The cause of the missing process metadata remains unresolved. The included image filter cannot be assumed to capture every curl connection on every system.

## Evidence handling

The XML files are sanitized derivatives of controlled lab observations, not byte-for-byte forensic originals.

Host/user details, addresses and selected identifiers were replaced. Consistent GUID substitutions preserve process relationships. The zero network GUID remains zero. Command lines and timestamps are retained.

Documentation IPv6 addresses are placeholders, not observed endpoints or indicators of compromise.

See [SANITIZATION.md](evidence/SANITIZATION.md) for transformation and validation details.

[SANITIZED-SHA256.json](evidence/SANITIZED-SHA256.json) records hashes of sanitized files. These hashes do not authenticate the original acquisitions.

Regenerate publication reports from sanitized fixtures rather than copying reports generated from private evidence.

## Limitations

- The detector supports a limited set of PowerShell option spellings.
- Unsupported argument sequences can produce an inconclusive result.
- It does not inspect script contents or decode or execute encoded payloads.
- A non-match is not a safety verdict.
- Batch counts are file-based and do not deduplicate events.
- Network correlation examines only the two supplied events.
- The small controlled dataset does not establish production coverage.

## Author

Dhrubojyoti Saha — aspiring SOC / blue-team analyst.

Developed with AI assistance. Event collection, local execution, troubleshooting and reported Windows validation were performed as part of this hands-on lab.
