# Case 006 — HTTPS connection with missing process attribution

## Objective

Collect a controlled HTTPS connection and correlate its network event

with the process that initiated the test.

## Test

Executed:

curl.exe --head --connect-timeout 10 --max-time 20 https://example.com/

The request returned HTTP 200 and exit code 0.

> Publication copy: identifiers and addresses were sanitized. See [sanitization notes](../SANITIZATION.md).

## Evidence

- case-006-curl-process.xml — Sysmon Event ID 1

- case-006-network-unknown.xml — Sysmon Event ID 3

All timestamps below are UTC.

| Field | Process event | Network event |
|---|---|---|
| Time | 2026-09-23 17:15:48.513 | 2026-09-23 17:15:52.585 |
| Process ID | 6504 | 6504 |
| Image | C:\Windows\System32\curl.exe | `<unknown process>` |
| Process GUID | {12340000-4000-8000-0000-000000000002} | {00000000-0000-0000-0000-000000000000} |

The network event records an initiated TCP connection to destination

port 443, occurring 4.072 seconds after process creation.

## Investigation

1. Confirmed the curl request succeeded.

2. Confirmed Sysmon network logging and the curl image filter were active.

3. Confirmed process-creation events were being recorded.

4. Found no Event ID 255 errors in the retained log.

5. Temporarily enabled network collection without an image filter.

6. Observed network events, including one with missing process metadata.

7. Restored the original curl-only configuration.

8. Located a curl process-creation event with the same PID near the
   network event's timestamp.

## Assessment

The matching PID, timing, and controlled test support a likely

association between the curl process and the network connection.

This is a candidate correlation, not a confirmed ProcessGuid match.

The missing network image would not satisfy the curl image filter.

## Limitations

- PIDs can be reused.

- The network event has no usable ProcessGuid.

- Process lifetime and intervening PID reuse were not independently checked.

- Destination port 443 alone does not identify a website or prove HTTPS.

- The cause of the missing process metadata remains unresolved.

- This controlled test provides no evidence of malicious activity.

## Publication

These are sanitized publication copies; the original evidence is retained privately.


## Timestamp caveat

The 4.072-second interval uses EventData/UtcTime. The network record
System/TimeCreated precedes its EventData/UtcTime by approximately
1.956 seconds. Both original timestamp values are preserved; the cause
of this discrepancy was not established. This is an additional timing limitation.
