# Sanitized evidence for publication

These nine XML files are derived from real, controlled lab events. They are
edited fixtures, not byte-for-byte forensic originals. Original files remain
in the private working lab. Do not present sanitized file hashes as original
acquisition hashes.

## Transformations

- Computer/domain name -> LAB-HOST; user/profile directory -> LabUser.
- Nonzero process, parent-process and logon GUIDs -> consistent pseudonyms.
- Zero GUIDs remain zero; the missing network image remains unknown.
- Logon IDs -> consistent placeholder IDs.
- Source and destination IPv6 addresses -> 2001:db8::10 and 2001:db8::20,
  documentation placeholders, not observed endpoints or indicators.
- XML was serialized as UTF-8 and indented.
- Markdown formatting was repaired and its GUID references updated.

Retained: command lines (including benign DHRUV-LAB markers), timestamps,
PIDs, record IDs, image paths outside the user profile, executable versions,
executable hashes, ports, protocol and the standard SYSTEM SID. The encoded
case-002 payload is unchanged and only prints the benign lab marker.
This is targeted de-identification, not a guarantee of anonymity.

## Validation performed on these copies

- All nine XML documents parse: eight process events and one network event.
- Data fields outside the documented transformations are unchanged.
- System timestamps and command lines are unchanged in all nine files.
- Seven top-level process fixtures retain four parent-child links and three
  missing-parent records.
- The network pair retains equal PIDs, a zero network ProcessGuid and the
  4.072-second EventData/UtcTime interval: only a PID/time candidate.
- Original host/user strings, GUIDs and network IPs are absent from this bundle.

No Windows-native detector execution was performed during sanitization.
Re-run test_detection.py and test_network_correlation.py in the Windows
publication folder before claiming the publication package passes tests.

## Layout and use

Extract the ZIP into endpoint-investigation-lab-publish so that evidence is
an immediate child directory. The separate evidence/network directory keeps
Event ID 3 outside the existing nonrecursive process-only batch scan.
Do not copy raw reports into the publication folder. Regenerate reports from
these sanitized fixtures. Case 004 and Case 006 write-ups are publication copies.

## Timestamp limitation

The network event's System/TimeCreated and EventData/UtcTime differ and are
preserved without correction. The reported 4.072 seconds uses EventData/UtcTime
in both events; it does not establish definitive attribution.
