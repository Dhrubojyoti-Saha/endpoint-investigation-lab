"""Regression checks using four locally collected Sysmon events."""

import unittest
from pathlib import Path

from parse_event import read_event
from detect_event import analyze

EVIDENCE = Path(__file__).resolve().parent / "evidence"


class DetectionTests(unittest.TestCase):
    def check_case(self, filename, expected_match):
        event = read_event(EVIDENCE / filename)
        report = analyze(event)

        self.assertIs(report["matched"], expected_match)
        self.assertEqual(report["rule_id"], "ENDPOINT-001")
        self.assertEqual(
            report["evidence"]["ProcessGuid"],
            event["ProcessGuid"],
        )

    def test_normal_command_prompt(self):
        self.check_case("case-001-process-create.xml", False)

    def test_encoded_powershell(self):
        self.check_case("case-002-encoded-powershell.xml", True)

    def test_normal_powershell(self):
        self.check_case("case-003-normal-powershell.xml", False)

    def test_quoted_flag_is_not_an_execution_option(self):
        self.check_case("case-004-quoted-flag.xml", False)


if __name__ == "__main__":
    unittest.main(verbosity=2)