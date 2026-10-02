"""Synthetic tests for network correlation; no network or evidence writes."""

import unittest
from datetime import datetime, timedelta

from correlate_network import correlate

GUID_A = "{11111111-1111-4111-8111-111111111111}"
GUID_B = "{22222222-2222-4222-8222-222222222222}"
ZERO_GUID = "{00000000-0000-0000-0000-000000000000}"


class NetworkCorrelationTests(unittest.TestCase):
    def setUp(self):
        self.process = {
            "computer": "synthetic-host",
            "fields": {
                "UtcTime": "2026-01-01 12:00:00.000",
                "ProcessId": "100",
                "ProcessGuid": GUID_A,
            },
        }
        self.network = {
            "computer": "synthetic-host",
            "fields": {
                "UtcTime": "2026-01-01 12:00:04.000",
                "ProcessId": "100",
                "ProcessGuid": GUID_A,
            },
        }

    def set_network_delay(self, seconds):
        start = datetime.fromisoformat(self.process["fields"]["UtcTime"])
        self.network["fields"]["UtcTime"] = (
            start + timedelta(seconds=seconds)
        ).isoformat(sep=" ", timespec="milliseconds")

    def assert_status(self, expected):
        result = correlate(self.process, self.network)
        self.assertEqual(result["status"], expected)
        return result

    def test_matching_guid(self):
        self.assert_status("guid_match")

    def test_zero_guid_is_only_a_candidate(self):
        self.network["fields"]["ProcessGuid"] = ZERO_GUID
        result = self.assert_status("candidate_pid_time")
        self.assertEqual(result["seconds_after_process_creation"], 4.0)

    def test_conflicting_guids_reject_pid_fallback(self):
        self.network["fields"]["ProcessGuid"] = GUID_B
        self.assert_status("unattributed")

    def test_different_computers_reject_matching_guid(self):
        self.network["computer"] = "another-host"
        self.assert_status("unattributed")

    def test_matching_guid_with_conflicting_pid(self):
        self.network["fields"]["ProcessId"] = "200"
        self.assert_status("unattributed")

    def test_missing_guid_with_different_pid(self):
        self.network["fields"]["ProcessGuid"] = ZERO_GUID
        self.network["fields"]["ProcessId"] = "200"
        self.assert_status("unattributed")

    def test_network_before_process_creation(self):
        self.set_network_delay(-1)
        self.assert_status("unattributed")

    def test_candidate_at_window_boundary(self):
        self.network["fields"]["ProcessGuid"] = ZERO_GUID
        self.set_network_delay(120)
        self.assert_status("candidate_pid_time")

    def test_candidate_outside_window(self):
        self.network["fields"]["ProcessGuid"] = ZERO_GUID
        self.set_network_delay(120.001)
        self.assert_status("unattributed")

    def test_guid_match_does_not_use_candidate_window(self):
        self.set_network_delay(600)
        self.assert_status("guid_match")

    def test_invalid_guid_raises_error(self):
        self.network["fields"]["ProcessGuid"] = "invalid-guid"
        with self.assertRaises(ValueError):
            correlate(self.process, self.network)


if __name__ == "__main__":
    unittest.main(verbosity=2)