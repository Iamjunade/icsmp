#!/usr/bin/env python3
"""
Automated Test Suite for Redact Mini DLP
Verifies all test cases T1 to T11 from Section 11 of the PRD.
"""

import unittest
from dlp_scanner import RedactScanner, DEFAULT_RULES

class TestRedactScanner(unittest.TestCase):

    def setUp(self):
        # Fresh scanner instance with default rules for each test
        self.scanner = RedactScanner()

    def test_t1_valid_aadhaar(self):
        """T1: Valid Aadhaar 2345 6789 0124 -> Detected, Government ID leak triggers, verdict BLOCKED"""
        res = self.scanner.scan_text("Employee Aadhaar record: 2345 6789 0124 verified.")
        self.assertEqual(res["verdict"], "BLOCK")
        self.assertEqual(res["findings_count"], 1)
        self.assertEqual(res["findings"][0]["detector_name"], "Aadhaar")
        triggered_names = [r["name"] for r in res["triggered_rules"]]
        self.assertIn("Government ID leak", triggered_names)

    def test_t2_invalid_aadhaar(self):
        """T2: Invalid Aadhaar 1234 5678 9012 -> Not detected, counted as rejected"""
        res = self.scanner.scan_text("Random test sequence 1234 5678 9012 here.")
        # Notice 1234 5678 9012 starts with 1 (Aadhaar requires 2-9).
        # Let's also test one starting with 2-9 that fails Verhoeff: 2345 6789 0123
        res2 = self.scanner.scan_text("Test with invalid checksum 2345 6789 0123 here.")
        self.assertEqual(res["findings_count"], 0)
        self.assertEqual(res2["findings_count"], 0)
        self.assertGreater(res2["rejections"]["aadhaar_verhoeff"], 0)
        self.assertEqual(res2["verdict"], "CLEAN")

    def test_t3_valid_card(self):
        """T3: Valid card 4532 0151 1283 0366 -> Detected, Payment data triggers"""
        res = self.scanner.scan_text("Payment transaction on Visa 4532 0151 1283 0366.")
        self.assertEqual(res["verdict"], "BLOCK")
        self.assertEqual(res["findings_count"], 1)
        self.assertEqual(res["findings"][0]["detector_name"], "Credit card")
        triggered_names = [r["name"] for r in res["triggered_rules"]]
        self.assertIn("Payment data", triggered_names)

    def test_t4_invalid_card(self):
        """T4: Invalid card 1234 5678 9012 3456 -> Not detected, counted as rejected"""
        res = self.scanner.scan_text("Fake card number 1234 5678 9012 3456 failed payment.")
        self.assertEqual(res["findings_count"], 0)
        self.assertGreater(res["rejections"]["credit_card_luhn"], 0)
        self.assertEqual(res["verdict"], "CLEAN")

    def test_t5_pan(self):
        """T5: PAN ABCDE1234F -> Detected"""
        res = self.scanner.scan_text("User tax PAN identifier is ABCDE1234F.")
        self.assertEqual(res["verdict"], "BLOCK")
        self.assertEqual(res["findings_count"], 1)
        self.assertEqual(res["findings"][0]["detector_name"], "PAN")

    def test_t6_password(self):
        """T6: Password password: Admin@123 -> Detected"""
        res = self.scanner.scan_text("Config contains password: Admin@123 for root user.")
        self.assertEqual(res["verdict"], "BLOCK")
        self.assertEqual(res["findings_count"], 1)
        self.assertEqual(res["findings"][0]["detector_name"], "Password")

    def test_t7_threshold(self):
        """T7: Three emails with Bulk personal data set to 5 -> No trigger. At threshold 3 it triggers."""
        text = "Contact alice@example.com, bob@example.com, and charlie@example.com for help."
        # Default threshold is 5
        res_default = self.scanner.scan_text(text)
        self.assertEqual(res_default["findings_count"], 3)
        self.assertEqual(res_default["verdict"], "CLEAN")
        self.assertEqual(len(res_default["triggered_rules"]), 0)

        # Scanner with threshold 3 for Bulk personal data
        rules = [dict(r) for r in DEFAULT_RULES]
        for r in rules:
            if r["id"] == "R4":
                r["threshold"] = 3
        custom_scanner = RedactScanner(rules=rules)
        res_custom = custom_scanner.scan_text(text)
        self.assertEqual(res_custom["verdict"], "WARN")
        self.assertEqual(len(res_custom["triggered_rules"]), 1)
        self.assertEqual(res_custom["triggered_rules"][0]["name"], "Bulk personal data")

    def test_t8_action_change(self):
        """T8: Set Payment data to LOG -> Verdict drops from BLOCKED to LOG"""
        text = "Payment transaction on Visa 4532 0151 1283 0366."
        rules = [dict(r) for r in DEFAULT_RULES]
        for r in rules:
            if r["id"] == "R2":
                r["action"] = "LOG"
        custom_scanner = RedactScanner(rules=rules)
        res = custom_scanner.scan_text(text)
        self.assertEqual(res["verdict"], "LOG")

    def test_t9_custom_detector(self):
        """T9: EMP-\\d{5} with text EMP-20481 -> Detected under Custom keyword rule"""
        custom_scanner = RedactScanner(custom_regex=r"EMP-\d{5}")
        res = custom_scanner.scan_text("Internal staff badge EMP-20481 scanned.")
        self.assertEqual(res["findings_count"], 1)
        self.assertEqual(res["findings"][0]["detector_name"], "Custom detector")
        self.assertEqual(res["verdict"], "WARN")

    def test_t10_clean_text(self):
        """T10: Ordinary paragraph -> Verdict CLEAN, no findings"""
        clean_text = "The quick brown fox jumps over the lazy dog. Today is a peaceful day in the computer science department."
        res = self.scanner.scan_text(clean_text)
        self.assertEqual(res["verdict"], "CLEAN")
        self.assertEqual(res["findings_count"], 0)
        self.assertEqual(res["risk_score"], 0)

    def test_t11_redaction(self):
        """T11: Matches hidden by bars of equal length and tagged placeholders"""
        text = "Contact: test@domain.org and PAN: ABCDE1234F"
        res = self.scanner.scan_text(text)
        blackout = res["redacted_blackout"]
        self.assertNotIn("test@domain.org", blackout)
        self.assertNotIn("ABCDE1234F", blackout)
        self.assertEqual(len(blackout), len(text))
        self.assertIn("█" * len("ABCDE1234F"), blackout)
        self.assertIn("[PAN REDACTED]", res["redacted_tagged"])

if __name__ == "__main__":
    unittest.main(verbosity=2)
