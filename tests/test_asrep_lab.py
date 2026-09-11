import json
import tempfile
import unittest
from pathlib import Path

from src.analyzer import assess, assess_all, metrics
from src.loader import load_accounts
from src.remediation import validate_closure
from src.reporting import render


class AsrepLabTests(unittest.TestCase):
    def sample(self, **overrides):
        record = {
            "sam_account_name": "svc_test",
            "enabled": True,
            "preauth_required": False,
            "password_age_days": 200,
            "privileged": False,
            "service_account": True,
            "managed_identity": False,
            "interactive_logon": False,
            "criticality": "high",
            "strong_authentication": False,
        }
        record.update(overrides)
        return record

    def test_preauth_required_is_informational(self):
        finding = assess(self.sample(preauth_required=True))
        self.assertEqual(finding.score, 0)
        self.assertEqual(finding.severity, "informational")

    def test_privileged_legacy_identity_is_high_risk(self):
        finding = assess(self.sample(privileged=True, interactive_logon=True, criticality="critical"))
        self.assertGreaterEqual(finding.score, 85)

    def test_disabled_account_reduces_risk(self):
        enabled = assess(self.sample(enabled=True)).score
        disabled = assess(self.sample(enabled=False)).score
        self.assertLess(disabled, enabled)

    def test_managed_identity_reduces_risk(self):
        unmanaged = assess(self.sample(managed_identity=False)).score
        managed = assess(self.sample(managed_identity=True)).score
        self.assertLess(managed, unmanaged)

    def test_score_is_bounded(self):
        finding = assess(self.sample(privileged=True, interactive_logon=True, criticality="critical", password_age_days=9999))
        self.assertLessEqual(finding.score, 100)

    def test_finding_id_is_deterministic(self):
        self.assertEqual(assess(self.sample()).finding_id, assess(self.sample()).finding_id)

    def test_attack_mapping_present(self):
        self.assertIn("T1558.004", assess(self.sample()).attack)

    def test_priority_order(self):
        findings = assess_all([self.sample(sam_account_name="low", enabled=False), self.sample(sam_account_name="high", privileged=True)])
        self.assertEqual(findings[0].account, "high")

    def test_metrics(self):
        findings = assess_all([self.sample(sam_account_name="a"), self.sample(sam_account_name="b", preauth_required=True)])
        self.assertEqual(metrics(findings)["accounts_assessed"], 2)
        self.assertEqual(metrics(findings)["exposed_accounts"], 1)

    def test_loader_rejects_duplicate_accounts(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "accounts.json"
            path.write_text(json.dumps([self.sample(), self.sample()]), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_accounts(path)

    def test_loader_rejects_invalid_boolean(self):
        bad = self.sample(enabled="yes")
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "accounts.json"
            path.write_text(json.dumps([bad]), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_accounts(path)

    def test_complete_remediation_is_validated(self):
        status, issues = validate_closure({
            "change_reference": "CHG-SYNTH-001", "owner": "Identity Engineering",
            "preauth_reenabled": True, "credential_rotated": True,
            "privilege_reviewed": True, "post_change_validated": True,
        })
        self.assertEqual(status, "validated")
        self.assertEqual(issues, [])

    def test_incomplete_remediation_needs_evidence(self):
        status, issues = validate_closure({
            "change_reference": "CHG-SYNTH-002", "owner": "Identity Engineering",
            "preauth_reenabled": True, "credential_rotated": False,
            "privilege_reviewed": True, "post_change_validated": True,
        })
        self.assertEqual(status, "needs_evidence")
        self.assertTrue(issues)

    def test_report_contains_expected_sections(self):
        report = render([assess(self.sample())])
        self.assertIn("Executive summary", report)
        self.assertIn("T1558.004", report)
        self.assertIn("Closure standard", report)


if __name__ == "__main__":
    unittest.main()
