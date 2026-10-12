import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from privacy import sanitize, shared_report

class PrivacyTests(unittest.TestCase):
    def test_secrets_never_exported(self):
        source = {"password": "secreto", "detail": "token=abc123 bearer abc.def"}
        result = sanitize(source)
        self.assertNotIn("secreto", str(result))
        self.assertNotIn("abc123", str(result))
        self.assertNotIn("abc.def", str(result))
        self.assertEqual(source["password"], "secreto")

    def test_identifiers_redacted(self):
        self.assertNotIn("10.0.0.1", str(sanitize({"detail": "host 10.0.0.1"})))

    def test_shared_report_omits_sources(self):
        report = shared_report({"sources": ["confidential.json"], "unique_observations": []})
        self.assertNotIn("confidential.json", str(report))

if __name__ == "__main__":
    unittest.main()
