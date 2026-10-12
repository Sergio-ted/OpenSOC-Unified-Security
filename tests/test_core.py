import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import observations, consolidate, identity


class CoreTests(unittest.TestCase):
    def test_observations_nested(self):
        self.assertEqual(len(observations({"results": {"observations": [{"title": "A"}]}})), 1)

    def test_observations_serialized(self):
        self.assertEqual(len(observations({"results": '{"observations":[{"title":"A"}]}'})), 1)

    def test_dedupe_retains_sources(self):
        a = {"observations": [{"engine": "nmap", "title": "80/tcp", "detail": "open"}]}
        result = consolidate([("one", a), ("two", a)])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["sources"], ["one", "two"])

    def test_distinct_evidence(self):
        a = {"observations": [{"title": "TLS", "detail": "1.2"}, {"title": "TLS", "detail": "1.3"}]}
        self.assertEqual(len(consolidate([("one", a)])), 2)

    def test_empty_is_not_a_finding(self):
        self.assertEqual(consolidate([("x", {"observations": [{}]})]), [])


if __name__ == "__main__":
    unittest.main()
