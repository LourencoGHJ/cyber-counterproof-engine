import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from audit import GitHubAPIError, audit


class AuditorTests(unittest.TestCase):
    @patch("audit.request_json")
    def test_security_policy_and_known_workflows_are_detected(self, request_json):
        def fake(path, token):
            if path == "/repos/example/project":
                return {"default_branch": "main", "html_url": "https://github.com/example/project", "full_name": "example/project", "visibility": "public"}
            if "/contents/SECURITY.md?" in path:
                return {"name": "SECURITY.md"}
            if "/contents/.github/workflows?" in path:
                return [
                    {"name": "ci.yml", "path": ".github/workflows/ci.yml"},
                    {"name": "codeql.yml", "path": ".github/workflows/codeql.yml"},
                ]
            raise AssertionError(path)
        request_json.side_effect = fake
        report = audit("example", "project", None)
        statuses = {item["check"]: item["status"] for item in report["checks"]}
        self.assertEqual(statuses["Security policy (SECURITY.md)"], "present")
        self.assertEqual(statuses["CI workflow"], "present")
        self.assertEqual(statuses["CodeQL workflow"], "present")
        self.assertEqual(statuses["Secret scanning workflow"], "unknown")

    @patch("audit.request_json")
    def test_missing_security_file_is_reported(self, request_json):
        def fake(path, token):
            if path == "/repos/example/project":
                return {"default_branch": "main", "html_url": "https://github.com/example/project", "full_name": "example/project"}
            if "/contents/SECURITY.md?" in path:
                raise GitHubAPIError("not found", 404)
            if "/contents/.github/workflows?" in path:
                return []
            raise AssertionError(path)
        request_json.side_effect = fake
        report = audit("example", "project", None)
        self.assertEqual(report["checks"][0]["status"], "missing")


if __name__ == "__main__":
    unittest.main()
