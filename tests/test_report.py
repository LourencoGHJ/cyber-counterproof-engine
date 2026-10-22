import json
from pathlib import Path

from cce.report import build_report, sha256_file, write_report


def test_hash_is_sha256(tmp_path):
    source = tmp_path / "evidence.txt"
    source.write_text("evidence", encoding="utf-8")
    assert len(sha256_file(source)) == 64


def test_report_round_trip(tmp_path):
    policy = tmp_path / "policy.json"
    requirements = tmp_path / "requirements.json"
    policy.write_text('{"policy_id":"test"}', encoding="utf-8")
    requirements.write_text('{"requirements":[]}', encoding="utf-8")
    report = build_report({"status": "PASS"}, policy, requirements)
    output = tmp_path / "report.json"
    write_report(report, output)
    loaded = json.loads(output.read_text(encoding="utf-8"))
    assert loaded["result"]["status"] == "PASS"
    assert loaded["input_evidence"]["policy"]["sha256"] == sha256_file(policy)
