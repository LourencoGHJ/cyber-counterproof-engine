
import json

import pytest

from cce.dashboard import generate_dashboard


def test_dashboard_shows_summary_and_findings(tmp_path):
    history = tmp_path / "history.json"
    output = tmp_path / "dashboard.html"

    history.write_text(
        json.dumps([
            {
                "timestamp_utc": "2026-10-24T13:00:00+00:00",
                "status": "PASS",
                "summary": {"findings_total": 0},
                "findings": [],
            },
            {
                "timestamp_utc": "2026-10-24T13:05:00+00:00",
                "status": "DRIFT",
                "summary": {"findings_total": 1},
                "findings": [
                    {
                        "code": "CCE-DRIFT-RULE-MISMATCH",
                        "rule_id": "allow-ssh-lab",
                        "severity": "high",
                    }
                ],
            },
            {
                "timestamp_utc": "2026-10-24T13:10:00+00:00",
                "status": "ERROR",
                "error": "Test error",
            },
        ]),
        encoding="utf-8",
    )

    result = generate_dashboard(history, output)
    content = result.read_text(encoding="utf-8")

    assert "Cyber Counterproof Engine" in content
    assert ">3</div>" in content
    assert "DRIFT" in content
    assert "CCE-DRIFT-RULE-MISMATCH" in content
    assert "allow-ssh-lab" in content
    assert "ERROR" in content


def test_dashboard_rejects_invalid_json(tmp_path):
    history = tmp_path / "history.json"
    history.write_text("{invalid", encoding="utf-8")

    with pytest.raises(ValueError, match="JSON válido"):
        generate_dashboard(history, tmp_path / "dashboard.html")


def test_dashboard_rejects_non_list_history(tmp_path):
    history = tmp_path / "history.json"
    history.write_text('{"status":"PASS"}', encoding="utf-8")

    with pytest.raises(ValueError, match="lista"):
        generate_dashboard(history, tmp_path / "dashboard.html")


def test_dashboard_rejects_missing_history(tmp_path):
    with pytest.raises(FileNotFoundError):
        generate_dashboard(
            tmp_path / "missing.json",
            tmp_path / "dashboard.html",
        )
