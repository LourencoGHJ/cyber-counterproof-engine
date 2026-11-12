import json

import pytest

from cce.dashboard import generate_dashboard


def write_history(path, entries):
    path.write_text(json.dumps(entries), encoding="utf-8")


def test_dashboard_shows_latest_assessment_findings_and_history(tmp_path):
    history = tmp_path / "history.json"
    output = tmp_path / "dashboard.html"
    write_history(
        history,
        [
            {
                "timestamp_utc": "2026-11-12T08:00:00+00:00",
                "status": "PASS",
                "summary": {"findings_total": 0},
                "findings": [],
            },
            {
                "timestamp_utc": "2026-11-12T08:05:00+00:00",
                "status": "DRIFT",
                "summary": {"findings_total": 1},
                "findings": [
                    {
                        "code": "CCE-DRIFT-RULE-MISMATCH",
                        "rule_id": "allow-ssh-lab",
                        "severity": "high",
                        "reason": "A regra observada diverge da política.",
                        "family": "ipv4",
                        "observed_lines": [5],
                    }
                ],
            },
            {
                "timestamp_utc": "2026-11-12T08:10:00+00:00",
                "status": "ERROR",
                "error": "Test error",
                "findings": [],
            },
        ],
    )

    result = generate_dashboard(history, output)
    content = result.read_text(encoding="utf-8")

    assert result == output
    assert "Histórico de auditorias" in content
    assert "Última verificação" in content
    assert "Execuções recentes" in content
    assert "DRIFT" in content
    assert "PASS" in content
    assert "allow-ssh-lab" not in content
    assert "Test error" in content
    assert "227" not in content


def test_dashboard_shows_empty_history_without_fabricated_metrics(tmp_path):
    history = tmp_path / "history.json"
    write_history(history, [])

    content = generate_dashboard(history, tmp_path / "dashboard.html").read_text(
        encoding="utf-8"
    )

    assert "Ainda não existem verificações" in content
    assert ">0</strong>" in content
    assert "Sem dados" not in content


def test_dashboard_escapes_untrusted_values_and_limits_status_css_classes(tmp_path):
    history = tmp_path / "history.json"
    malicious = '</td><script>alert("xss")</script>'
    write_history(
        history,
        [
            {
                "timestamp_utc": malicious,
                "status": malicious,
                "summary": {"findings_total": 1},
                "findings": [
                    {
                        "code": malicious,
                        "rule_id": malicious,
                        "severity": malicious,
                        "reason": malicious,
                    }
                ],
            }
        ],
    )

    content = generate_dashboard(history, tmp_path / "dashboard.html").read_text(
        encoding="utf-8"
    )

    assert malicious not in content
    assert "&lt;/td&gt;&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;" in content
    assert "status-unknown" in content
    assert 'class="status status-&lt;' not in content


def test_dashboard_is_self_contained_and_has_no_decorative_scripts_or_charts(tmp_path):
    history = tmp_path / "history.json"
    write_history(history, [{"status": "PASS", "findings": []}])

    content = generate_dashboard(history, tmp_path / "dashboard.html").read_text(
        encoding="utf-8"
    )

    assert "http://" not in content
    assert "https://" not in content
    assert "<script" not in content
    assert "<svg" not in content
    assert "gradient" not in content.lower()


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
