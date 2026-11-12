import json

import pytest

from cce.dashboard import generate_dashboard


def write_history(path, entries):
    path.write_text(json.dumps(entries), encoding="utf-8")


def test_dashboard_renders_overview_distribution_findings_and_activity(tmp_path):
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
                "summary": {"findings_total": 2},
                "findings": [
                    {
                        "code": "CCE-DRIFT-RULE-MISMATCH",
                        "rule_id": "allow-ssh-lab",
                        "severity": "high",
                        "reason": "A regra observada diverge da política.",
                    },
                    {
                        "code": "CCE-BASE-POLICY-MISMATCH",
                        "rule_id": "INPUT",
                        "severity": "medium",
                        "reason": "A política base não coincide.",
                    },
                ],
            },
            {
                "timestamp_utc": "2026-11-12T08:10:00+00:00",
                "status": "ERROR",
                "error": "Test error",
                "findings": [],
            },
            {
                "timestamp_utc": "2026-11-12T08:15:00+00:00",
                "status": "INCONCLUSIVE",
                "summary": {"findings_total": 1},
                "findings": [
                    {"code": "CCE-UNKNOWN", "rule_id": "INPUT", "severity": "low"}
                ],
            },
        ],
    )

    result = generate_dashboard(history, output)
    content = result.read_text(encoding="utf-8")

    assert result == output
    assert "Firewall security posture" in content
    assert "Distribuição de estados" in content
    assert "Tendência de descobertas" in content
    assert "Histórico de verificações" in content
    assert "INCONCLUSIVE" in content
    assert "DRIFT" in content
    assert "CCE-UNKNOWN" in content
    assert "allow-ssh-lab" not in content  # Findings are scoped to the latest run.
    assert "Test error" in content  # Historical errors remain visible in activity.
    assert "Verificações registadas" in content
    assert "FIREWALL SECURITY OPERATIONS" in content


def test_dashboard_renders_empty_history_with_actionable_empty_states(tmp_path):
    history = tmp_path / "history.json"
    write_history(history, [])

    content = generate_dashboard(history, tmp_path / "dashboard.html").read_text(
        encoding="utf-8"
    )

    assert "Sem verificações registadas" in content
    assert "Ainda não existem estados registados." in content
    assert "Executa" in content
    assert "Sem atividade para apresentar" in content


def test_dashboard_escapes_untrusted_history_values_and_whitelists_status_classes(
    tmp_path,
):
    history = tmp_path / "history.json"
    malicious = '</script><script>alert("xss")</script>'
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
    assert "&lt;/script&gt;&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;" in content
    assert "badge-unknown" in content
    assert 'class="badge badge-&lt;' not in content


def test_dashboard_has_no_external_assets_or_network_dependencies(tmp_path):
    history = tmp_path / "history.json"
    write_history(history, [{"status": "PASS", "findings": []}])

    content = generate_dashboard(history, tmp_path / "dashboard.html").read_text(
        encoding="utf-8"
    )

    assert "http://" not in content
    assert "https://" not in content
    assert "<svg" in content
    assert "addEventListener" in content


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
