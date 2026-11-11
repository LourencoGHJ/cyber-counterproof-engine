import json
from pathlib import Path

from cce.cli import main


def test_evaluate_scenarios_matches_all_four_expected_verdicts(
    tmp_path, monkeypatch, capsys
):
    project_root = Path(__file__).resolve().parents[1]
    manifest = project_root / "examples" / "firewall-scenarios.json"
    output = tmp_path / "reports" / "scenario-results.json"

    monkeypatch.setattr(
        "sys.argv",
        [
            "cce",
            "evaluate-scenarios",
            "--manifest",
            str(manifest),
            "--output",
            str(output),
        ],
    )

    assert main() == 0

    stdout = capsys.readouterr().out
    assert "[OK] https-allowed: esperado=ACCEPT obtido=ACCEPT" in stdout
    assert "[OK] ssh-source-restricted: esperado=DROP obtido=DROP" in stdout
    assert "[OK] telnet-rejected: esperado=REJECT obtido=REJECT" in stdout
    assert (
        "[OK] https-rate-limit-unsupported: "
        "esperado=INCONCLUSIVE obtido=INCONCLUSIVE"
    ) in stdout
    assert "CCE: 4/4 cenários corretos" in stdout

    report_text = output.read_text(encoding="utf-8")
    report = json.loads(report_text)
    assert report["summary"] == {
        "scenarios_total": 4,
        "scenarios_passed": 4,
        "scenarios_failed": 0,
    }
    actual = {item["id"]: item["actual"] for item in report["scenarios"]}
    assert actual == {
        "https-allowed": "ACCEPT",
        "ssh-source-restricted": "DROP",
        "telnet-rejected": "REJECT",
        "https-rate-limit-unsupported": "INCONCLUSIVE",
    }

    for scenario in report["scenarios"]:
        assert scenario["passed"] is True
        assert scenario["result"]["decision_explanation"]
        for step in scenario["result"]["trace"]:
            assert step["explanation"]

    # Reports must not include packet IP addresses from the synthetic inputs.
    assert "192.0.2.10" not in report_text
    assert "198.51.100.20" not in report_text
    assert "203.0.113.25" not in report_text
    assert "203.0.113.30" not in report_text


def test_evaluate_scenarios_returns_failure_when_expected_verdict_is_wrong(
    tmp_path, monkeypatch, capsys
):
    project_root = Path(__file__).resolve().parents[1]
    original = json.loads(
        (project_root / "examples" / "firewall-scenarios.json").read_text(
            encoding="utf-8"
        )
    )
    original["scenarios"] = [original["scenarios"][0]]
    original["scenarios"][0]["expected"] = "DROP"

    manifest = tmp_path / "manifest.json"
    output = tmp_path / "scenario-results.json"
    manifest.write_text(json.dumps(original), encoding="utf-8")

    # Copy the scenario inputs under the temporary manifest directory so that
    # manifest-relative paths remain inside its allowed root.
    scenario_root = tmp_path / "firewall-scenarios"
    scenario_root.mkdir()
    source_snapshot = (
        project_root
        / "examples"
        / "firewall-scenarios"
        / "accept-https.save"
    )
    (scenario_root / "accept-https.save").write_text(
        source_snapshot.read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    packet_root = tmp_path / "packets"
    packet_root.mkdir()
    source_packet = project_root / "examples" / "packets" / "https-request.json"
    (packet_root / "https-request.json").write_text(
        source_packet.read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        "sys.argv",
        [
            "cce",
            "evaluate-scenarios",
            "--manifest",
            str(manifest),
            "--output",
            str(output),
        ],
    )

    assert main() == 1
    assert "[FALHOU] https-allowed: esperado=DROP obtido=ACCEPT" in capsys.readouterr().out
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["summary"]["scenarios_failed"] == 1
