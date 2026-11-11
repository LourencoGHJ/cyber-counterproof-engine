import json

from cce.cli import main


def test_conflict_cli_writes_report_and_returns_findings_status(
    tmp_path, monkeypatch, capsys
):
    snapshot = tmp_path / "firewall.save"
    output = tmp_path / "reports" / "conflicts.json"
    snapshot.write_text(
        "*filter\n"
        ":INPUT DROP [0:0]\n"
        ":OUTPUT ACCEPT [0:0]\n"
        ":FORWARD DROP [0:0]\n"
        "-A INPUT -s 192.0.2.0/24 -p tcp -j DROP\n"
        "-A INPUT -s 192.0.2.10/32 -p tcp -j ACCEPT\n"
        "COMMIT\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        "sys.argv",
        [
            "cce",
            "analyze-rule-conflicts",
            "--snapshot", str(snapshot),
            "--family", "ipv4",
            "--output", str(output),
        ],
    )

    assert main() == 1
    stdout = capsys.readouterr().out
    assert "Sombreadas: 1" in stdout

    report_text = output.read_text(encoding="utf-8")
    report = json.loads(report_text)
    assert report["operation"] == "analyze_rule_conflicts"
    assert report["result"]["findings"][0]["code"] == "SHADOWED_RULE"
    assert "192.0.2.0/24" not in report_text
    assert "192.0.2.10/32" not in report_text


def test_conflict_cli_returns_zero_when_rules_are_disjoint(
    tmp_path, monkeypatch, capsys
):
    snapshot = tmp_path / "firewall.save"
    output = tmp_path / "conflicts.json"
    snapshot.write_text(
        "*filter\n"
        ":INPUT DROP [0:0]\n"
        ":OUTPUT ACCEPT [0:0]\n"
        ":FORWARD DROP [0:0]\n"
        "-A INPUT -s 192.0.2.0/24 -p tcp -j ACCEPT\n"
        "-A INPUT -s 203.0.113.0/24 -p tcp -j DROP\n"
        "COMMIT\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        "sys.argv",
        [
            "cce",
            "analyze-rule-conflicts",
            "--snapshot", str(snapshot),
            "--family", "ipv4",
            "--output", str(output),
        ],
    )

    assert main() == 0
    assert "0 descoberta(s)" in capsys.readouterr().out
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["result"]["findings"] == []


def test_conflict_cli_handles_malformed_snapshot(
    tmp_path, monkeypatch, capsys
):
    snapshot = tmp_path / "malformed.save"
    output = tmp_path / "conflicts.json"
    snapshot.write_text(
        "*filter\n"
        ":INPUT DROP [0:0]\n"
        "not-an-iptables-rule\n"
        "COMMIT\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        "sys.argv",
        [
            "cce",
            "analyze-rule-conflicts",
            "--snapshot", str(snapshot),
            "--family", "ipv4",
            "--output", str(output),
        ],
    )

    assert main() == 2
    assert "ERRO:" in capsys.readouterr().err
    assert not output.exists()



def test_conflict_cli_reports_unmatchable_rule_without_pair_location(
    tmp_path, monkeypatch, capsys
):
    snapshot = tmp_path / "impossible-flags.save"
    output = tmp_path / "conflicts.json"
    snapshot.write_text(
        "*filter\n"
        ":INPUT DROP [0:0]\n"
        ":OUTPUT ACCEPT [0:0]\n"
        ":FORWARD DROP [0:0]\n"
        "-A INPUT -p tcp ! --tcp-flags NONE NONE -j DROP\n"
        "COMMIT\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        "sys.argv",
        [
            "cce",
            "analyze-rule-conflicts",
            "--snapshot", str(snapshot),
            "--family", "ipv4",
            "--output", str(output),
        ],
    )

    assert main() == 1
    stdout = capsys.readouterr().out
    assert "UNMATCHABLE_RULE" in stdout
    assert "INPUT:5 | DROP" in stdout

    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["result"]["summary"]["unmatchable_terminal_rules"] == 1
