import json

from cce.cli import main


def write_json(path, data):
    path.write_text(json.dumps(data), encoding="utf-8")


def make_snapshot(rule):
    return (
        "*filter\n"
        ":INPUT DROP [0:0]\n"
        ":OUTPUT ACCEPT [0:0]\n"
        ":FORWARD DROP [0:0]\n"
        f"{rule}"
        "COMMIT\n"
    )


def run_evaluate(snapshot, packet, output, monkeypatch, hook="INPUT"):
    monkeypatch.setattr(
        "sys.argv",
        [
            "cce",
            "evaluate-packet",
            "--snapshot", str(snapshot),
            "--family", "ipv4",
            "--hook", hook,
            "--packet", str(packet),
            "--output", str(output),
        ],
    )
    return main()


def valid_packet(**overrides):
    data = {
        "source_ip": "192.0.2.10",
        "destination_ip": "198.51.100.20",
        "protocol": "tcp",
        "source_port": 51514,
        "destination_port": 443,
        "input_interface": "eth0",
        "connection_state": "NEW",
        "tcp_flags": ["SYN"],
        "is_non_initial_fragment": False,
    }
    data.update(overrides)
    return data


def test_evaluate_packet_writes_accept_report_without_packet_addresses(
    tmp_path, monkeypatch, capsys
):
    snapshot = tmp_path / "firewall.save"
    packet = tmp_path / "packet.json"
    output = tmp_path / "reports" / "evaluation.json"
    snapshot.write_text(
        make_snapshot("-A INPUT -p tcp --dport 443 -j ACCEPT\n"),
        encoding="utf-8",
    )
    write_json(packet, valid_packet())

    assert run_evaluate(snapshot, packet, output, monkeypatch) == 0

    stdout = capsys.readouterr().out
    assert "CCE: ACCEPT" in stdout
    assert "Decisão: ACCEPT" in stdout

    report_text = output.read_text(encoding="utf-8")
    report = json.loads(report_text)
    assert report["operation"] == "evaluate_packet"
    assert report["result"]["status"] == "ACCEPT"
    assert report["result"]["trace"][0]["action"] == "ACCEPT"
    assert "192.0.2.10" not in report_text
    assert "198.51.100.20" not in report_text
    assert report["input_evidence"]["snapshot"]["sha256"]
    assert report["input_evidence"]["packet_metadata"]["sha256"]


def test_evaluate_packet_returns_inconclusive_when_required_metadata_is_missing(
    tmp_path, monkeypatch, capsys
):
    snapshot = tmp_path / "firewall.save"
    packet = tmp_path / "packet.json"
    output = tmp_path / "evaluation.json"
    snapshot.write_text(
        make_snapshot("-A INPUT -p tcp --dport 443 -j ACCEPT\n"),
        encoding="utf-8",
    )
    write_json(packet, valid_packet(destination_port=None))

    assert run_evaluate(snapshot, packet, output, monkeypatch) == 3
    assert "CCE: INCONCLUSIVE" in capsys.readouterr().out

    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["result"]["status"] == "INCONCLUSIVE"


def test_evaluate_packet_rejects_missing_required_packet_fields(
    tmp_path, monkeypatch, capsys
):
    snapshot = tmp_path / "firewall.save"
    packet = tmp_path / "packet.json"
    output = tmp_path / "evaluation.json"
    snapshot.write_text(make_snapshot(""), encoding="utf-8")
    write_json(packet, {"source_ip": "192.0.2.10", "protocol": "tcp"})

    assert run_evaluate(snapshot, packet, output, monkeypatch) == 2
    assert "destination_ip" in capsys.readouterr().err
    assert not output.exists()


def test_evaluate_packet_rejects_unknown_packet_fields(
    tmp_path, monkeypatch, capsys
):
    snapshot = tmp_path / "firewall.save"
    packet = tmp_path / "packet.json"
    output = tmp_path / "evaluation.json"
    snapshot.write_text(make_snapshot(""), encoding="utf-8")
    write_json(packet, valid_packet(unexpected="value"))

    assert run_evaluate(snapshot, packet, output, monkeypatch) == 2
    assert "unexpected" in capsys.readouterr().err
    assert not output.exists()


def test_evaluate_packet_returns_error_for_family_mismatch(
    tmp_path, monkeypatch, capsys
):
    snapshot = tmp_path / "firewall.save"
    packet = tmp_path / "packet.json"
    output = tmp_path / "evaluation.json"
    snapshot.write_text(make_snapshot(""), encoding="utf-8")
    write_json(packet, valid_packet(source_ip="2001:db8::10"))

    assert run_evaluate(snapshot, packet, output, monkeypatch) == 2
    assert "não corresponde à família" in capsys.readouterr().err
    assert not output.exists()


def test_evaluate_packet_rejects_non_list_tcp_flags(
    tmp_path, monkeypatch, capsys
):
    snapshot = tmp_path / "firewall.save"
    packet = tmp_path / "packet.json"
    output = tmp_path / "evaluation.json"
    snapshot.write_text(make_snapshot(""), encoding="utf-8")
    write_json(packet, valid_packet(tcp_flags="SYN"))

    assert run_evaluate(snapshot, packet, output, monkeypatch) == 2
    assert "tcp_flags" in capsys.readouterr().err
    assert not output.exists()
