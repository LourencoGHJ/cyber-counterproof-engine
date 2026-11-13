import json

from cce.cli import main, make_parser


def write_json(path, data):
    path.write_text(json.dumps(data), encoding="utf-8")


def valid_policy(policy_id="test-policy"):
    return {
        "policy_id": policy_id,
        "input_policy": "drop",
        "output_policy": "accept",
        "rules": [
            {
                "id": "R001",
                "chain": "input",
                "action": "accept",
                "protocol": "tcp",
                "source": "any",
                "destination_port": 443,
                "service": "https",
            }
        ],
    }


def run_compare(expected, observed, output, monkeypatch):
    monkeypatch.setattr(
        "sys.argv",
        [
            "cce",
            "compare-policy",
            "--expected", str(expected),
            "--observed", str(observed),
            "--output", str(output),
        ],
    )
    return main()


def test_compare_policy_passes_for_identical_policies(tmp_path, monkeypatch, capsys):
    policy = valid_policy()
    expected = tmp_path / "expected.json"
    observed = tmp_path / "observed.json"
    output = tmp_path / "report.json"
    write_json(expected, policy)
    write_json(observed, policy)

    assert run_compare(expected, observed, output, monkeypatch) == 0
    assert "CCE: PASS" in capsys.readouterr().out
    assert output.exists()
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["result"]["status"] == "PASS"


def test_compare_policy_rejects_invalid_rules(tmp_path, monkeypatch, capsys):
    invalid = valid_policy("bad")
    invalid["rules"] = "not-a-list"
    expected = tmp_path / "expected.json"
    observed = tmp_path / "observed.json"
    output = tmp_path / "report.json"
    write_json(expected, invalid)
    write_json(observed, valid_policy("observed"))

    assert run_compare(expected, observed, output, monkeypatch) == 2
    assert "Política esperada inválida" in capsys.readouterr().err
    assert not output.exists()


def test_compare_policy_handles_missing_file(tmp_path, monkeypatch, capsys):
    missing = tmp_path / "missing.json"
    observed = tmp_path / "observed.json"
    output = tmp_path / "report.json"
    write_json(observed, valid_policy("observed"))

    assert run_compare(missing, observed, output, monkeypatch) == 2
    assert "ERRO:" in capsys.readouterr().err
    assert not output.exists()


def test_compare_policy_rejects_invalid_action_field(tmp_path, monkeypatch, capsys):
    invalid = valid_policy("bad-action")
    invalid["input_policy"] = ["accept"]
    expected = tmp_path / "expected.json"
    observed = tmp_path / "observed.json"
    output = tmp_path / "report.json"
    write_json(expected, invalid)
    write_json(observed, valid_policy("observed"))

    assert run_compare(expected, observed, output, monkeypatch) == 2
    assert "input_policy" in capsys.readouterr().err
    assert not output.exists()




def test_compare_iptables_save_reports_ssh_candidate(
    tmp_path, monkeypatch, capsys
):
    policy_file = tmp_path / "policy.json"
    ipv4_file = tmp_path / "rules-v4.save"
    ipv6_file = tmp_path / "rules-v6.save"
    output_file = tmp_path / "report.json"

    write_json(policy_file, valid_policy())

    safe_snapshot = (
        "*filter\n"
        ":INPUT DROP [0:0]\n"
        ":OUTPUT ACCEPT [0:0]\n"
        ":FORWARD DROP [0:0]\n"
        "COMMIT\n"
    )
    ipv4_snapshot = safe_snapshot.replace(
        "COMMIT\n",
        "-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT\nCOMMIT\n",
        1,
    )

    ipv4_file.write_text(ipv4_snapshot, encoding="utf-8")
    ipv6_file.write_text(safe_snapshot, encoding="utf-8")

    monkeypatch.setattr(
        "sys.argv",
        [
            "cce",
            "compare-iptables-save",
            "--policy", str(policy_file),
            "--ipv4", str(ipv4_file),
            "--ipv6", str(ipv6_file),
            "--output", str(output_file),
        ],
    )

    # A regra HTTPS declarada não existe em nenhum dos dois snapshots.
    # A análise de SSH é independente e não substitui a comparação semântica.
    assert main() == 1

    output = capsys.readouterr().out
    assert "CCE: DRIFT" in output
    assert "Drifts de regras: 2" in output
    assert "[MISSING] R001" in output
    assert "Riscos candidatos: 1" in output
    assert "possível SSH/TCP/22" in output

    report = json.loads(output_file.read_text(encoding="utf-8"))
    assert report["result"]["summary"]["rule_risk_candidates"] == 1
    assert report["result"]["rule_risk_candidates"][0]["family"] == "ipv4"
    assert report["result"]["summary"]["rules_semantically_compared"] == 2
    assert report["result"]["summary"]["semantic_rule_drifts"] == 2
    assert report["result"]["rule_policy_comparison"]["summary"]["rules_missing"] == 2

def test_compare_iptables_save_reports_missing_policy_rules_as_drift(
    tmp_path, monkeypatch, capsys
):
    policy_file = tmp_path / "policy.json"
    ipv4_file = tmp_path / "rules-v4.save"
    ipv6_file = tmp_path / "rules-v6.save"
    output_file = tmp_path / "report.json"

    write_json(policy_file, valid_policy())

    snapshot = (
        "*filter\n"
        ":INPUT DROP [0:0]\n"
        ":OUTPUT ACCEPT [0:0]\n"
        ":FORWARD DROP [0:0]\n"
        "COMMIT\n"
    )
    ipv4_file.write_text(snapshot, encoding="utf-8")
    ipv6_file.write_text(snapshot, encoding="utf-8")

    monkeypatch.setattr(
        "sys.argv",
        [
            "cce",
            "compare-iptables-save",
            "--policy", str(policy_file),
            "--ipv4", str(ipv4_file),
            "--ipv6", str(ipv6_file),
            "--output", str(output_file),
        ],
    )

    assert main() == 1
    output = capsys.readouterr().out
    assert "CCE: DRIFT" in output
    assert "[MISSING] R001" in output

    report = json.loads(output_file.read_text(encoding="utf-8"))
    assert report["result"]["status"] == "DRIFT"
    assert report["result"]["summary"]["base_policies_matched"] == 4
    assert report["result"]["summary"]["rules_semantically_compared"] == 2
    assert report["result"]["summary"]["semantic_rule_drifts"] == 2



def test_serve_dashboard_cli_exposes_live_read_only_options():
    args = make_parser().parse_args(
        [
            "serve-dashboard",
            "--policy", "config/policy.json",
            "--source", "auto",
            "--host", "127.0.0.1",
            "--port", "9000",
            "--interval-ms", "1500",
            "--timeout", "4",
            "--sudo-readonly",
        ]
    )

    assert args.command == "serve-dashboard"
    assert args.policy == "config/policy.json"
    assert args.source == "auto"
    assert args.host == "127.0.0.1"
    assert args.port == 9000
    assert args.interval_ms == 1500
    assert args.timeout == 4
    assert args.sudo_readonly is True


def test_serve_dashboard_cli_loads_policy_and_starts_server(
    tmp_path, monkeypatch
):
    policy_file = tmp_path / "policy.json"
    write_json(policy_file, valid_policy())
    captured = {}

    def fake_serve(**kwargs):
        captured.update(kwargs)

    monkeypatch.setattr("cce.cli.serve_live_dashboard", fake_serve)
    monkeypatch.setattr(
        "sys.argv",
        [
            "cce",
            "serve-dashboard",
            "--policy", str(policy_file),
            "--host", "127.0.0.1",
            "--port", "9010",
            "--interval-ms", "1000",
            "--timeout", "4",
            "--sudo-readonly",
        ],
    )

    assert main() == 0
    assert captured["policy_path"] == str(policy_file)
    assert captured["host"] == "127.0.0.1"
    assert captured["port"] == 9010
    assert captured["interval_seconds"] == 1.0
    assert captured["timeout_seconds"] == 4
    assert captured["sudo_readonly"] is True


def test_serve_dashboard_cli_rejects_invalid_policy(tmp_path, monkeypatch, capsys):
    policy_file = tmp_path / "policy.json"
    invalid = valid_policy()
    invalid["input_policy"] = "invalid"
    write_json(policy_file, invalid)

    def should_not_start(**_kwargs):
        raise AssertionError("The service must not start with an invalid policy.")

    monkeypatch.setattr("cce.cli.serve_live_dashboard", should_not_start)
    monkeypatch.setattr(
        "sys.argv",
        ["cce", "serve-dashboard", "--policy", str(policy_file)],
    )

    assert main() == 2
    assert "input_policy" in capsys.readouterr().err
