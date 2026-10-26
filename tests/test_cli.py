import json

from cce.cli import main


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
