import json

from cce.cli import main


def write_json(path, data):
    path.write_text(json.dumps(data), encoding="utf-8")


def test_compare_policy_passes_for_identical_policies(tmp_path, monkeypatch, capsys):
    policy = {
        "policy_id": "test-policy",
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

    expected = tmp_path / "expected.json"
    observed = tmp_path / "observed.json"
    output = tmp_path / "report.json"

    write_json(expected, policy)
    write_json(observed, policy)

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

    assert main() == 0
    assert "CCE: PASS" in capsys.readouterr().out
    assert output.exists()

    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["result"]["status"] == "PASS"


def test_compare_policy_rejects_invalid_rules(tmp_path, monkeypatch, capsys):
    invalid = tmp_path / "invalid.json"
    observed = tmp_path / "observed.json"
    output = tmp_path / "report.json"

    write_json(invalid, {"policy_id": "bad", "rules": "not-a-list"})
    write_json(observed, {"policy_id": "observed", "rules": []})

    monkeypatch.setattr(
        "sys.argv",
        [
            "cce",
            "compare-policy",
            "--expected", str(invalid),
            "--observed", str(observed),
            "--output", str(output),
        ],
    )

    assert main() == 2
    assert "ERRO:" in capsys.readouterr().err
    assert not output.exists()


def test_compare_policy_handles_missing_file(tmp_path, monkeypatch, capsys):
    missing = tmp_path / "missing.json"
    observed = tmp_path / "observed.json"
    output = tmp_path / "report.json"

    write_json(observed, {"policy_id": "observed", "rules": []})

    monkeypatch.setattr(
        "sys.argv",
        [
            "cce",
            "compare-policy",
            "--expected", str(missing),
            "--observed", str(observed),
            "--output", str(output),
        ],
    )

    assert main() == 2
    assert "ERRO:" in capsys.readouterr().err
    assert not output.exists()
