import hashlib

from cce.nftables import validate_rules_file


def make_result(returncode, stdout="", stderr=""):
    class Result:
        pass

    result = Result()
    result.returncode = returncode
    result.stdout = stdout
    result.stderr = stderr
    return result


def setup_nft_mock(monkeypatch, result):
    monkeypatch.setattr(
        "cce.nftables._nft",
        lambda: "/usr/sbin/nft",
    )
    monkeypatch.setattr(
        "cce.nftables.subprocess.run",
        lambda *args, **kwargs: result,
    )


def test_validate_file_reports_hash_and_never_applies(tmp_path, monkeypatch):
    f = tmp_path / "rules.nft"
    f.write_text("table inet cce_test { }\n", encoding="utf-8")
    setup_nft_mock(monkeypatch, make_result(0))

    result = validate_rules_file(f)

    assert result["status"] == "PASS"
    assert result["valid"] is True
    assert result["applied"] is False
    assert result["sha256"] == hashlib.sha256(f.read_bytes()).hexdigest()


def test_invalid_rules_return_fail(tmp_path, monkeypatch):
    f = tmp_path / "invalid.nft"
    f.write_text("invalid syntax\n", encoding="utf-8")
    setup_nft_mock(
        monkeypatch,
        make_result(1, stderr="syntax error, unexpected invalid"),
    )

    result = validate_rules_file(f)

    assert result["status"] == "FAIL"
    assert result["valid"] is False
    assert result["applied"] is False


def test_netlink_permission_error_returns_error(tmp_path, monkeypatch):
    f = tmp_path / "rules.nft"
    f.write_text("table inet cce_test { }\n", encoding="utf-8")
    setup_nft_mock(
        monkeypatch,
        make_result(
            1,
            stderr="netlink: Error: cache initialization failed: Operation not permitted",
        ),
    )

    result = validate_rules_file(f)

    assert result["status"] == "ERROR"
    assert result["valid"] is None
    assert result["applied"] is False


def test_unexpected_execution_error_returns_error(tmp_path, monkeypatch):
    f = tmp_path / "rules.nft"
    f.write_text("table inet cce_test { }\n", encoding="utf-8")
    setup_nft_mock(
        monkeypatch,
        make_result(1, stderr="internal execution error"),
    )

    result = validate_rules_file(f)

    assert result["status"] == "ERROR"
    assert result["valid"] is None
    assert result["applied"] is False
