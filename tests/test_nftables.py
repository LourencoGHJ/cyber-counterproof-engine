import hashlib
from cce.nftables import validate_rules_file

def test_validate_file_reports_hash_and_never_applies(tmp_path, monkeypatch):
    f = tmp_path / "rules.nft"
    f.write_text("table inet cce_test { }\\n", encoding="utf-8")
    class Result:
        returncode, stdout, stderr = 0, "", ""
    monkeypatch.setattr("cce.nftables._nft", lambda: "/usr/bin/nft")
    monkeypatch.setattr("cce.nftables.subprocess.run", lambda *a, **kw: Result())
    result = validate_rules_file(f)
    assert result["valid"] is True
    assert result["applied"] is False
    assert result["sha256"] == hashlib.sha256(f.read_bytes()).hexdigest()
