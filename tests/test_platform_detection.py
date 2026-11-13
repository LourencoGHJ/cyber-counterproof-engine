from cce.platform import detection


def test_linux_platform_detects_firewall_tools(monkeypatch):
    monkeypatch.setattr(detection.platform, "system", lambda: "Linux")
    monkeypatch.setattr(
        detection.platform,
        "freedesktop_os_release",
        lambda: {"PRETTY_NAME": "Manjaro Linux"},
    )
    tools = {
        "iptables-save": "/usr/bin/iptables-save",
        "ip6tables-save": "/usr/bin/ip6tables-save",
        "nft": "/usr/bin/nft",
        "sudo": "/usr/bin/sudo",
    }
    monkeypatch.setattr(
        detection.shutil, "which", lambda name: tools.get(name)
    )
    monkeypatch.setattr(detection.os, "geteuid", lambda: 1000, raising=False)

    info = detection.detect_platform()

    assert info["host"]["system"] == "linux"
    assert info["host"]["distribution"] == "Manjaro Linux"
    assert info["privileges"]["context"] == "standard_user"
    assert len(info["adapters"]) == 2
    assert all(item["status"] == "available" for item in info["adapters"])
    assert info["security"]["firewall_commands_executed"] is False


def test_windows_detection_reports_implemented_adapter(monkeypatch):
    monkeypatch.setattr(detection.platform, "system", lambda: "Windows")
    monkeypatch.setattr(
        detection.shutil, "which",
        lambda name: "C:/PowerShell/pwsh.exe" if name == "pwsh" else None,
    )
    monkeypatch.setattr(detection, "_is_admin", lambda _system: False)

    info = detection.detect_platform()

    assert info["host"]["system"] == "windows"
    assert info["adapters"][0]["implementation"] == "implemented"
    assert info["adapters"][0]["status"] == "available"
    assert "NetSecurity" in info["adapters"][0]["note"]


def test_windows_detection_reports_missing_powershell(monkeypatch):
    monkeypatch.setattr(detection.platform, "system", lambda: "Windows")
    monkeypatch.setattr(detection.shutil, "which", lambda _name: None)
    monkeypatch.setattr(detection, "_is_admin", lambda _system: False)

    info = detection.detect_platform()

    assert info["adapters"][0]["implementation"] == "implemented"
    assert info["adapters"][0]["status"] == "tool_not_found"
    assert info["adapters"][0]["available"] is False


def test_unknown_platform_is_not_misclassified(monkeypatch):
    monkeypatch.setattr(detection.platform, "system", lambda: "FreeBSD")
    monkeypatch.setattr(detection, "_is_admin", lambda _system: False)
    monkeypatch.setattr(detection.shutil, "which", lambda _name: None)

    info = detection.detect_platform()

    assert info["host"]["system"] == "unknown"
    assert info["adapters"] == []


def test_platform_info_cli_commands_are_registered():
    from cce.cli import make_parser

    assert make_parser().parse_args(["doctor"]).command == "doctor"
    assert make_parser().parse_args(
        ["platform-info", "--json"]
    ).command == "platform-info"
