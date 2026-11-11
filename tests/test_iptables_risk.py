import json

from cce.iptables_risk import find_ssh_rule_candidates


def sample():
    return (
        "*filter\n"
        ":INPUT DROP [0:0]\n"
        ":OUTPUT ACCEPT [0:0]\n"
        ":FORWARD DROP [0:0]\n"
        ":ufw-before-input - [0:0]\n"
        ":orphan - [0:0]\n"
        "-A INPUT -j ufw-before-input\n"
        "COMMIT\n"
    )


def add_rule(snapshot, rule):
    return snapshot.replace("COMMIT\n", f"{rule}\nCOMMIT\n", 1)


def test_detects_ssh_accept_without_source_restriction():
    snapshot = add_rule(
        sample(),
        "-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT",
    )

    candidates = find_ssh_rule_candidates(snapshot, "ipv4")

    assert len(candidates) == 1
    assert candidates[0]["family"] == "ipv4"
    assert candidates[0]["chain"] == "INPUT"
    assert candidates[0]["severity"] == "medium"
    assert candidates[0]["confidence"] == "candidate"


def test_positive_source_restriction_suppresses_candidate():
    snapshot = add_rule(
        sample(),
        "-A INPUT -p tcp -s 192.0.2.0/24 "
        "-m tcp --dport 22 -j ACCEPT",
    )

    assert find_ssh_rule_candidates(snapshot, "ipv4") == []


def test_wildcard_source_is_not_a_restrictive_source():
    snapshot = add_rule(
        sample(),
        "-A INPUT -p tcp -s 0.0.0.0/0 "
        "-m tcp --dport 22 -j ACCEPT",
    )

    candidates = find_ssh_rule_candidates(snapshot, "ipv4")

    assert len(candidates) == 1
    assert "0.0.0.0/0" not in json.dumps(candidates)


def test_negated_destination_port_is_not_reported_as_ssh_allow():
    snapshot = add_rule(
        sample(),
        "-A INPUT -p tcp -m tcp ! --dport 22 -j ACCEPT",
    )

    assert find_ssh_rule_candidates(snapshot, "ipv4") == []


def test_detects_candidate_in_reachable_user_chain():
    snapshot = add_rule(
        sample(),
        "-A ufw-before-input -p tcp -m tcp --dport 22 -j ACCEPT",
    )

    candidates = find_ssh_rule_candidates(snapshot, "ipv4")

    assert len(candidates) == 1
    assert candidates[0]["chain"] == "ufw-before-input"
    assert candidates[0]["severity"] == "low"


def test_ignores_candidate_in_unreachable_chain():
    snapshot = add_rule(
        sample(),
        "-A orphan -p tcp -m tcp --dport 22 -j ACCEPT",
    )

    assert find_ssh_rule_candidates(snapshot, "ipv4") == []
