import json

import pytest

from cce.packet import Packet
from cce.rule_evaluator import evaluate_iptables_packet


def make_snapshot(rules="", extra_chains=""):
    return (
        "*filter\n"
        ":INPUT DROP [0:0]\n"
        ":OUTPUT ACCEPT [0:0]\n"
        ":FORWARD DROP [0:0]\n"
        f"{extra_chains}"
        f"{rules}"
        "COMMIT\n"
    )


def packet(**overrides):
    fields = {
        "family": "ipv4",
        "source_ip": "192.0.2.10",
        "destination_ip": "198.51.100.20",
        "protocol": "tcp",
        "source_port": 51000,
        "destination_port": 443,
        "input_interface": "eth0",
        "output_interface": "eth1",
        "connection_state": "NEW",
        "tcp_flags": frozenset({"SYN"}),
        "is_non_initial_fragment": False,
    }
    fields.update(overrides)
    return Packet(**fields)


def evaluate(snapshot, candidate=None, **kwargs):
    return evaluate_iptables_packet(
        snapshot,
        "ipv4",
        candidate or packet(),
        **kwargs,
    )


def test_accepts_packet_matching_terminal_accept_rule():
    result = evaluate(
        make_snapshot("-A INPUT -p tcp --dport 443 -j ACCEPT\n")
    )

    assert result.status == "ACCEPT"
    assert result.decision_source == "rule"
    assert result.trace[0].result == "match"
    assert result.trace[0].action == "ACCEPT"


def test_drops_packet_when_no_rule_matches_and_policy_is_drop():
    result = evaluate(
        make_snapshot("-A INPUT -p tcp --dport 22 -j ACCEPT\n")
    )

    assert result.status == "DROP"
    assert result.decision_source == "base_chain_policy"
    assert result.trace[0].result == "no_match"


def test_uses_accept_base_chain_policy_when_no_rule_matches():
    snapshot = make_snapshot().replace(
        ":INPUT DROP [0:0]\n",
        ":INPUT ACCEPT [0:0]\n",
    )

    result = evaluate(snapshot)

    assert result.status == "ACCEPT"
    assert result.decision_source == "base_chain_policy"


def test_matches_source_and_destination_networks():
    result = evaluate(
        make_snapshot(
            "-A INPUT -s 192.0.2.0/24 -d 198.51.100.0/24 "
            "-p tcp --dport 443 -j ACCEPT\n"
        )
    )

    assert result.status == "ACCEPT"


def test_skips_rule_when_source_network_does_not_match():
    result = evaluate(
        make_snapshot(
            "-A INPUT -s 203.0.113.0/24 -p tcp --dport 443 -j ACCEPT\n"
        )
    )

    assert result.status == "DROP"
    assert result.trace[0].reason == "source_mismatch"


def test_supports_negated_source_network():
    result = evaluate(
        make_snapshot(
            "-A INPUT ! -s 203.0.113.0/24 -p tcp --dport 443 -j ACCEPT\n"
        )
    )

    assert result.status == "ACCEPT"


def test_supports_destination_port_ranges():
    result = evaluate(
        make_snapshot(
            "-A INPUT -p tcp -m multiport --dports 80:90,443 -j ACCEPT\n"
        ),
        packet(destination_port=85),
    )

    assert result.status == "ACCEPT"


def test_missing_packet_port_produces_inconclusive():
    result = evaluate(
        make_snapshot("-A INPUT -p tcp --dport 443 -j ACCEPT\n"),
        packet(destination_port=None),
    )

    assert result.status == "INCONCLUSIVE"
    assert result.decision_source == "rule_interpretation"


def test_supports_exact_and_prefix_interface_matching():
    exact = evaluate(
        make_snapshot("-A INPUT -i eth0 -p tcp -j ACCEPT\n")
    )
    prefix = evaluate(
        make_snapshot("-A INPUT -i eth+ -p tcp -j ACCEPT\n")
    )

    assert exact.status == "ACCEPT"
    assert prefix.status == "ACCEPT"


def test_interface_mismatch_skips_rule():
    result = evaluate(
        make_snapshot("-A INPUT -i wlan+ -p tcp -j ACCEPT\n")
    )

    assert result.status == "DROP"
    assert result.trace[0].reason == "input_interface_mismatch"


def test_supports_connection_state_matching():
    result = evaluate(
        make_snapshot(
            "-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n"
        ),
        packet(connection_state="ESTABLISHED"),
    )

    assert result.status == "ACCEPT"


def test_missing_connection_state_is_inconclusive():
    result = evaluate(
        make_snapshot("-A INPUT -m conntrack --ctstate NEW -j ACCEPT\n"),
        packet(connection_state=None),
    )

    assert result.status == "INCONCLUSIVE"


def test_unsupported_module_is_inconclusive_when_known_conditions_match():
    result = evaluate(
        make_snapshot(
            "-A INPUT -p tcp -m recent --name ssh --set -j ACCEPT\n"
        )
    )

    assert result.status == "INCONCLUSIVE"
    assert result.trace[0].result == "inconclusive"


def test_known_mismatch_can_skip_partially_interpreted_rule():
    result = evaluate(
        make_snapshot(
            "-A INPUT -p tcp --dport 22 "
            "-m recent --name ssh --set -j ACCEPT\n"
        )
    )

    assert result.status == "DROP"
    assert result.trace[0].result == "no_match"


def test_jump_to_user_chain_can_return_terminal_verdict():
    snapshot = make_snapshot(
        "-A INPUT -j ssh-check\n"
        ":ssh-check - [0:0]\n"
        "-A ssh-check -p tcp --dport 443 -j ACCEPT\n"
    )

    result = evaluate(snapshot)

    assert result.status == "ACCEPT"
    assert [step.action for step in result.trace] == ["jump", "ACCEPT"]


def test_jump_resumes_caller_after_user_chain_returns():
    snapshot = make_snapshot(
        "-A INPUT -j empty-chain\n"
        "-A INPUT -p tcp --dport 443 -j ACCEPT\n"
        ":empty-chain - [0:0]\n"
    )

    result = evaluate(snapshot)

    assert result.status == "ACCEPT"
    assert [step.chain for step in result.trace] == ["INPUT", "INPUT"]
    assert result.trace[1].action == "ACCEPT"


def test_goto_return_skips_remainder_of_current_user_chain():
    snapshot = make_snapshot(
        "-A INPUT -j outer\n"
        "-A INPUT -p tcp --dport 443 -j ACCEPT\n"
        ":outer - [0:0]\n"
        ":inner - [0:0]\n"
        "-A outer -g inner\n"
        "-A outer -p tcp --dport 443 -j DROP\n"
    )

    result = evaluate(snapshot)

    assert result.status == "ACCEPT"
    assert [step.chain for step in result.trace] == [
        "INPUT",
        "outer",
        "INPUT",
    ]


def test_explicit_return_in_user_chain_resumes_after_jump():
    snapshot = make_snapshot(
        "-A INPUT -j child\n"
        "-A INPUT -p tcp --dport 443 -j ACCEPT\n"
        ":child - [0:0]\n"
        "-A child -p tcp -j RETURN\n"
    )

    result = evaluate(snapshot)

    assert result.status == "ACCEPT"
    assert result.trace[1].action == "RETURN"


def test_explicit_return_in_base_chain_applies_base_policy():
    result = evaluate(
        make_snapshot("-A INPUT -j RETURN\n")
    )

    assert result.status == "DROP"
    assert result.decision_source == "base_chain_policy"


def test_reject_is_a_terminal_verdict():
    result = evaluate(
        make_snapshot("-A INPUT -p tcp --dport 443 -j REJECT\n")
    )

    assert result.status == "REJECT"


def test_unknown_extension_target_is_inconclusive():
    result = evaluate(
        make_snapshot("-A INPUT -p tcp -j LOG\n")
    )

    assert result.status == "INCONCLUSIVE"


def test_syn_match_requires_syn_without_ack_rst_or_fin():
    snapshot = make_snapshot("-A INPUT -p tcp --syn -j ACCEPT\n")

    syn = evaluate(snapshot, packet(tcp_flags=frozenset({"SYN"})))
    ack = evaluate(snapshot, packet(tcp_flags=frozenset({"SYN", "ACK"})))

    assert syn.status == "ACCEPT"
    assert ack.status == "DROP"


def test_tcp_syn_rule_without_tcp_flags_is_inconclusive():
    result = evaluate(
        make_snapshot("-A INPUT -p tcp --syn -j ACCEPT\n"),
        packet(tcp_flags=None),
    )

    assert result.status == "INCONCLUSIVE"


def test_fragment_match_requires_fragment_metadata():
    result = evaluate(
        make_snapshot("-A INPUT -f -j ACCEPT\n"),
        packet(is_non_initial_fragment=None),
    )

    assert result.status == "INCONCLUSIVE"


def test_missing_base_hook_is_inconclusive():
    snapshot = (
        "*filter\n"
        ":OUTPUT ACCEPT [0:0]\n"
        ":FORWARD DROP [0:0]\n"
        "COMMIT\n"
    )

    result = evaluate(snapshot)

    assert result.status == "INCONCLUSIVE"
    assert result.reason == "requested_base_chain_not_found"


def test_only_filter_table_is_supported():
    with pytest.raises(ValueError, match="tabela filter"):
        evaluate(make_snapshot(), table="nat")


def test_chain_recursion_returns_inconclusive():
    snapshot = make_snapshot(
        "-A INPUT -j first\n"
        ":first - [0:0]\n"
        ":second - [0:0]\n"
        "-A first -j second\n"
        "-A second -j first\n"
    )

    result = evaluate(snapshot)

    assert result.status == "INCONCLUSIVE"
    assert result.decision_source == "chain_recursion"


def test_chain_depth_limit_returns_inconclusive():
    snapshot = make_snapshot(
        "-A INPUT -j level1\n"
        + "".join(
            f":level{i} - [0:0]\n"
            f"-A level{i} -j level{i + 1}\n"
            for i in range(1, 5)
        )
        + ":level5 - [0:0]\n"
    )

    result = evaluate(snapshot, max_chain_depth=2)

    assert result.status == "INCONCLUSIVE"
    assert result.decision_source == "execution_limit"


def test_step_limit_returns_inconclusive():
    snapshot = make_snapshot(
        "-A INPUT -p udp --dport 53 -j ACCEPT\n"
        "-A INPUT -p tcp --dport 22 -j ACCEPT\n"
        "-A INPUT -p tcp --dport 443 -j ACCEPT\n"
    )

    result = evaluate(snapshot, max_steps=1)

    assert result.status == "INCONCLUSIVE"
    assert result.decision_source == "execution_limit"


def test_trace_does_not_expose_packet_addresses():
    snapshot = make_snapshot("-A INPUT -p tcp -j ACCEPT\n")

    result = evaluate(snapshot)
    rendered = json.dumps(result.to_dict(), ensure_ascii=False)

    assert "192.0.2.10" not in rendered
    assert "198.51.100.20" not in rendered


def test_packet_rejects_address_from_wrong_family():
    with pytest.raises(ValueError, match="família"):
        Packet(
            family="ipv4",
            source_ip="2001:db8::1",
            destination_ip="192.0.2.1",
            protocol="tcp",
        )


def test_snapshot_family_mismatch_is_inconclusive():
    result = evaluate(
        make_snapshot("-A INPUT -p tcp -j ACCEPT\n"),
        packet(family="ipv6", source_ip="2001:db8::1",
               destination_ip="2001:db8::2"),
    )

    assert result.status == "INCONCLUSIVE"
    assert result.decision_source == "input_validation"



def test_evaluates_tcp_flags_mask_and_comparison():
    result = evaluate(
        make_snapshot(
            "-A INPUT -p tcp --tcp-flags SYN,ACK,FIN,RST SYN -j ACCEPT\n"
        ),
        packet(tcp_flags=frozenset({"SYN"})),
    )

    assert result.status == "ACCEPT"
    assert result.trace[0].result == "match"


def test_tcp_flags_outside_mask_do_not_change_match_result():
    result = evaluate(
        make_snapshot(
            "-A INPUT -p tcp --tcp-flags SYN,ACK SYN -j ACCEPT\n"
        ),
        packet(tcp_flags=frozenset({"SYN", "ECE"})),
    )

    assert result.status == "ACCEPT"


def test_tcp_flags_inside_mask_can_prevent_match():
    result = evaluate(
        make_snapshot(
            "-A INPUT -p tcp --tcp-flags SYN,ACK,FIN,RST SYN -j ACCEPT\n"
        ),
        packet(tcp_flags=frozenset({"SYN", "ACK"})),
    )

    assert result.status == "DROP"
    assert result.trace[0].reason == "tcp_flags_mask_mismatch"


def test_negated_tcp_flags_rule_matches_packets_that_fail_comparison():
    snapshot = make_snapshot(
        "-A INPUT -p tcp ! --tcp-flags SYN,ACK SYN -j ACCEPT\n"
    )

    syn = evaluate(snapshot, packet(tcp_flags=frozenset({"SYN"})))
    ack = evaluate(snapshot, packet(tcp_flags=frozenset({"ACK"})))

    assert syn.status == "DROP"
    assert ack.status == "ACCEPT"


def test_tcp_flags_mask_requires_packet_flag_metadata():
    result = evaluate(
        make_snapshot(
            "-A INPUT -p tcp --tcp-flags SYN,ACK SYN -j ACCEPT\n"
        ),
        packet(tcp_flags=None),
    )

    assert result.status == "INCONCLUSIVE"
    assert result.trace[0].result == "inconclusive"


def test_all_none_tcp_flag_comparison_matches_packet_without_tcp_flags():
    result = evaluate(
        make_snapshot(
            "-A INPUT -p tcp --tcp-flags ALL NONE -j ACCEPT\n"
        ),
        packet(tcp_flags=frozenset()),
    )

    assert result.status == "ACCEPT"


def test_none_none_tcp_flag_mask_does_not_require_flag_metadata():
    result = evaluate(
        make_snapshot(
            "-A INPUT -p tcp --tcp-flags NONE NONE -j ACCEPT\n"
        ),
        packet(tcp_flags=None),
    )

    assert result.status == "ACCEPT"



def test_non_tcp_packet_with_malformed_tcp_flag_rule_is_inconclusive():
    result = evaluate(
        make_snapshot(
            "-A INPUT -p udp --tcp-flags SYN,ACK SYN -j ACCEPT\n"
        ),
        packet(protocol="udp", source_port=None, destination_port=None,
               tcp_flags=None),
    )

    assert result.status == "INCONCLUSIVE"
    assert result.trace[0].result == "inconclusive"
