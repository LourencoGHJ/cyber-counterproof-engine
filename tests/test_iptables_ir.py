import json

import pytest

from cce.iptables_ir import (
    build_iptables_ir_document,
    parse_iptables_rules_ir,
)


def snapshot(rule="", family="ipv4", extra_chains=""):
    if family == "ipv6":
        input_policy = "DROP"
    else:
        input_policy = "DROP"

    return (
        "*filter\n"
        f":INPUT {input_policy} [0:0]\n"
        ":OUTPUT ACCEPT [0:0]\n"
        ":FORWARD DROP [0:0]\n"
        f"{extra_chains}"
        f"{rule}\n"
        "COMMIT\n"
    )


def first_rule(rule, family="ipv4", extra_chains=""):
    rules = parse_iptables_rules_ir(
        snapshot(rule, family, extra_chains),
        family,
    )
    assert len(rules) == 1
    return rules[0]


def test_normalizes_tcp_rule_and_port_fields():
    rule = first_rule(
        "-A INPUT -p tcp -m tcp "
        "-s 192.0.2.17/24 -d 198.51.100.4 "
        "-i eth0+ -o eth1 "
        "--sport 50000 --dport 22 -j ACCEPT"
    )

    assert rule.protocol == "tcp"
    assert rule.source == "192.0.2.0/24"
    assert rule.destination == "198.51.100.4/32"
    assert rule.input_interface == "eth0+"
    assert rule.output_interface == "eth1"
    assert rule.source_ports[0].first == 50000
    assert rule.destination_ports[0].first == 22
    assert rule.target == "ACCEPT"
    assert rule.target_operation == "jump"
    assert rule.interpretation == "complete"


def test_normalizes_ipv6_networks():
    rule = first_rule(
        "-A INPUT -p tcp -s 2001:db8::1234/64 "
        "-d 2001:db8:1::1 -j ACCEPT",
        family="ipv6",
    )

    assert rule.source == "2001:db8::/64"
    assert rule.destination == "2001:db8:1::1/128"
    assert rule.family == "ipv6"
    assert rule.interpretation == "complete"


def test_records_negated_source_and_destination_port():
    rule = first_rule(
        "-A INPUT -p tcp -m tcp "
        "! -s 192.0.2.0/24 --dport ! 22 -j DROP"
    )

    assert "source" in rule.negated_conditions
    assert "destination_ports" in rule.negated_conditions
    assert rule.source == "192.0.2.0/24"
    assert rule.destination_ports[0].first == 22
    assert rule.target == "DROP"


def test_parses_multiport_ranges_without_collapsing_them():
    rule = first_rule(
        "-A INPUT -p tcp -m multiport "
        "--dports 22,80:90,443 -j ACCEPT"
    )

    assert [(p.first, p.last) for p in rule.destination_ports] == [
        (22, 22),
        (80, 90),
        (443, 443),
    ]
    assert rule.interpretation == "complete"


def test_multiport_either_direction_is_kept_distinct():
    rule = first_rule(
        "-A INPUT -p udp -m multiport --ports 53,123 -j ACCEPT"
    )

    assert rule.source_ports == ()
    assert rule.destination_ports == ()
    assert [(p.first, p.last) for p in rule.either_ports] == [
        (53, 53),
        (123, 123),
    ]


def test_parses_connection_states():
    rule = first_rule(
        "-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED "
        "-j ACCEPT"
    )

    assert rule.connection_states == ("ESTABLISHED", "RELATED")
    assert rule.interpretation == "complete"


def test_tcp_module_can_supply_implicit_protocol():
    rule = first_rule(
        "-A INPUT -m tcp --dport 22 -j ACCEPT"
    )

    assert rule.protocol == "tcp"
    assert rule.interpretation == "complete"


def test_unknown_module_is_explicitly_partial():
    rule = first_rule(
        "-A INPUT -p tcp -m recent --name ssh "
        "--rcheck --seconds 60 --hitcount 3 -j DROP"
    )

    assert "recent" in rule.unsupported_modules
    assert rule.interpretation == "partial"


def test_unsupported_limit_option_is_not_treated_as_neutral():
    rule = first_rule(
        "-A INPUT -p tcp -m tcp --dport 22 "
        "--limit 5/second -j ACCEPT"
    )

    assert "--limit" in rule.unsupported_options
    assert rule.interpretation == "partial"


def test_symbolic_port_is_unresolved_not_guessed():
    rule = first_rule(
        "-A INPUT -p tcp -m tcp --dport ssh -j ACCEPT"
    )

    assert rule.destination_ports == ()
    assert "unresolved_port_specification" in rule.warnings
    assert rule.interpretation == "partial"


def test_network_from_other_address_family_is_partial():
    rule = first_rule(
        "-A INPUT -p tcp -s 2001:db8::/32 -j ACCEPT",
        family="ipv4",
    )

    assert rule.source is None
    assert "unparsed_network:source" in rule.warnings
    assert rule.interpretation == "partial"


def test_unknown_target_is_explicitly_partial():
    rule = first_rule(
        "-A INPUT -p tcp -j LOG"
    )

    assert rule.target == "LOG"
    assert "LOG" in rule.unsupported_targets
    assert rule.interpretation == "partial"


def test_user_chain_target_is_supported_and_preserved():
    rule = first_rule(
        "-A INPUT -g custom-chain",
        extra_chains=":custom-chain - [0:0]\n",
    )

    assert rule.target == "custom-chain"
    assert rule.target_operation == "goto"
    assert rule.unsupported_targets == ()
    assert rule.interpretation == "complete"


def test_comment_metadata_is_not_copied_into_ir():
    rule = first_rule(
        '-A INPUT -m comment --comment "private note" '
        "-p tcp -j ACCEPT"
    )

    rendered = json.dumps(rule.to_dict(), ensure_ascii=False)
    assert "private note" not in rendered
    assert rule.interpretation == "complete"


def test_conflicting_protocol_and_transport_module_is_partial():
    rule = first_rule(
        "-A INPUT -p udp -m tcp --dport 22 -j ACCEPT"
    )

    assert rule.protocol == "udp"
    assert "protocol_module_mismatch" in rule.warnings
    assert rule.interpretation == "partial"


def test_rule_without_target_is_partial():
    rule = first_rule("-A INPUT -p tcp")

    assert rule.target is None
    assert "missing_target" in rule.warnings
    assert rule.interpretation == "partial"


def test_document_reports_complete_and_partial_counts():
    text = snapshot(
        "-A INPUT -p tcp -j ACCEPT\n"
        "-A INPUT -p tcp -m recent --name ssh -j DROP"
    )

    document = build_iptables_ir_document(text, "ipv4")

    assert document["schema_version"] == "1.1"
    assert document["summary"] == {
        "rules_total": 2,
        "rules_fully_interpreted": 1,
        "rules_partially_interpreted": 1,
    }


def test_rejects_structurally_malformed_snapshot():
    text = snapshot("not-a-valid-rule")

    with pytest.raises(ValueError, match="estruturalmente malformada"):
        parse_iptables_rules_ir(text, "ipv4")


def test_single_port_selector_does_not_accept_multiport_csv_syntax():
    rule = first_rule(
        "-A INPUT -p tcp -m tcp --dport 22,80 -j ACCEPT"
    )

    assert rule.destination_ports == ()
    assert "--dport" in rule.unsupported_options
    assert rule.interpretation == "partial"


def test_port_selector_without_transport_protocol_is_partial():
    rule = first_rule(
        "-A INPUT -p icmp -m icmp --dport 22 -j ACCEPT"
    )

    assert rule.destination_ports[0].first == 22
    assert "port_selector_without_transport_protocol" in rule.warnings
    assert rule.interpretation == "partial"


def test_multiport_option_without_multiport_module_is_partial():
    rule = first_rule(
        "-A INPUT -p tcp --dports 22,443 -j ACCEPT"
    )

    assert "multiport_selector_without_module" in rule.warnings
    assert rule.interpretation == "partial"


def test_tcp_syn_flag_without_tcp_protocol_is_partial():
    rule = first_rule(
        "-A INPUT -p udp --syn -j ACCEPT"
    )

    assert rule.tcp_syn_only is True
    assert "tcp_syn_without_tcp_protocol" in rule.warnings
    assert rule.interpretation == "partial"


def test_ctstate_without_conntrack_module_is_partial():
    rule = first_rule(
        "-A INPUT --ctstate NEW -j ACCEPT"
    )

    assert rule.connection_states == ("NEW",)
    assert "ctstate_without_conntrack_module" in rule.warnings
    assert rule.interpretation == "partial"


def test_state_without_state_module_is_partial():
    rule = first_rule(
        "-A INPUT --state ESTABLISHED -j ACCEPT"
    )

    assert "state_without_state_module" in rule.warnings
    assert rule.interpretation == "partial"


def test_inline_protocol_and_target_values_are_supported():
    rule = first_rule(
        "-A INPUT --protocol=tcp --jump=ACCEPT"
    )

    assert rule.protocol == "tcp"
    assert rule.target == "ACCEPT"
    assert rule.target_operation == "jump"
    assert rule.interpretation == "complete"


def test_json_document_does_not_include_original_snapshot_line():
    rule = first_rule(
        '-A INPUT -m comment --comment "do-not-disclose" '
        "-p tcp -j ACCEPT"
    )

    rendered = json.dumps(rule.to_dict(), ensure_ascii=False)

    assert "do-not-disclose" not in rendered
    assert "-A INPUT" not in rendered



def test_normalizes_tcp_flags_mask_and_comparison():
    rule = first_rule(
        "-A INPUT -p tcp --tcp-flags SYN,ACK,FIN,RST SYN -j ACCEPT"
    )

    assert rule.tcp_flags_mask == ("FIN", "SYN", "RST", "ACK")
    assert rule.tcp_flags_comp == ("SYN",)
    assert "--tcp-flags" not in rule.unsupported_options
    assert rule.interpretation == "complete"


def test_expands_all_and_none_tcp_flag_aliases():
    rule = first_rule(
        "-A INPUT -p tcp --tcp-flags ALL NONE -j DROP"
    )

    assert rule.tcp_flags_mask == (
        "FIN", "SYN", "RST", "PSH", "ACK", "URG"
    )
    assert rule.tcp_flags_comp == ()
    assert rule.interpretation == "complete"


def test_supports_none_as_tcp_flag_mask():
    rule = first_rule(
        "-A INPUT -p tcp --tcp-flags NONE NONE -j ACCEPT"
    )

    assert rule.tcp_flags_mask == ()
    assert rule.tcp_flags_comp == ()
    assert rule.interpretation == "complete"


def test_tcp_flag_comparison_must_be_subset_of_mask():
    rule = first_rule(
        "-A INPUT -p tcp --tcp-flags SYN ACK -j ACCEPT"
    )

    assert rule.tcp_flags_mask is None
    assert "--tcp-flags" in rule.unsupported_options
    assert "invalid_tcp_flags_specification" in rule.warnings
    assert rule.interpretation == "partial"


def test_unknown_tcp_flag_name_is_not_interpreted():
    rule = first_rule(
        "-A INPUT -p tcp --tcp-flags SYN,FOO SYN -j ACCEPT"
    )

    assert "--tcp-flags" in rule.unsupported_options
    assert "invalid_tcp_flags_specification" in rule.warnings
    assert rule.interpretation == "partial"


def test_tcp_flags_selector_without_tcp_protocol_is_partial():
    rule = first_rule(
        "-A INPUT -p udp --tcp-flags SYN,ACK SYN -j ACCEPT"
    )

    assert rule.tcp_flags_mask == ("SYN", "ACK")
    assert rule.tcp_flags_comp == ("SYN",)
    assert "tcp_flags_without_tcp_protocol" in rule.warnings
    assert rule.interpretation == "partial"


def test_negated_tcp_flags_selector_is_preserved():
    rule = first_rule(
        "-A INPUT -p tcp ! --tcp-flags SYN,ACK SYN -j DROP"
    )

    assert rule.tcp_flags_mask == ("SYN", "ACK")
    assert rule.tcp_flags_comp == ("SYN",)
    assert "tcp_flags" in rule.negated_conditions
    assert rule.interpretation == "complete"


def test_ir_json_serializes_tcp_flag_fields_as_lists():
    rule = first_rule(
        "-A INPUT -p tcp --tcp-flags SYN,ACK SYN -j ACCEPT"
    )

    document = rule.to_dict()
    assert document["tcp_flags_mask"] == ["SYN", "ACK"]
    assert document["tcp_flags_comp"] == ["SYN"]
