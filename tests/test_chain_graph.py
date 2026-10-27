import pytest

from cce.chain_graph import analyze_chain_graph


def make_snapshot():
    return {
        "nftables": [
            {"chain": {
                "family": "ip", "table": "filter", "name": "INPUT",
                "type": "filter", "hook": "input", "prio": 0,
                "policy": "drop",
            }},
            {"chain": {
                "family": "ip", "table": "filter", "name": "user-input",
            }},
            {"chain": {
                "family": "ip", "table": "filter", "name": "leaf",
            }},
            {"chain": {
                "family": "ip", "table": "filter", "name": "orphan",
            }},
            {"rule": {
                "family": "ip", "table": "filter", "chain": "INPUT",
                "expr": [{"jump": {"target": "user-input"}}],
            }},
            {"rule": {
                "family": "ip", "table": "filter", "chain": "user-input",
                "expr": [{"goto": {"target": "leaf"}}],
            }},
            {"rule": {
                "family": "ip", "table": "filter", "chain": "leaf",
                "expr": [{"xt": {"type": "target", "name": "example"}}],
            }},
        ]
    }


def test_follows_explicit_jump_and_goto():
    result = analyze_chain_graph(make_snapshot())
    summary = result["summary"]

    assert summary["chains_total"] == 4
    assert summary["base_chains"] == 1
    assert summary["reachable_chains"] == 3
    assert summary["jump_references"] == 1
    assert summary["goto_references"] == 1
    assert summary["dangling_targets"] == 0


def test_reports_chains_without_explicit_path():
    result = analyze_chain_graph(make_snapshot())

    assert result["summary"]["chains_without_explicit_path"] == 1
    chain = result["chains_without_explicit_path"][0]
    assert chain["chain"] == "orphan"
    assert chain["reachable_via_explicit_jump_goto"] is False


def test_detects_missing_jump_target():
    snapshot = make_snapshot()
    snapshot["nftables"].append({
        "rule": {
            "family": "ip", "table": "filter", "chain": "INPUT",
            "expr": [{"jump": {"target": "missing-chain"}}],
        }
    })

    result = analyze_chain_graph(snapshot)

    assert result["summary"]["dangling_targets"] == 1
    assert result["dangling_targets"][0]["target"] == "missing-chain"
    assert result["dangling_targets"][0]["resolved"] is False


def test_counts_xt_without_interpreting_it():
    result = analyze_chain_graph(make_snapshot())

    assert result["summary"]["rules_with_xt"] == 1
    assert result["summary"]["xt_expressions"] == 1
    assert result["expression_kinds"]["xt"] == 1


def test_rejects_rule_with_missing_source_chain():
    snapshot = {
        "nftables": [{
            "rule": {
                "family": "ip", "table": "filter",
                "chain": "missing-source", "expr": [],
            }
        }]
    }

    with pytest.raises(ValueError, match="chain de origem ausente"):
        analyze_chain_graph(snapshot)


def test_rejects_duplicate_chain_identity():
    snapshot = make_snapshot()
    snapshot["nftables"].append({
        "chain": {
            "family": "ip", "table": "filter", "name": "INPUT",
        }
    })

    with pytest.raises(ValueError, match="Chain duplicada"):
        analyze_chain_graph(snapshot)
