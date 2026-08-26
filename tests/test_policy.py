"""Phase 2.3 — the policy schema, loaded and checked against the declared estate.

Validation here is not tidiness. Every problem it reports is a case where generating
anyway produces a ruleset that *looks* right and is not: a rule for a segment that
does not exist protects nothing, an alias that resolves to nothing matches nothing,
and neither is visible in the output. Refusing beats generating something plausible.
"""

from __future__ import annotations

from ipaddress import IPv4Address, IPv4Interface
from pathlib import Path

import pytest

from btht.app.model.estate import Estate, Firewall, Interface, Node, Platform
from btht.app.model.policy import (
    EstateFileError,
    empty_aliases,
    load_policy,
    validate_policy,
)

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "enclave-policy.example.yaml"


def a_firewall(enclave: str, roles: tuple[str, ...]) -> Firewall:
    return Firewall(
        enclave=enclave,
        fqdn=f"fw1.{enclave}",
        node=Node(
            name=f"fw1.{enclave}",
            platform=Platform.PFSENSE,
            mgmt_address=IPv4Address("10.0.0.1"),
            enclave=enclave,
        ),
        interfaces=tuple(
            Interface(ifname=f"opt{n}", role=role, v4=IPv4Interface(f"192.0.{n}.1/24"))
            for n, role in enumerate(roles)
        ),
    )


def an_estate() -> Estate:
    """Named to match the shipped example so the example can be validated against it."""
    return Estate(
        team=14,
        team_padded="14",
        role_vocabulary=("wan", "ws", "svrs", "dmz", "uav"),
        firewalls=(
            a_firewall("do", ("wan", "ws", "svrs", "dmz")),
            a_firewall("ds", ("wan", "ws", "svrs", "uav", "dmz")),
            a_firewall("dsoc", ("wan", "svrs", "ws")),
        ),
    )


# --- the shipped example ---------------------------------------------------


def test_the_worked_example_loads() -> None:
    """It is documentation the operator reads and edits, so it has to be loadable."""
    policy = load_policy(EXAMPLE)
    assert {a.name for a in policy.aliases} >= {"Mgmt_Sources", "DNS_Servers"}
    assert {f.enclave for f in policy.firewalls} == {"do", "ds", "dsoc"}
    assert policy.options.dual_stack == "require"
    assert 2 in policy.options.icmp6_minimum, "Packet Too Big, or PMTUD breaks silently"


def test_the_worked_example_validates_against_a_matching_estate() -> None:
    assert validate_policy(load_policy(EXAMPLE), an_estate()) == []


def test_nested_and_segment_alias_entries_are_understood() -> None:
    """`Mgmt_Sources` nests the baseline VPN alias and this enclave's own segment."""
    alias = next(a for a in load_policy(EXAMPLE).aliases if a.name == "Mgmt_Sources")
    assert alias.nested_aliases == ("Remote_Access",)
    assert alias.segments == ("ws",)
    assert alias.lockout_critical is True


def test_aliases_awaiting_an_answer_are_surfaced() -> None:
    """They are legitimate, and each one produces a rule that matches nothing.

    Better said now than discovered when the scoring probe fails.
    """
    assert set(empty_aliases(load_policy(EXAMPLE))) == {
        "Scoring_Sources",
        "YT_Usersim_Sources",
    }


def test_dependencies_carry_both_ends() -> None:
    """Declared once; the generator emits egress on one firewall and ingress on the other."""
    fleet = next(d for d in load_policy(EXAMPLE).dependencies if "Fleet" in d.name)
    assert set(fleet.from_enclaves) == {"do", "ds"}
    assert fleet.to_enclave == "dsoc"
    assert fleet.ports == (8220,)


# --- what validation catches ----------------------------------------------


def test_a_service_on_a_segment_the_estate_does_not_have_is_refused() -> None:
    """The rule would generate cleanly and protect nothing."""
    policy = load_policy(EXAMPLE)
    estate = an_estate()
    thinner = Estate(
        team=estate.team,
        team_padded=estate.team_padded,
        role_vocabulary=estate.role_vocabulary,
        firewalls=(a_firewall("do", ("wan", "ws")), *estate.firewalls[1:]),
    )
    problems = validate_policy(policy, thinner)
    assert any("dmz" in p and "not a segment of do" in p for p in problems)


def test_a_policy_for_an_enclave_that_does_not_exist_is_refused() -> None:
    estate = Estate(team=14, team_padded="14", firewalls=(a_firewall("do", ("wan", "ws")),))
    problems = validate_policy(load_policy(EXAMPLE), estate)
    assert any("no such enclave" in p for p in problems)


def test_an_undeclared_alias_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text(
        "version: 1\nfirewalls:\n"
        "  - enclave: do\n    services:\n"
        "      - {name: X, segment: ws, protocol: tcp, ports: [443], from: {alias: Nope}}\n",
        encoding="utf-8",
    )
    problems = validate_policy(load_policy(path), an_estate())
    assert any("'Nope' is not declared" in p for p in problems)


def test_a_service_with_no_source_is_refused(tmp_path: Path) -> None:
    """`any` is a decision. It has to be said out loud, not arrived at by omission."""
    path = tmp_path / "policy.yaml"
    path.write_text(
        "version: 1\nfirewalls:\n"
        "  - enclave: do\n    services:\n"
        "      - {name: X, segment: ws, protocol: tcp, ports: [443]}\n",
        encoding="utf-8",
    )
    problems = validate_policy(load_policy(path), an_estate())
    assert any("has to be said out loud" in p for p in problems)


def test_a_service_with_no_ports_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text(
        "version: 1\nfirewalls:\n"
        "  - enclave: do\n    services:\n"
        "      - {name: X, segment: ws, protocol: tcp, from: any}\n",
        encoding="utf-8",
    )
    problems = validate_policy(load_policy(path), an_estate())
    assert any("needs saying deliberately" in p for p in problems)


def test_an_unnamed_service_is_refused(tmp_path: Path) -> None:
    """Every rule shows the operator one line. A rule with no name has nothing to show."""
    path = tmp_path / "policy.yaml"
    path.write_text(
        "version: 1\nfirewalls:\n"
        "  - enclave: do\n    services:\n"
        "      - {segment: ws, protocol: tcp, ports: [443], from: any}\n",
        encoding="utf-8",
    )
    problems = validate_policy(load_policy(path), an_estate())
    assert any("no name to show the operator" in p for p in problems)


def test_an_impossible_port_is_refused_at_load(tmp_path: Path) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text(
        "version: 1\nfirewalls:\n"
        "  - enclave: do\n    services:\n"
        "      - {name: X, segment: ws, ports: [70000], from: any}\n",
        encoding="utf-8",
    )
    with pytest.raises(EstateFileError, match="70000"):
        load_policy(path)


def test_an_unknown_egress_default_is_refused(tmp_path: Path) -> None:
    """A typo here decides whether the enclave denies egress or allows it."""
    path = tmp_path / "policy.yaml"
    path.write_text(
        "version: 1\nfirewalls:\n  - enclave: do\n    egress: {default: deny_and_logg}\n",
        encoding="utf-8",
    )
    problems = validate_policy(load_policy(path), an_estate())
    assert any("deny_and_logg" in p for p in problems)


def test_a_dependency_to_a_missing_enclave_is_refused(tmp_path: Path) -> None:
    """Half a path is worse than none: one side allows, the other silently drops."""
    path = tmp_path / "policy.yaml"
    path.write_text(
        "version: 1\ndependencies:\n"
        "  - name: X\n    from: {enclaves: [do]}\n    to: {enclave: nowhere}\n"
        "    protocol: tcp\n    ports: [443]\n",
        encoding="utf-8",
    )
    problems = validate_policy(load_policy(path), an_estate())
    assert any("nowhere" in p for p in problems)
