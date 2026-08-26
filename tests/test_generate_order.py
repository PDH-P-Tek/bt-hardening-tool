"""Phase 3.1 — the ordering contract.

Position is the product here. A correct rule below a catch-all is not a correct
ruleset, and every enclave in the evidence finished the exercise with thirty careful
rules sitting above an open door. So these tests assert *order and quickness*, not
just presence.
"""

from __future__ import annotations

from ipaddress import IPv4Address, IPv4Interface
from pathlib import Path

import pytest

from btht.app.generate.order import (
    BLOCK_ALL,
    ESSENTIAL_SERVICES,
    FLOATING_ORDER,
    MGMT_ACCESS,
    OUT_OF_BOUNDS,
    PRESERVED,
    SCORING,
    THREAT_BLOCK,
    GenerationRefused,
    generate,
    tracker_for,
)
from btht.app.ingest.isa import load_catalogue
from btht.app.model.estate import Firewall, Host, Interface, Node, Platform
from btht.app.model.policy import (
    EgressPolicy,
    FirewallPolicy,
    Policy,
    PolicyAlias,
    Selector,
    ServiceRule,
)
from btht.app.model.rules import Action, AnyEndpoint, Family, Rule

CATALOGUE = load_catalogue(Path(__file__).resolve().parents[1] / "isa-checks.yaml")

ESSENTIAL = {
    "dns": Selector(alias="DNS_Servers"),
    "ntp": Selector(host="192.0.3.10"),
}


def a_firewall() -> Firewall:
    return Firewall(
        enclave="alpha",
        fqdn="fw1.alpha",
        node=Node(
            name="fw1.alpha",
            platform=Platform.PFSENSE,
            mgmt_address=IPv4Address("10.9.0.1"),
        ),
        interfaces=(
            Interface(ifname="wan", role="wan", v4=IPv4Interface("198.51.100.2/24")),
            Interface(ifname="lan", role="users", v4=IPv4Interface("192.0.2.1/24"), is_lan=True),
            Interface(ifname="opt1", role="servers", v4=IPv4Interface("192.0.3.1/24")),
        ),
        hosts=(
            Host(
                hostname="dc01",
                v4=IPv4Address("192.0.3.5"),
                segment_role="servers",
                service_role="domain_controller",
                isa_checks=("HOST", "LDAP"),
            ),
            Host(
                hostname="npc",
                v4=IPv4Address("192.0.2.249"),
                segment_role="users",
                out_of_bounds=True,
            ),
        ),
    )


def a_policy(**overrides: object) -> Policy:
    entry = FirewallPolicy(
        enclave="alpha",
        services=(
            ServiceRule(
                name="AD / DC",
                segment="servers",
                host="192.0.3.5",
                protocol="tcp",
                ports=(389,),
                source=Selector(segments=("users",)),
            ),
        ),
        egress=EgressPolicy(default="deny_and_log"),
    )
    base: dict[str, object] = {
        "aliases": (PolicyAlias(name="Mgmt_Sources", lockout_critical=True),),
        "firewalls": (entry,),
    }
    base.update(overrides)
    return Policy(**base)  # type: ignore[arg-type]


def build(**kwargs: object):  # type: ignore[no-untyped-def]
    return generate(
        a_firewall(),
        a_policy(),
        CATALOGUE,
        scoring_source=Selector(alias="Scoring_Sources"),
        essential=ESSENTIAL,
        **kwargs,  # type: ignore[arg-type]
    )


# --- the contract ----------------------------------------------------------


def test_the_floating_blocks_come_out_in_the_contracted_order() -> None:
    blocks = [g.block for g in build().floating]
    ordered = [b for b in FLOATING_ORDER if b in blocks]
    positions = [blocks.index(b) for b in ordered]
    assert positions == sorted(positions), f"floating blocks out of order: {blocks}"


def test_the_threat_block_is_first() -> None:
    """Somewhere to put an indicator at 3am without redesigning the ruleset."""
    assert build().floating[0].block == THREAT_BLOCK


def test_every_generated_rule_is_quick() -> None:
    """`SPEC.md` §7.1 — output must never depend on non-quick evaluation.

    The shipped floating passes are non-quick and act as a backstop. Add a quick
    block at the end of an interface tab and it matches first: DNS, NTP and ICMP die
    silently with nothing in the configuration looking wrong.
    """
    for generated in build().all_rules():
        if generated.preserved:
            continue
        assert generated.rule.quick is True, f"{generated.block}: {generated.intent}"


def test_preserved_rules_are_untouched_and_come_last_in_the_floating_tab() -> None:
    preserved = Rule(action=Action.PASS, interfaces=("wan",), descr="baseline", tracker="1")
    ruleset = build(preserved_floating=(preserved,))
    assert ruleset.floating[-1].rule == preserved, "byte-identical, including its tracker"
    assert ruleset.floating[-1].block == PRESERVED


def test_each_internal_segment_ends_in_a_deny() -> None:
    for _role, rules in build().per_interface:
        assert rules[-1].block == BLOCK_ALL
        assert rules[-1].rule.action is Action.BLOCK


def test_the_wan_catch_all_is_not_reproduced() -> None:
    """`EVIDENCE.md` E1 — six of six enclaves finished with this still live."""
    wan = build().wan
    permissive = [
        g
        for g in wan
        if g.rule.action is Action.PASS
        and isinstance(g.rule.source, AnyEndpoint)
        and isinstance(g.rule.destination, AnyEndpoint)
        and not g.preserved
    ]
    assert permissive == []


# --- the refusals ----------------------------------------------------------


def test_it_refuses_to_generate_without_a_management_path() -> None:
    with pytest.raises(GenerationRefused, match="locks itself out"):
        generate(
            a_firewall(),
            a_policy(aliases=()),
            CATALOGUE,
            scoring_source=Selector(alias="Scoring_Sources"),
            essential=ESSENTIAL,
        )


@pytest.mark.parametrize("missing", ["dns", "ntp"])
def test_it_refuses_to_emit_a_deny_without_essential_services_above_it(missing: str) -> None:
    """`SPEC.md` §12.4, and it is not overridable.

    `EVIDENCE.md` E6 is a team who added the deny without them and lost DNS silently.
    """
    essential = {k: v for k, v in ESSENTIAL.items() if k != missing}
    with pytest.raises(GenerationRefused, match=missing.upper()):
        generate(
            a_firewall(),
            a_policy(),
            CATALOGUE,
            scoring_source=Selector(alias="Scoring_Sources"),
            essential=essential,
        )


# --- what is generated -----------------------------------------------------


def test_management_reaches_every_internal_segment() -> None:
    """Uniform regardless of which pfSense interface happens to be `lan`."""
    mgmt = next(g for g in build().floating if g.block == MGMT_ACCESS)
    assert set(mgmt.rule.interfaces) == {"users", "servers"}
    assert [p.low for p in mgmt.rule.destination_ports] == [22, 443]


def test_scored_hosts_get_a_rule_per_scored_port() -> None:
    scoring = [g for g in build().floating if g.block == SCORING]
    assert scoring, "the catalogue and a scoring source were both provided"
    assert any("dc01" in g.intent for g in scoring)
    assert all("DO NOT REMOVE" in g.intent for g in scoring)


def test_an_out_of_bounds_host_keeps_both_directions() -> None:
    """Its outbound path is a scored obligation, not a courtesy — F8."""
    oob = [g for g in build().floating if g.block == OUT_OF_BOUNDS]
    directions = {g.rule.direction.value for g in oob}
    assert directions == {"in", "out"}
    assert all("npc" in g.intent for g in oob)


def test_the_icmp_minimum_set_is_emitted_whole() -> None:
    """Narrowing this to echo breaks IPv6 in ways that fail slowly — F5."""
    icmp = next(
        g for g in build().floating if g.block == ESSENTIAL_SERVICES and g.rule.protocol == "icmp"
    )
    assert {"133", "134", "135", "136", "2", "128", "129"} <= set(icmp.rule.icmp_types)


def test_generated_rules_are_dual_stack() -> None:
    """`EVIDENCE.md` E2 — 74 IPv4-only rules across the estate, all bypassed on IPv6."""
    for generated in build().all_rules():
        if not generated.preserved:
            assert generated.rule.family is Family.INET46


def test_every_generated_rule_names_itself_in_the_log() -> None:
    """With filter descriptions on, this string appears against every match."""
    for generated in build().all_rules():
        if not generated.preserved:
            assert generated.description.startswith("BTHT | ")
            assert generated.intent


# --- determinism -----------------------------------------------------------


def test_generation_is_a_pure_function_of_its_inputs() -> None:
    first, second = build(), build()
    assert [g.description for g in first.all_rules()] == [g.description for g in second.all_rules()]
    assert [g.rule.tracker for g in first.all_rules()] == [
        g.rule.tracker for g in second.all_rules()
    ]


def test_trackers_come_from_the_rule_not_from_the_clock() -> None:
    """A timestamp or a counter would break byte-identical output on the second run."""
    rule = Rule(action=Action.PASS, interfaces=("wan",))
    assert tracker_for(rule) == tracker_for(rule)
    assert tracker_for(rule).isdigit()
