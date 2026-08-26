"""Phase 3.3 — Tier 1 output.

The team has GUI access and nothing else, so this list *is* the product for now: a
person types from it, at speed, under pressure. Two things are therefore asserted
harder than the markup — the order is the entry order, and every rule carries a line
saying what it is for rather than restating its fields.
"""

from __future__ import annotations

from pathlib import Path

from conftest import ESSENTIAL, a_firewall, a_policy

from btht.app.generate.emit import checklist, endpoint_text, rule_row
from btht.app.generate.order import BLOCK_ALL, PRESERVED, Ruleset, generate
from btht.app.ingest.isa import load_catalogue
from btht.app.model.policy import Selector
from btht.app.model.rules import (
    AliasRef,
    AnyEndpoint,
    HostAddress,
    InterfaceNet,
    Negated,
    Network,
    SelfEndpoint,
)

CATALOGUE = load_catalogue(Path(__file__).resolve().parents[1] / "isa-checks.yaml")


def a_ruleset() -> Ruleset:
    return generate(
        a_firewall(),
        a_policy(),
        CATALOGUE,
        scoring_source=Selector(alias="Scoring_Sources"),
        essential=ESSENTIAL,
    )


def test_endpoints_are_written_as_the_gui_field_is_typed() -> None:
    from ipaddress import ip_address, ip_network

    assert endpoint_text(AnyEndpoint()) == "any"
    assert endpoint_text(SelfEndpoint()) == "This Firewall (self)"
    assert endpoint_text(AliasRef("Mgmt_Sources")) == "Mgmt_Sources"
    assert endpoint_text(InterfaceNet("servers")) == "servers net"
    assert endpoint_text(HostAddress(ip_address("192.0.2.5"))) == "192.0.2.5"
    assert endpoint_text(Network(ip_network("192.0.2.0/24"))) == "192.0.2.0/24"
    assert endpoint_text(Negated(AnyEndpoint())) == "NOT any"


def test_every_gui_field_is_spelled_out() -> None:
    """Nothing left for a tired reader to infer."""
    row = rule_row(a_ruleset().floating[0])
    assert set(row) >= {
        "action",
        "interface",
        "family",
        "protocol",
        "source",
        "destination",
        "ports",
        "quick",
        "log",
        "description",
        "intent",
    }
    assert all(value != "" for value in row.values())


def test_the_checklist_is_in_entry_order() -> None:
    """A rule entered in the wrong place is a different ruleset."""
    text = checklist(a_ruleset())
    floating = text.index("## Floating tab")
    wan = text.index("## WAN tab")
    assert floating < wan
    assert text.index("### THREAT BLOCK") < text.index("### MGMT ACCESS")
    assert text.index("### MGMT ACCESS") < text.index("### ESSENTIAL SERVICES")


def test_it_says_position_is_part_of_the_rule() -> None:
    assert "the same rule in a different place is a different ruleset" in checklist(
        a_ruleset()
    ).replace("\n", " ")


def test_every_rule_has_a_line_saying_what_it_is_for() -> None:
    """`CLAUDE.md` — they read one line per rule, not the XML."""
    ruleset = a_ruleset()
    text = checklist(ruleset)
    assert "## What each rule is for" in text
    for generated in ruleset.all_rules():
        assert generated.intent in text


def test_the_deny_is_called_out_where_it_bites() -> None:
    text = checklist(a_ruleset())
    assert "Anything this segment needs that is not above it will stop working" in text
    assert BLOCK_ALL in [g.block for g in a_ruleset().per_interface[0][1]]


def test_preserved_rules_are_marked_do_not_retype() -> None:
    """They are already on the box. Retyping them is how a baseline gets mangled."""
    from btht.app.model.rules import Action, Rule

    ruleset = generate(
        a_firewall(),
        a_policy(),
        CATALOGUE,
        preserved_floating=(Rule(action=Action.PASS, interfaces=("wan",), descr="baseline"),),
        scoring_source=Selector(alias="Scoring_Sources"),
        essential=ESSENTIAL,
    )
    text = checklist(ruleset)
    assert f"### {PRESERVED}" in text
    assert "Do not retype these" in text


def test_warnings_come_first_because_they_change_what_you_type() -> None:
    ruleset = a_ruleset()
    text = checklist(ruleset)
    assert ruleset.warnings, "this fixture has a scored host with no IPv6"
    assert text.index("## Read before you start") < text.index("## Floating tab")


def test_the_checklist_is_deterministic() -> None:
    assert checklist(a_ruleset()) == checklist(a_ruleset())
