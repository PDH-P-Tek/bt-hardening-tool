"""Tier 1 output — the GUI checklist. `SPEC.md` §9.

The team has pfSense GUI access and nothing else. No API, no shell, no Ansible. So
the primary output is not XML: it is a list a person works down, entering rules by
hand, at speed, under time pressure, possibly at three in the morning.

Which makes the wording the feature. **They read one line per rule, not the XML.** A
line that says what a rule is *for* survives being read badly; a line that restates
the fields does not. Every generated rule carries an intent written for that reader,
and this module's job is to lay them out in exactly the order they must be entered.
"""

from __future__ import annotations

from btht.app.generate.order import BLOCK_ALL, PRESERVED, GeneratedRule, Ruleset
from btht.app.model.rules import (
    AliasRef,
    AnyEndpoint,
    Endpoint,
    HostAddress,
    InterfaceNet,
    Negated,
    Network,
    Rule,
    SelfEndpoint,
)


def endpoint_text(endpoint: Endpoint) -> str:
    """An endpoint as it should be typed into the GUI field."""
    match endpoint:
        case AnyEndpoint():
            return "any"
        case SelfEndpoint():
            return "This Firewall (self)"
        case Network(cidr):
            return str(cidr)
        case HostAddress(address):
            return str(address)
        case AliasRef(name):
            return name
        case InterfaceNet(role):
            return f"{role} net"
        case Negated(inner):
            return f"NOT {endpoint_text(inner)}"


def ports_text(rule: Rule) -> str:
    if not rule.destination_ports:
        return "any"
    return ", ".join(
        str(p.low) if p.low == p.high else f"{p.low}-{p.high}" for p in rule.destination_ports
    )


def rule_row(generated: GeneratedRule) -> dict[str, str]:
    """Every GUI field spelled out. Nothing left for the reader to infer."""
    rule = generated.rule
    return {
        "action": rule.action.value.upper(),
        "interface": ", ".join(rule.interfaces) or "—",
        "family": rule.family.value,
        "protocol": rule.protocol or ("icmp" if rule.icmp_types else "any"),
        "source": endpoint_text(rule.source),
        "destination": endpoint_text(rule.destination),
        "ports": ports_text(rule),
        "quick": "yes" if rule.quick else "no",
        "log": "yes" if rule.log else "no",
        "description": rule.descr or generated.description,
        "intent": generated.intent,
    }


def _cell(text: str) -> str:
    """Escape a value for a markdown table cell.

    Every generated description contains `|` as its own separator, which in a table
    silently splits the row into extra columns. The checklist *is* the product here,
    so a mangled table is a mangled product.
    """
    return text.replace("|", "\\|")


def _table(rows: list[dict[str, str]]) -> list[str]:
    if not rows:
        return ["_Nothing in this tab._", ""]
    lines = [
        "| # | Action | Protocol | Source | Destination | Port | Description |",
        "|---|---|---|---|---|---|---|",
    ]
    for index, row in enumerate(rows, start=1):
        lines.append(
            f"| {index} | {row['action']} | {_cell(row['protocol'])} | "
            f"{_cell(row['source'])} | {_cell(row['destination'])} | "
            f"{_cell(row['ports'])} | `{_cell(row['description'])}` |"
        )
    lines.append("")
    return lines


def checklist(ruleset: Ruleset, team: str = "") -> str:
    """The whole thing as markdown, in entry order.

    Entry order is not presentation. A rule entered in the wrong place is a different
    ruleset, so the numbering here is the order to type them in, top to bottom.
    """
    out: list[str] = [
        f"# {ruleset.firewall} — firewall entry checklist",
        "",
        (
            "Enter these in the order shown. Position is part of the rule: the same rule "
            "in a different place is a different ruleset."
        ),
        "",
    ]
    if team:
        out += [f"Team {team}.", ""]

    if ruleset.warnings:
        out += ["## Read before you start", ""]
        out += [f"- {warning}" for warning in ruleset.warnings]
        out += [""]

    out += [
        "## Floating tab",
        "",
        (
            "Firewall → Rules → Floating. Every rule here is **quick**, and the order "
            "matters. The preserved rules at the bottom are the shipped baseline, left "
            "exactly as they were."
        ),
        "",
    ]
    current = ""
    rows: list[dict[str, str]] = []
    for generated in ruleset.floating:
        if generated.block != current:
            if rows:
                out += _table(rows)
                rows = []
            current = generated.block
            out += [f"### {current}", ""]
            if current == PRESERVED:
                out += ["Do not retype these. They are already on the box.", ""]
        rows.append(rule_row(generated))
    out += _table(rows)

    out += ["## WAN tab", ""]
    out += _table([rule_row(g) for g in ruleset.wan])

    for role, rules in ruleset.per_interface:
        out += [f"## {role} tab", ""]
        deny = [g for g in rules if g.block == BLOCK_ALL]
        if deny:
            out += [
                (
                    "The last rule denies everything else. Anything this segment needs "
                    "that is not above it will stop working."
                ),
                "",
            ]
        out += _table([rule_row(g) for g in rules])

    out += [
        "## What each rule is for",
        "",
        "One line per rule, in the same order. This is the column to read at 3am.",
        "",
    ]
    for generated in ruleset.all_rules():
        marker = "preserved" if generated.preserved else generated.block
        out += [f"- **{marker}** — {generated.intent}"]
    out += [""]
    return "\n".join(out)
