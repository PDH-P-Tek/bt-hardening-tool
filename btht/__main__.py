"""Command line entry point.

`python -m btht map <config.xml>...` prints the interface map — the first thing
worth having from this codebase, and the fastest way to see whether the tool has
understood an estate before anything is generated from it.

Run it with no declared convention and every internal interface comes back
unresolved. That is not a failure: the tool ships no vocabulary, and an estate it
has not been told about is one it will not guess at.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

import yaml

from btht.app.ingest.classify import Tier, classify_aliases, classify_rules
from btht.app.ingest.normalise import Template, alias_table
from btht.app.ingest.pfsense import ParseError, parse_file
from btht.app.ingest.roles import (
    RoleConvention,
    SideRule,
    apply_roles,
    convention_from_mapping,
    derive_interfaces,
    derive_side,
    is_unresolved,
    side_rules_from_mapping,
)
from btht.app.model.profile import load_profile


def load_setup(path: Path | None) -> tuple[RoleConvention, tuple[SideRule, ...]]:
    """Load the operator's declared convention. Nothing declared is a valid state."""
    if path is None:
        return RoleConvention(), ()
    data: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    convention = convention_from_mapping(data.get("interface_roles", {}))
    sides = side_rules_from_mapping(data.get("sides", []))
    return convention, sides


def print_map(config: Path, convention: RoleConvention, sides: tuple[SideRule, ...]) -> int:
    try:
        parsed = parse_file(config)
    except (ParseError, OSError) as exc:
        print(f"{config.name}: {exc}", file=sys.stderr)
        return 1

    interfaces = derive_interfaces(parsed.interfaces, convention)
    side = derive_side(interfaces, sides)

    print(f"\n{config.name}")
    print(f"  config format {parsed.facts.config_version or '?'}", end="")
    print(f" · anti-lockout {'on' if parsed.facts.antilockout_enabled else 'OFF'}", end="")
    print(f" · rule descriptions in the log {'on' if parsed.facts.filter_descriptions else 'off'}")
    print(f"  side: {side or '(not declared)'}")
    print(f"  {'ifname':<8} {'role':<24} {'address':<22} descr")
    for iface in interfaces:
        address = str(iface.v4.ip) if iface.v4 else (str(iface.v6.ip) if iface.v6 else "")
        flag = "  <- anti-lockout binds here" if iface.is_lan else ""
        role = iface.role + (" ?" if is_unresolved(iface.role) else "")
        print(f"  {iface.ifname:<8} {role:<24} {address:<22} {iface.descr}{flag}")

    unresolved = [i for i in interfaces if is_unresolved(i.role)]
    if unresolved:
        print(f"  {len(unresolved)} interface(s) unresolved — declare them at setup")
    return 0


def print_classification(
    config: Path,
    profile_path: Path,
    convention: RoleConvention,
    team: int | None,
) -> int:
    """Show what the profile recognised, and what still needs a human."""
    try:
        parsed = parse_file(config)
        profile = load_profile(profile_path)
    except (ParseError, OSError) as exc:
        print(f"{config.name}: {exc}", file=sys.stderr)
        return 1

    interfaces = derive_interfaces(parsed.interfaces, convention)
    roles = frozenset(i.role for i in interfaces)
    rules = apply_roles(parsed.rules, {i.ifname: i.role for i in interfaces})
    template = Template(number=team, padded=str(team) if team is not None else "")

    rule_matches = classify_rules(rules, alias_table(parsed.aliases), profile, template, roles)
    alias_matches = classify_aliases(parsed.aliases, profile, template)

    print(f"\n{config.name}")
    for alias_match in alias_matches:
        flag = " LOCKOUT-CRITICAL" if alias_match.lockout_critical else ""
        print(f"  {alias_match.tier.value:<11} alias {alias_match.alias.name}{flag}")
    for rule_match in rule_matches:
        label = rule_match.rule.descr or "(no description)"
        print(
            f"  {rule_match.tier.value:<11} {','.join(rule_match.rule.interfaces):<22}"
            f" {rule_match.role.value:<20} {label[:38]}"
        )

    undecided = sum(1 for m in rule_matches if m.needs_a_human) + sum(
        1 for m in alias_matches if m.tier is not Tier.STRICT
    )
    if undecided:
        print(f"  {undecided} item(s) need a decision before anything is generated")
    else:
        print("  everything recognised — nothing to triage")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="btht", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    show = sub.add_parser("map", help="print the interface map for one or more configs")
    show.add_argument("configs", nargs="+", type=Path)
    show.add_argument(
        "--setup",
        type=Path,
        default=None,
        help="YAML declaring this estate's interface_roles and sides",
    )

    check = sub.add_parser("classify", help="match a config against a classification profile")
    check.add_argument("configs", nargs="+", type=Path)
    check.add_argument("--setup", type=Path, default=None)
    check.add_argument("--profile", type=Path, default=Path("seed-profile.yaml"))
    check.add_argument("--team", type=int, default=None, help="team number, for templating")

    args = parser.parse_args(argv)
    convention, sides = load_setup(args.setup)

    if args.command == "classify":
        return max(
            print_classification(config, args.profile, convention, args.team)
            for config in args.configs
        )
    return max(print_map(config, convention, sides) for config in args.configs)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
