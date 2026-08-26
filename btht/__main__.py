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

from btht.app.ingest.pfsense import ParseError, parse_file
from btht.app.ingest.roles import (
    RoleConvention,
    SideRule,
    convention_from_mapping,
    derive_interfaces,
    derive_side,
    is_unresolved,
    side_rules_from_mapping,
)


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

    args = parser.parse_args(argv)
    convention, sides = load_setup(args.setup)
    return max(print_map(config, convention, sides) for config in args.configs)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
