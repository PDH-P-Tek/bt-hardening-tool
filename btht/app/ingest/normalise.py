"""Canonicalisation — `SPEC.md` §6.1. Applied before anything is fingerprinted.

This is the module that decides whether the tool is usable. A brittle canonical form
means near-identical rules hash differently, the triage modal fires on everything, and
people click through it blind — at which point the classification means nothing and the
tool is worse than not having one.

So the rule is: **two rules that a firewall would treat identically must canonicalise
identically**, whatever the configuration happens to spell them as. `53` and `53-53`,
`any` and `0.0.0.0/0`, an address list in either order.

Nothing here hashes. `fingerprint.py` does that, over what this produces.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from ipaddress import IPv4Network, IPv6Network, ip_address, ip_network
from typing import Any

from btht.app.model.rules import (
    Alias,
    AliasRef,
    AnyEndpoint,
    Endpoint,
    Family,
    HostAddress,
    InterfaceNet,
    Negated,
    Network,
    PortSpec,
    Rule,
    SelfEndpoint,
)

#: Whole-token boundaries: an address octet, an IPv6 group, or a DNS label. Prevents
#: team 4 from matching inside 143 or fd81.
_TOKEN = re.compile(r"(?<![0-9A-Za-z]) *([0-9A-Za-z]+) *(?![0-9A-Za-z])")

#: A rule bound to every interface on its firewall. Canonicalising to this is what
#: lets one profile entry describe a protected rule that appears on enclaves with
#: different numbers of interfaces — see `canonical_rule`.
ALL_INTERFACES = "*"

_ANY_V4 = IPv4Network("0.0.0.0/0")
_ANY_V6 = IPv6Network("::/0")


@dataclass(frozen=True, slots=True)
class Template:
    """Replaces this estate's team number with a placeholder before hashing.

    A shipped profile describes the baseline for *any* team, so its entries read
    `25.{X}.0.1` while a real configuration reads `25.14.0.1`. Templating both sides
    lets one profile match every team.

    Whole tokens only. A host address that happens to equal the team number templates
    too, which is harmless: both sides of every comparison go through the same
    substitution, so it cannot make a match wrong — only, in principle, make two
    genuinely different rules collide, which needs the team number to appear as a
    whole octet in a position that distinguishes them.
    """

    number: int | None = None
    padded: str = ""

    def apply(self, text: str) -> str:
        if self.number is None:
            return text
        plain = str(self.number)
        padded = self.padded or plain

        def swap(match: re.Match[str]) -> str:
            token = match.group(1)
            if token == padded and padded != plain:
                return match.group(0).replace(token, "{XX}")
            if token in (plain, padded):
                return match.group(0).replace(token, "{X}")
            return match.group(0)

        return _TOKEN.sub(swap, text)


def canonical_address(text: str) -> str:
    """Lowercase, RFC 5952 for IPv6, and a bare host address stays bare.

    `ipaddress` already emits the RFC 5952 form, so this is mostly about routing the
    text through it rather than trusting how the configuration spelled it.
    """
    raw = text.strip()
    if "{" in raw:
        # Already templated — a profile entry such as `25.{X}.0.1`. Lowercasing it
        # would turn the placeholder into `{x}` and it would match nothing.
        return raw
    try:
        return str(ip_address(raw))
    except ValueError:
        pass
    try:
        return str(ip_network(raw, strict=False))
    except ValueError:
        return raw.lower()


def canonical_entries(entries: tuple[str, ...], template: Template) -> list[str]:
    """Sorted and deduplicated — `SPEC.md` §6.1. Order in the file means nothing."""
    return sorted({template.apply(canonical_address(e)) for e in entries if e.strip()})


def canonical_ports(ports: tuple[PortSpec, ...]) -> list[list[int]]:
    """`53` and `53-53` are the same port. Order and repetition are not information."""
    return [list(pair) for pair in sorted({(p.low, p.high) for p in ports})]


def canonical_families(family: Family) -> list[str]:
    """`inet46` is the pair — `SPEC.md` §6.1.

    Expanding it here is what lets an `inet46` rule compare equal to the `{inet, inet6}`
    pair of otherwise-identical rules. Collapsing an actual *pair* of rules into one is
    a set-level operation and belongs where rule sets are compared, not here.
    """
    if family is Family.INET46:
        return ["inet", "inet6"]
    return [family.value]


def _is_any_network(value: IPv4Network | IPv6Network) -> bool:
    return value in (_ANY_V4, _ANY_V6)


def canonical_endpoint(
    endpoint: Endpoint,
    aliases: dict[str, Alias],
    template: Template,
    *,
    structural: bool = False,
) -> dict[str, Any]:
    """One endpoint in canonical form.

    `structural=True` reduces it to its kind and drops alias contents, which is the
    second tier of `SPEC.md` §6.2: same shape, different membership.
    """
    match endpoint:
        case Negated(inner):
            return {
                "kind": "not",
                "of": canonical_endpoint(inner, aliases, template, structural=structural),
            }
        case AnyEndpoint():
            return {"kind": "any"}
        case SelfEndpoint():
            return {"kind": "self"}
        case Network(cidr):
            if _is_any_network(cidr):
                return {"kind": "any"}
            if structural:
                return {"kind": "network"}
            return {"kind": "network", "cidr": template.apply(str(cidr))}
        case HostAddress(address):
            if structural:
                return {"kind": "host"}
            return {"kind": "host", "address": template.apply(str(address))}
        case InterfaceNet(role):
            return {"kind": "interface", "role": role}
        case AliasRef(name):
            if structural:
                # Alias contents ignored: the point of the tier is to match a rule
                # whose alias membership has been edited.
                return {"kind": "alias"}
            alias = aliases.get(name)
            return {
                "kind": "alias",
                "name": name,
                "entries": canonical_entries(alias.entries, template) if alias else [],
            }
    raise TypeError(f"unhandled endpoint: {endpoint!r}")


def canonical_rule(
    rule: Rule,
    aliases: dict[str, Alias],
    template: Template,
    *,
    structural: bool = False,
    all_roles: frozenset[str] | None = None,
) -> dict[str, Any]:
    """Exactly the fields `SPEC.md` §6.2 names, and no others.

    `all_roles` is this firewall's complete set of interface roles. A rule naming every
    one of them collapses to `["*"]`. Without that, the *same* shipped protected rule
    fingerprints differently on every enclave with a different interface count, and a
    profile written against one estate matches nothing on the next. This extends
    `SPEC.md` §6.1; it does not contradict it.

    `descr`, `tracker`, `detail`, `log` and `id` are absent by construction rather than
    by being stripped later: descriptions are display, never identity — three rules
    labelled BLOCK in the observed estate had action `pass` (`EVIDENCE.md` E3).
    """
    return {
        "type": rule.action.value,
        "floating": rule.floating,
        "quick": rule.quick,
        "direction": rule.direction.value,
        "interfaces": (
            [ALL_INTERFACES]
            if set(rule.interfaces) == {"any"} or (all_roles and set(rule.interfaces) == all_roles)
            else sorted(set(rule.interfaces))
        ),
        "ipprotocol": canonical_families(rule.family),
        "protocol": rule.protocol.lower() if rule.protocol else None,
        "icmptype": sorted(set(rule.icmp_types)),
        "source": canonical_endpoint(rule.source, aliases, template, structural=structural),
        "destination": canonical_endpoint(
            rule.destination, aliases, template, structural=structural
        ),
        "srcport": canonical_ports(rule.source_ports),
        "dstport": canonical_ports(rule.destination_ports),
        "statetype": rule.state_type.lower(),
    }


def alias_table(aliases: tuple[Alias, ...]) -> dict[str, Alias]:
    return {alias.name: alias for alias in aliases}
