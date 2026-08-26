"""Interface roles and side labels — `SPEC.md` §4.1, §4.2.

**Nothing here knows any vocabulary.** The operator declares which role tokens their
estate uses and which naming convention its interface descriptions follow; this module
applies what it is given. A convention with nothing in it proposes nothing, which is
the correct behaviour rather than a degenerate one: an undeclared role surfaces in
triage, and triage is where a human decides.

Why this exists at all, rather than reading `lan` and `opt1` directly: in the observed
estate one enclave maps `lan` to servers while the rest map it to workstations
(`BASELINE-ANALYSIS.md` F2). Applying one enclave's ruleset to another on that
assumption would be actively destructive, so the ifname is used for emission and for
nothing else.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from ipaddress import IPv4Network, IPv6Network, ip_network

from btht.app.ingest.pfsense import RawInterface
from btht.app.model.estate import Interface
from btht.app.model.rules import Endpoint, InterfaceNet, Negated, Rule

#: Marks a description the convention could not resolve. Carries the original text so
#: triage can show it. Never resolved by guessing.
OTHER_PREFIX = "other:"

#: pfSense names its outside interface `wan` and binds anti-lockout to `lan`. Platform
#: facts, not estate vocabulary — they describe the firewall, not the exercise.
PF_WAN_IFNAME = "wan"
PF_ANTILOCKOUT_IFNAME = "lan"


@dataclass(frozen=True, slots=True)
class RoleConvention:
    """How this estate names things. Declared at setup, or offered by a profile.

    Empty is a valid state and means "nothing declared yet".
    """

    vocabulary: tuple[str, ...] = ()
    """Role tokens this estate uses."""

    enclave_tokens: tuple[str, ...] = ()
    """Prefixes stripped from a description before matching, longest first so that a
    longer token wins over a shorter one that is also a prefix."""

    def strip_enclave_token(self, descr: str) -> str:
        for token in sorted(self.enclave_tokens, key=len, reverse=True):
            if descr.startswith(token):
                return descr[len(token) :]
        return descr


@dataclass(frozen=True, slots=True)
class SideRule:
    """Maps a WAN network to an operator-declared label — `SPEC.md` §4.2.

    Applied to the **WAN address only**. A firewall can sit on one side while its
    internal segments address into another, so reading an internal range and drawing
    a conclusion gets exactly those cases backwards.
    """

    network: IPv4Network | IPv6Network
    label: str


def propose_role(ifname: str, descr: str, convention: RoleConvention) -> str:
    """Propose a role token for one interface. A proposal, not a decision."""
    if ifname == PF_WAN_IFNAME:
        return PF_WAN_IFNAME
    remainder = convention.strip_enclave_token(descr.strip().lower())
    if remainder and remainder in convention.vocabulary:
        return remainder
    return f"{OTHER_PREFIX}{descr.strip().lower()}"


def is_unresolved(role: str) -> bool:
    """Whether a role still needs a human. Blocks export while true."""
    return role.startswith(OTHER_PREFIX)


def derive_side(interfaces: tuple[Interface, ...], rules: tuple[SideRule, ...]) -> str:
    """Label this firewall from its WAN address. Empty when nothing matches."""
    wan = next((i for i in interfaces if i.ifname == PF_WAN_IFNAME), None)
    if wan is None:
        return ""
    for candidate in (wan.v4, wan.v6):
        if candidate is None:
            continue
        for rule in rules:
            if candidate.ip in rule.network:
                return rule.label
    return ""


def derive_interfaces(
    raw: tuple[RawInterface, ...], convention: RoleConvention
) -> tuple[Interface, ...]:
    """Turn parsed interfaces into domain interfaces carrying proposed roles."""
    return tuple(
        Interface(
            ifname=item.ifname,
            role=propose_role(item.ifname, item.descr, convention),
            descr=item.descr,
            nic=item.nic,
            v4=item.v4,
            v6=item.v6,
            is_lan=item.ifname == PF_ANTILOCKOUT_IFNAME,
        )
        for item in raw
    )


def convention_from_mapping(data: dict[str, object]) -> RoleConvention:
    """Build a convention from loaded data — a profile, or the operator's setup.

    Kept here so there is one place where declared vocabulary enters the system.
    """
    vocabulary = data.get("recognised", ())
    tokens = data.get("enclave_tokens", ())
    return RoleConvention(
        vocabulary=tuple(str(v) for v in vocabulary) if isinstance(vocabulary, list) else (),
        enclave_tokens=tuple(str(t) for t in tokens) if isinstance(tokens, list) else (),
    )


def side_rules_from_mapping(data: list[dict[str, str]]) -> tuple[SideRule, ...]:
    """Build side rules from declared `{network, label}` pairs."""
    return tuple(
        SideRule(network=ip_network(entry["network"], strict=False), label=entry["label"])
        for entry in data
    )


def _remap_endpoint(endpoint: Endpoint, mapping: dict[str, str]) -> Endpoint:
    match endpoint:
        case Negated(inner):
            return Negated(_remap_endpoint(inner, mapping))
        case InterfaceNet(token):
            return InterfaceNet(mapping.get(token, token))
    return endpoint


def apply_roles(rules: tuple[Rule, ...], mapping: dict[str, str]) -> tuple[Rule, ...]:
    """Rewrite every ifname a rule mentions into the estate's role token.

    **This must happen before anything is fingerprinted.** Rules come out of the parser
    carrying `lan` and `opt1`, and hashing those is the exact mistake the role layer
    exists to prevent: on the inverted enclave `lan` is the server segment, so an
    identical fingerprint would mean two opposite things on two firewalls.

    An unmapped token is carried through unchanged rather than dropped, so it surfaces
    downstream instead of vanishing.
    """
    return tuple(
        replace(
            rule,
            interfaces=tuple(mapping.get(name, name) for name in rule.interfaces),
            source=_remap_endpoint(rule.source, mapping),
            destination=_remap_endpoint(rule.destination, mapping),
        )
        for rule in rules
    )
