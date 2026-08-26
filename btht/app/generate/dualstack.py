"""Dual-stack emission — `SPEC.md` §7.2.

**Never emit a v4-only rule silently.** Across the observed estate there were 74
IPv4-only rules stacked above `inet46` catch-alls, so every one of them was bypassed
on IPv6 — and IPv6 availability is scored. The best-hardened enclave had 31 such
rules and none of its work applied to half the traffic (`EVIDENCE.md` E2).

The failure was not carelessness. A rule written against an IPv4 address *is*
IPv4-only, and nothing in the interface says so. This module's whole job is to notice
that and say it out loud, per rule, naming what forced it.
"""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address, ip_network

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
    Rule,
    SelfEndpoint,
)


@dataclass(frozen=True, slots=True)
class FamilyVerdict:
    family: Family
    reason: str = ""
    """Empty when the rule is genuinely dual-stack. Otherwise names what forced it,
    in words the operator can act on."""

    @property
    def is_asymmetric(self) -> bool:
        return self.family is not Family.INET46


def _alias_families(alias: Alias) -> set[str]:
    families: set[str] = set()
    for entry in alias.entries:
        text = entry.strip()
        if not text or "{" in text:
            continue
        try:
            version = (
                ip_network(text, strict=False).version if "/" in text else ip_address(text).version
            )
        except ValueError:
            continue
        families.add("inet" if version == 4 else "inet6")
    return families


def endpoint_family(endpoint: Endpoint, aliases: dict[str, Alias]) -> tuple[Family, str]:
    """What family an endpoint can actually match, and why."""
    match endpoint:
        case Negated(inner):
            return endpoint_family(inner, aliases)
        case AnyEndpoint() | SelfEndpoint() | InterfaceNet():
            return Family.INET46, ""
        case HostAddress(address):
            if address.version == 4:
                return Family.INET, f"the address {address} is IPv4"
            return Family.INET6, f"the address {address} is IPv6"
        case Network(cidr):
            if cidr.version == 4:
                return Family.INET, f"the network {cidr} is IPv4"
            return Family.INET6, f"the network {cidr} is IPv6"
        case AliasRef(name):
            alias = aliases.get(name)
            if alias is None:
                return Family.INET46, ""
            families = _alias_families(alias)
            if families == {"inet"}:
                return Family.INET, f"alias {name} holds IPv4 entries only"
            if families == {"inet6"}:
                return Family.INET6, f"alias {name} holds IPv6 entries only"
            return Family.INET46, ""


def verdict_for(rule: Rule, aliases: dict[str, Alias]) -> FamilyVerdict:
    """Decide a rule's family from its endpoints, and explain a narrowing.

    Where the two ends disagree the rule cannot be dual-stack at all, which is worth
    a distinct message: it usually means an address was pasted into one end of a rule
    whose other end is a v6-capable alias.
    """
    source_family, source_reason = endpoint_family(rule.source, aliases)
    dest_family, dest_reason = endpoint_family(rule.destination, aliases)

    if source_family is dest_family:
        return FamilyVerdict(source_family, source_reason or dest_reason)
    if source_family is Family.INET46:
        return FamilyVerdict(dest_family, dest_reason)
    if dest_family is Family.INET46:
        return FamilyVerdict(source_family, source_reason)
    return FamilyVerdict(
        source_family,
        f"the two ends disagree — {source_reason}, while {dest_reason}. "
        "This rule cannot work for both families as written",
    )


def apply_families(
    rules: tuple[Rule, ...], aliases: dict[str, Alias]
) -> tuple[tuple[Rule, ...], tuple[str, ...]]:
    """Set each rule's family and report every narrowing.

    `V-DUALSTACK-ASYMMETRY` is raised from these. Nothing is silently downgraded: a
    rule that ends up single-family arrives with a sentence saying which, and why.
    """
    from dataclasses import replace

    out: list[Rule] = []
    warnings: list[str] = []
    for rule in rules:
        verdict = verdict_for(rule, aliases)
        out.append(replace(rule, family=verdict.family))
        if verdict.is_asymmetric:
            label = rule.descr or "(unnamed rule)"
            warnings.append(
                f"{label}: emitted {verdict.family.value} only, because {verdict.reason}. "
                "IPv6 is scored, so this rule protects half of what it appears to."
            )
    return tuple(out), tuple(warnings)
