"""The classification profile — `SPEC.md` §4.3, §6.

A profile states what a known-good baseline *contains*, semantically. It never
contains a hash: fingerprints are computed at load time through the same
normalisation path as ingest, so a change to normalisation moves both sides
together. Hand-written hashes would drift from the implementation and start
silently failing to match, which is the failure this whole layer exists to avoid.

Entries are templated (`25.{X}.0.1`), so one profile describes the baseline for
every team rather than one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from btht.app.model.rules import (
    Action,
    Alias,
    AliasRef,
    AliasType,
    AnyEndpoint,
    Direction,
    Disposition,
    Endpoint,
    Family,
    PortSpec,
    Role,
    Rule,
    SelfEndpoint,
)

#: What a profile rule bound to every interface canonicalises to. Matches the token
#: `normalise.ALL_INTERFACES` produces for a config rule on all of them.
ANY_INTERFACE = "*"


@dataclass(frozen=True, slots=True)
class KnownDefect:
    """A fault the baseline ships with, recorded so the tool does not "fix" it blindly."""

    id: str = ""
    severity: str = ""
    summary: str = ""
    validators: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ProfileRule:
    key: str
    rule: Rule
    role: Role = Role.UNKNOWN
    disposition: Disposition = Disposition.KEEP_VERBATIM
    lockout_critical: bool = False
    plain_english: str = ""
    """One line the operator reads instead of the XML. A first-class feature."""

    known_defect: KnownDefect | None = None
    applies_to_roles: tuple[str, ...] = ()
    """This entry describes a rule that appears once per segment, not once per
    firewall. The listed roles are the profile's *suggestion*; the classifier expands
    against the segments the firewall actually has, since the vocabulary is the
    operator's. Empty means the entry binds to the interfaces named in `rule`."""


@dataclass(frozen=True, slots=True)
class ProfileAlias:
    alias: Alias
    role: Role = Role.UNKNOWN
    disposition: Disposition = Disposition.KEEP_VERBATIM
    lockout_critical: bool = False
    plain_english: str = ""
    known_defect: KnownDefect | None = None


@dataclass(frozen=True, slots=True)
class Profile:
    version: int = 0
    rules: tuple[ProfileRule, ...] = ()
    aliases: tuple[ProfileAlias, ...] = ()
    interface_roles: dict[str, Any] = field(default_factory=dict)
    """The suggested vocabulary and enclave tokens. A suggestion the operator
    confirms at setup — never applied on its own."""

    def alias_table(self) -> dict[str, Alias]:
        return {entry.alias.name: entry.alias for entry in self.aliases}


# --- loading ---------------------------------------------------------------


def _endpoint(value: Any) -> tuple[Endpoint, tuple[PortSpec, ...]]:
    """Read one `source:` or `destination:` from the declarative form."""
    if value in ("any", None):
        return AnyEndpoint(), ()
    if value == "self":
        return SelfEndpoint(), ()
    if isinstance(value, dict):
        ports = _ports(value.get("port"))
        if value.get("any"):
            return AnyEndpoint(), ports
        if "alias" in value:
            return AliasRef(str(value["alias"])), ports
        if value.get("self"):
            return SelfEndpoint(), ports
    raise ValueError(f"profile: cannot read endpoint {value!r}")


def _ports(value: Any) -> tuple[PortSpec, ...]:
    if value is None:
        return ()
    text = str(value)
    if "-" in text:
        low, high = text.split("-", 1)
        return (PortSpec(int(low), int(high)),)
    return (PortSpec(int(text), int(text)),)


def _interfaces(value: Any) -> tuple[str, ...]:
    """`any` means every interface on the firewall, which canonicalises to `*`."""
    if value in ("any", None):
        return (ANY_INTERFACE,)
    if isinstance(value, str):
        return (value,)
    return tuple(str(v) for v in value)


def _entries(value: Any) -> tuple[str, ...]:
    """Alias entries are either plain strings or `{cidr, owner}` pairs."""
    out: list[str] = []
    for item in value or ():
        if isinstance(item, dict):
            out.append(str(item.get("cidr") or item.get("address") or ""))
        else:
            out.append(str(item))
    return tuple(e for e in out if e)


def _defect(value: Any) -> KnownDefect | None:
    if not isinstance(value, dict):
        return None
    return KnownDefect(
        id=str(value.get("id", "")),
        severity=str(value.get("severity", "")),
        summary=str(value.get("summary", "")).strip(),
        validators=tuple(str(v) for v in value.get("validators", ())),
    )


def _rule(data: dict[str, Any]) -> ProfileRule:
    source, source_ports = _endpoint(data.get("source"))
    destination, destination_ports = _endpoint(data.get("destination"))
    icmp = data.get("icmptype") or ()
    return ProfileRule(
        key=str(data.get("key", "")),
        role=Role(data.get("role", "unknown")),
        disposition=Disposition(data.get("disposition", "keep_verbatim")),
        lockout_critical=bool(data.get("lockout_critical", False)),
        plain_english=str(data.get("plain_english", "")).strip(),
        known_defect=_defect(data.get("known_defect")),
        applies_to_roles=tuple(str(r) for r in data.get("applies_to_roles", ())),
        rule=Rule(
            action=Action(str(data.get("type", "pass"))),
            interfaces=_interfaces(data.get("interface")),
            family=Family(str(data.get("ipprotocol", "inet46"))),
            direction=Direction(str(data.get("direction", "in"))),
            quick=bool(data.get("quick", False)),
            floating=bool(data.get("floating", False)),
            protocol=str(data["protocol"]) if data.get("protocol") else None,
            icmp_types=tuple(sorted(str(t) for t in icmp)),
            state_type=str(data.get("statetype", "")),
            source=source,
            destination=destination,
            source_ports=source_ports,
            destination_ports=destination_ports,
            descr=str(data.get("descr", "")),
        ),
    )


def _alias(data: dict[str, Any]) -> ProfileAlias:
    return ProfileAlias(
        role=Role(data.get("role", "unknown")),
        disposition=Disposition(data.get("disposition", "keep_verbatim")),
        lockout_critical=bool(data.get("lockout_critical", False)),
        plain_english=str(data.get("plain_english", "")).strip(),
        known_defect=_defect(data.get("known_defect")),
        alias=Alias(
            name=str(data.get("name", "")),
            type=AliasType(str(data.get("type", "host"))),
            entries=_entries(data.get("entries")),
            descr=str(data.get("descr", "")),
        ),
    )


def load_profile(path: Path) -> Profile:
    data: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return Profile(
        version=int(data.get("version", 0)),
        rules=tuple(_rule(r) for r in data.get("rules", ())),
        aliases=tuple(_alias(a) for a in data.get("aliases", ())),
        interface_roles=dict(data.get("interface_roles", {})),
    )
