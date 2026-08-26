"""Services and host types — Phase 9.1 and 9.2.

The estate is not a list of addresses. It is a few kinds of machine, repeated: ten
Windows 10 workstations, five Ubuntu desktops, two domain controllers. Declaring each
one by hand is both tedious and how a host gets missed — and a host nobody declared is
a host whose ports nobody opened.

So there are three layers here, each answering a different question:

- a **Service** is a thing that listens: a name, a protocol and its ports. `RDP` is
  3389/tcp everywhere, so the operator picks it rather than typing a number.
- a **HostType** is a kind of machine: what it usually runs. A Windows workstation is
  RDP; a domain controller is eleven things and the one everybody forgets is the RPC
  dynamic range.
- a **HostGroup** (in `estate.py`) is many machines of one type, declared once.

**Non-standard services are first-class, not an afterthought.** Every estate has
something bespoke on an odd port, and a catalogue that only knows well-known ports
forces the operator to lie about what they are running.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

import yaml


class Confidence(StrEnum):
    STANDARD = "standard"
    """Well-known. Safe to apply."""

    ASSUMED = "assumed"
    """A plausible default. Verify before relying on it."""

    UNVERIFIED = "unverified"
    """Genuinely unknown. Raises `V-UNVERIFIED-SERVICE` on every export until closed."""


@dataclass(frozen=True, slots=True)
class Service:
    """One listening service. Ports are the point; the name is how a human picks it."""

    name: str
    tcp: tuple[int, ...] = ()
    udp: tuple[int, ...] = ()
    tcp_dynamic: str = ""
    """A range such as `49152-65535`, kept as written because it is usually a trap
    worth quoting rather than a number worth computing."""

    descr: str = ""
    confidence: Confidence = Confidence.STANDARD
    note: str = ""
    """Shown to the operator when they pick it. This is where the traps live."""

    custom: bool = False
    """Declared by this operator rather than shipped. Neither is more real."""

    @property
    def summary(self) -> str:
        parts = []
        if self.tcp:
            parts.append("tcp " + ",".join(str(p) for p in self.tcp))
        if self.udp:
            parts.append("udp " + ",".join(str(p) for p in self.udp))
        if self.tcp_dynamic:
            parts.append(f"tcp {self.tcp_dynamic}")
        return " · ".join(parts) or "no ports declared"

    def all_ports(self) -> tuple[tuple[str, int], ...]:
        return tuple(sorted({("tcp", p) for p in self.tcp} | {("udp", p) for p in self.udp}))


@dataclass(frozen=True, slots=True)
class HostType:
    """A kind of machine, and what it usually runs.

    A suggestion the operator confirms — the same rule as everywhere else. The tool
    proposes the service set; it does not decide that a box called `dc01` is a domain
    controller.
    """

    name: str
    services: tuple[str, ...] = ()
    default_os: str = ""
    descr: str = ""
    custom: bool = False


@dataclass(frozen=True, slots=True)
class Catalogue:
    services: dict[str, Service] = field(default_factory=dict)
    host_types: dict[str, HostType] = field(default_factory=dict)
    hostname_patterns: tuple[tuple[str, str], ...] = ()
    """`(regex, host_type)`. Drives suggestion only, never assignment."""

    def service(self, name: str) -> Service | None:
        return self.services.get(name)

    def ports_for(self, service_names: tuple[str, ...]) -> tuple[tuple[str, int], ...]:
        """Every protocol/port pair these services need, deduplicated and ordered."""
        pairs: set[tuple[str, int]] = set()
        for name in service_names:
            service = self.services.get(name)
            if service is not None:
                pairs.update(service.all_ports())
        return tuple(sorted(pairs))

    def unverified(self, service_names: tuple[str, ...]) -> tuple[str, ...]:
        """Services whose ports are a guess. They keep a rule open until closed."""
        return tuple(
            name
            for name in service_names
            if (s := self.services.get(name)) is not None and s.confidence is Confidence.UNVERIFIED
        )

    def suggest_type(self, hostname: str) -> str:
        """Propose a host type from a hostname. A proposal, never an assignment."""
        import re

        for pattern, type_name in self.hostname_patterns:
            if re.fullmatch(pattern, hostname.lower()) or re.match(pattern, hostname.lower()):
                return type_name
        return ""

    def dangling_patterns(self) -> tuple[str, ...]:
        """Hostname patterns pointing at a host type that does not exist.

        A suggestion that resolves to nothing is worse than no suggestion: the operator
        sees a blank where they expected a proposal and cannot tell whether the tool
        looked or simply had nothing to say.
        """
        return tuple(
            f"{pattern} -> {type_name}"
            for pattern, type_name in self.hostname_patterns
            if type_name not in self.host_types
        )

    def with_service(self, service: Service) -> Catalogue:
        return Catalogue(
            services={**self.services, service.name: service},
            host_types=self.host_types,
            hostname_patterns=self.hostname_patterns,
        )

    def with_host_type(self, host_type: HostType) -> Catalogue:
        return Catalogue(
            services=self.services,
            host_types={**self.host_types, host_type.name: host_type},
            hostname_patterns=self.hostname_patterns,
        )


def _ports(value: Any) -> tuple[int, ...]:
    return tuple(int(p) for p in value or ())


def load_catalogue(path: Path) -> Catalogue:
    """Load the shipped catalogue plus anything the operator has added."""
    if not path.exists():
        return Catalogue()
    data: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8")) or {}

    services: dict[str, Service] = {}
    for name, spec in (data.get("named_services") or {}).items():
        spec = spec or {}
        services[str(name)] = Service(
            name=str(name),
            tcp=_ports(spec.get("tcp")),
            udp=_ports(spec.get("udp")),
            tcp_dynamic=str(spec.get("tcp_dynamic", "")),
            descr=str(spec.get("descr", "")),
            confidence=Confidence(str(spec.get("confidence", "standard"))),
            note=str(spec.get("note", "")).strip(),
            custom=bool(spec.get("custom", False)),
        )

    host_types: dict[str, HostType] = {}
    for name, spec in (data.get("host_types") or {}).items():
        spec = spec or {}
        host_types[str(name)] = HostType(
            name=str(name),
            services=tuple(str(s) for s in spec.get("services", ()) or ()),
            default_os=str(spec.get("default_os", "")),
            descr=str(spec.get("descr", "")),
            custom=bool(spec.get("custom", False)),
        )

    patterns = tuple(
        (str(entry["match"]), str(entry["role"]))
        for entry in data.get("hostname_patterns", ()) or ()
        if entry.get("match") and entry.get("role")
    )
    return Catalogue(services=services, host_types=host_types, hostname_patterns=patterns)


def save_catalogue(catalogue: Catalogue, path: Path) -> None:
    """Write services and host types back, preserving everything else in the file."""
    data: dict[str, Any] = {}
    if path.exists():
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}

    data["named_services"] = {
        name: {
            **({"tcp": list(s.tcp)} if s.tcp else {}),
            **({"udp": list(s.udp)} if s.udp else {}),
            **({"tcp_dynamic": s.tcp_dynamic} if s.tcp_dynamic else {}),
            **({"descr": s.descr} if s.descr else {}),
            "confidence": s.confidence.value,
            **({"note": s.note} if s.note else {}),
            **({"custom": True} if s.custom else {}),
        }
        for name, s in sorted(catalogue.services.items())
    }
    data["host_types"] = {
        name: {
            "services": list(t.services),
            **({"default_os": t.default_os} if t.default_os else {}),
            **({"descr": t.descr} if t.descr else {}),
            **({"custom": True} if t.custom else {}),
        }
        for name, t in sorted(catalogue.host_types.items())
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump(data, sort_keys=False, default_flow_style=False, allow_unicode=True),
        encoding="utf-8",
    )
