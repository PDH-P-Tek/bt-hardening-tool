"""Scoring check assignment — `SPEC.md` §5.3.

The problem this solves: the documents that describe an estate give hostnames,
addresses and roles, and **no port numbers**. The scoring board gives them, per
target, and is readable on day one.

So the catalogue maps a service role to a set of named checks, and each check to a
protocol and ports. The tool proposes; the operator confirms against the live board.
It is proposed rather than applied for a reason recorded in the catalogue itself: the
mapping was read from one board on one exercise, and two ways of being wrong are
expensive. A check that runs and was not allowed loses points silently, and a port
assumed to be checked that is not buys nothing while widening the firewall.

**The catalogue is optional.** With none loaded, no checks are proposed and no scoring
rules are generated. A tool that invented a scored port list would be worse than one
that admits it does not have one.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True, slots=True)
class Check:
    """One named check, and what it takes to satisfy it."""

    name: str
    proto: str = "tcp"
    ports: tuple[int, ...] = ()
    note: str = ""

    @property
    def satisfiable_by_ingress(self) -> bool:
        """Whether an inbound allow rule can satisfy this at all.

        Some checks measure the target reaching *out* — the catalogue marks those
        `egress` or `application`. An ingress rule does nothing for them, and an
        egress default-deny fails them. `V-EGRESS-CHECK` exists for exactly this.
        """
        return self.proto not in ("egress", "application")


@dataclass(frozen=True, slots=True)
class Catalogue:
    checks: dict[str, Check]
    role_check_sets: dict[str, tuple[str, ...]]
    role_notes: dict[str, str]
    source: str = ""

    @property
    def is_empty(self) -> bool:
        return not self.checks

    def propose(self, service_role: str) -> tuple[str, ...]:
        """The check set a role usually carries. A starting point for confirmation."""
        return self.role_check_sets.get(service_role, ())

    def resolve(self, names: tuple[str, ...]) -> tuple[Check, ...]:
        """Named checks to protocol and ports. Unknown names are dropped by `unknown`."""
        return tuple(self.checks[name] for name in names if name in self.checks)

    def unknown(self, names: tuple[str, ...]) -> tuple[str, ...]:
        """Names this catalogue does not define — surfaced, never quietly ignored."""
        return tuple(name for name in names if name not in self.checks)


EMPTY = Catalogue(checks={}, role_check_sets={}, role_notes={})


def load_catalogue(path: Path | None) -> Catalogue:
    """Load a scoring catalogue. A missing file is a valid state, not an error."""
    if path is None or not path.exists():
        return EMPTY

    data: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    checks: dict[str, Check] = {}
    for name, spec in (data.get("checks") or {}).items():
        spec = spec or {}
        checks[str(name)] = Check(
            name=str(name),
            proto=str(spec.get("proto", "tcp")),
            ports=tuple(int(p) for p in spec.get("ports", ()) or ()),
            note=str(spec.get("note", "")).strip(),
        )

    role_sets: dict[str, tuple[str, ...]] = {}
    role_notes: dict[str, str] = {}
    for role, spec in (data.get("role_check_sets") or {}).items():
        spec = spec or {}
        role_sets[str(role)] = tuple(str(c) for c in spec.get("checks", ()) or ())
        if spec.get("note"):
            role_notes[str(role)] = str(spec["note"]).strip()

    source = str((data.get("source") or {}).get("system", ""))
    return Catalogue(checks=checks, role_check_sets=role_sets, role_notes=role_notes, source=source)


@dataclass(frozen=True, slots=True)
class HostAssignment:
    """What is proposed for one host, and what the operator needs to know about it."""

    hostname: str
    service_role: str
    proposed: tuple[str, ...]
    confirmed: tuple[str, ...]
    notes: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()

    @property
    def needs_confirming(self) -> bool:
        return self.proposed != self.confirmed or not self.confirmed


def assign(
    hostname: str,
    service_role: str,
    confirmed: tuple[str, ...],
    catalogue: Catalogue,
    *,
    out_of_bounds: bool = False,
) -> HostAssignment:
    """Propose a check set for one host and report what the operator should look at."""
    proposed = catalogue.propose(service_role)
    notes: list[str] = []
    warnings: list[str] = []

    if catalogue.is_empty:
        warnings.append(
            "No scoring catalogue is loaded, so nothing is proposed and no scoring "
            "rules will be generated."
        )
    elif not proposed and not confirmed:
        warnings.append(
            f"No checks proposed for role {service_role or '(none set)'}. Confirm on the "
            "board that this host really is unscored."
        )

    if service_role in catalogue.role_notes:
        notes.append(catalogue.role_notes[service_role])

    unknown = catalogue.unknown(confirmed)
    if unknown:
        warnings.append(
            "Checks this catalogue does not define: " + ", ".join(unknown) + ". "
            "They will not generate a rule until the catalogue defines their ports."
        )

    for check in catalogue.resolve(confirmed):
        if not check.satisfiable_by_ingress:
            warnings.append(
                f"{check.name} measures this host reaching out. No inbound rule satisfies "
                "it, and an egress default-deny will fail it."
            )
        if check.note:
            notes.append(f"{check.name}: {check.note}")

    if out_of_bounds:
        notes.append("Out of bounds. It must keep working and must never be a policy target.")

    return HostAssignment(
        hostname=hostname,
        service_role=service_role,
        proposed=proposed,
        confirmed=confirmed,
        notes=tuple(notes),
        warnings=tuple(warnings),
    )


def required_ports(confirmed: tuple[str, ...], catalogue: Catalogue) -> tuple[tuple[str, int], ...]:
    """Every protocol/port pair that must stay reachable, deduplicated and ordered.

    This is what the generator turns into scoring rules and what the verification
    manifest is built from — one list, two consumers, so they cannot disagree about
    what was supposed to be open.
    """
    pairs: set[tuple[str, int]] = set()
    for check in catalogue.resolve(confirmed):
        if not check.satisfiable_by_ingress:
            continue
        if not check.ports:
            pairs.add((check.proto, 0))  # a protocol with no port, such as ICMP echo
        for port in check.ports:
            pairs.add((check.proto, port))
    return tuple(sorted(pairs))
