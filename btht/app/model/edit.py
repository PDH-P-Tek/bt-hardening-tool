"""Editing what the operator has already declared — Phase 9.6.

Everything in this tool was add-only, which is fine right up until somebody types an
address wrong at half past eleven the night before the range opens. Then it is the
difference between fixing a field and hand-editing YAML under pressure, which is how a
second mistake gets made.

Two rules shape this module.

**Nothing is deleted while something still points at it.** Removing a service that four
host types use, or an alias a rule references, produces a configuration that looks
complete and quietly does nothing. So deletion asks what refers to it first, and says
so by name.

**Renaming carries its references with it.** A rename is the most useful edit and the
most dangerous one: rename a service and every host that runs it silently stops
running anything. References are rewritten in the same operation, and the operator is
told what moved.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import TypeVar

from btht.app.model.estate import Estate, Firewall
from btht.app.model.policy import Policy, PolicyAlias, ServiceRule
from btht.app.model.services import Catalogue, HostType, Service

T = TypeVar("T")


class InUse(Exception):
    """Refusing to remove something other things depend on."""


@dataclass(frozen=True, slots=True)
class Rename:
    """What a rename touched, so the operator sees the blast radius rather than
    trusting that it worked."""

    what: str
    old: str
    new: str
    references_updated: tuple[str, ...] = ()

    @property
    def summary(self) -> str:
        if not self.references_updated:
            return f"Renamed {self.what} {self.old} to {self.new}."
        return (
            f"Renamed {self.what} {self.old} to {self.new}, and updated "
            f"{len(self.references_updated)} reference(s): " + ", ".join(self.references_updated)
        )


# --- the estate -------------------------------------------------------------


def update_firewall(estate: Estate, enclave: str, **changes: object) -> Estate:
    """Amend one enclave's firewall. `enclave` may itself be among the changes."""
    firewalls = tuple(
        replace(fw, **changes) if fw.enclave == enclave else fw  # type: ignore[arg-type]
        for fw in estate.firewalls
    )
    return replace(estate, firewalls=firewalls)


def remove_firewall(estate: Estate, enclave: str, policy: Policy | None = None) -> Estate:
    """Remove an enclave, unless a declared path still names it."""
    if policy is not None:
        naming = [
            d.name
            for d in policy.dependencies
            if enclave in d.from_enclaves or d.to_enclave == enclave
        ]
        if naming:
            raise InUse(
                f"{enclave} is named by {len(naming)} declared path(s): "
                + ", ".join(naming)
                + ". Remove or repoint those first, or the far end keeps a rule for "
                "traffic that can no longer arrive."
            )
    return replace(estate, firewalls=tuple(f for f in estate.firewalls if f.enclave != enclave))


def update_interface(estate: Estate, enclave: str, ifname: str, **changes: object) -> Estate:
    interfaces_changed = False

    def amend(firewall: Firewall) -> Firewall:
        nonlocal interfaces_changed
        if firewall.enclave != enclave:
            return firewall
        interfaces_changed = True
        return replace(
            firewall,
            interfaces=tuple(
                replace(i, **changes) if i.ifname == ifname else i  # type: ignore[arg-type]
                for i in firewall.interfaces
            ),
        )

    return replace(estate, firewalls=tuple(amend(f) for f in estate.firewalls))


def remove_interface(estate: Estate, enclave: str, ifname: str) -> Estate:
    """Remove an interface, unless hosts still sit on the segment it carries."""
    firewall = estate.firewall(enclave)
    if firewall is not None:
        interface = next((i for i in firewall.interfaces if i.ifname == ifname), None)
        if interface is not None:
            occupants = [
                h.hostname for h in firewall.all_hosts() if h.segment_role == interface.role
            ]
            if occupants:
                raise InUse(
                    f"{len(occupants)} host(s) are on the {interface.role} segment: "
                    + ", ".join(occupants[:6])
                    + ("…" if len(occupants) > 6 else "")
                    + ". Move or remove them first — a host on a segment that no longer "
                    "exists gets no rules and appears nowhere."
                )
    return replace(
        estate,
        firewalls=tuple(
            replace(f, interfaces=tuple(i for i in f.interfaces if i.ifname != ifname))
            if f.enclave == enclave
            else f
            for f in estate.firewalls
        ),
    )


def update_host(estate: Estate, enclave: str, hostname: str, **changes: object) -> Estate:
    return replace(
        estate,
        firewalls=tuple(
            replace(
                f,
                hosts=tuple(
                    replace(h, **changes) if h.hostname == hostname else h  # type: ignore[arg-type]
                    for h in f.hosts
                ),
            )
            if f.enclave == enclave
            else f
            for f in estate.firewalls
        ),
    )


def remove_host(estate: Estate, enclave: str, hostname: str) -> Estate:
    return replace(
        estate,
        firewalls=tuple(
            replace(f, hosts=tuple(h for h in f.hosts if h.hostname != hostname))
            if f.enclave == enclave
            else f
            for f in estate.firewalls
        ),
    )


def update_host_group(estate: Estate, enclave: str, prefix: str, **changes: object) -> Estate:
    return replace(
        estate,
        firewalls=tuple(
            replace(
                f,
                host_groups=tuple(
                    replace(g, **changes) if g.name_prefix == prefix else g  # type: ignore[arg-type]
                    for g in f.host_groups
                ),
            )
            if f.enclave == enclave
            else f
            for f in estate.firewalls
        ),
    )


def remove_host_group(estate: Estate, enclave: str, prefix: str) -> Estate:
    """Removing a group removes every machine in it. The count is the warning."""
    return replace(
        estate,
        firewalls=tuple(
            replace(f, host_groups=tuple(g for g in f.host_groups if g.name_prefix != prefix))
            if f.enclave == enclave
            else f
            for f in estate.firewalls
        ),
    )


# --- the catalogue ----------------------------------------------------------


def service_references(catalogue: Catalogue, estate: Estate, name: str) -> tuple[str, ...]:
    """Everything that would stop working if this service disappeared."""
    out: list[str] = []
    for type_name, host_type in sorted(catalogue.host_types.items()):
        if name in host_type.services:
            out.append(f"host type {type_name}")
    for firewall in estate.firewalls:
        for host in firewall.hosts:
            if name in host.services:
                out.append(f"host {host.hostname}")
        for group in firewall.host_groups:
            if name in group.services:
                out.append(f"group {group.name_prefix}")
    return tuple(out)


def rename_service(
    catalogue: Catalogue, estate: Estate, old: str, new: str
) -> tuple[Catalogue, Estate, Rename]:
    """Rename a service and carry every reference with it.

    Without this a rename silently empties every host that ran it: the name no longer
    resolves, the ports vanish from generation, and nothing reports an error because
    an unknown service is indistinguishable from no service.
    """
    service = catalogue.services.get(old)
    if service is None:
        raise KeyError(old)
    touched = service_references(catalogue, estate, old)

    services = {k: v for k, v in catalogue.services.items() if k != old}
    services[new] = replace(service, name=new)
    host_types = {
        k: replace(t, services=tuple(new if s == old else s for s in t.services))
        for k, t in catalogue.host_types.items()
    }
    updated_catalogue = Catalogue(
        services=services,
        host_types=host_types,
        hostname_patterns=catalogue.hostname_patterns,
    )

    def swap(names: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(new if n == old else n for n in names)

    updated_estate = replace(
        estate,
        firewalls=tuple(
            replace(
                f,
                hosts=tuple(replace(h, services=swap(h.services)) for h in f.hosts),
                host_groups=tuple(replace(g, services=swap(g.services)) for g in f.host_groups),
            )
            for f in estate.firewalls
        ),
    )
    return updated_catalogue, updated_estate, Rename("service", old, new, touched)


def update_service(catalogue: Catalogue, service: Service) -> Catalogue:
    return catalogue.with_service(service)


def remove_service(catalogue: Catalogue, estate: Estate, name: str) -> Catalogue:
    used_by = service_references(catalogue, estate, name)
    if used_by:
        raise InUse(
            f"{name} is used by {len(used_by)} thing(s): "
            + ", ".join(used_by[:8])
            + ("…" if len(used_by) > 8 else "")
            + ". Removing it leaves them running a service the tool no longer knows the "
            "ports for, which generates nothing and reports nothing."
        )
    return Catalogue(
        services={k: v for k, v in catalogue.services.items() if k != name},
        host_types=catalogue.host_types,
        hostname_patterns=catalogue.hostname_patterns,
    )


def host_type_references(estate: Estate, name: str) -> tuple[str, ...]:
    out: list[str] = []
    for firewall in estate.firewalls:
        for host in firewall.hosts:
            if host.service_role == name:
                out.append(f"host {host.hostname}")
        for group in firewall.host_groups:
            if group.host_type == name:
                out.append(f"group {group.name_prefix}")
    return tuple(out)


def update_host_type(catalogue: Catalogue, host_type: HostType) -> Catalogue:
    return catalogue.with_host_type(host_type)


def remove_host_type(catalogue: Catalogue, estate: Estate, name: str) -> Catalogue:
    used_by = host_type_references(estate, name)
    if used_by:
        raise InUse(
            f"{name} is used by {len(used_by)} thing(s): "
            + ", ".join(used_by[:8])
            + ("…" if len(used_by) > 8 else "")
            + ". They would keep the type name and lose its services."
        )
    return Catalogue(
        services=catalogue.services,
        host_types={k: v for k, v in catalogue.host_types.items() if k != name},
        hostname_patterns=catalogue.hostname_patterns,
    )


# --- policy -----------------------------------------------------------------


def update_policy_service(policy: Policy, enclave: str, name: str, service: ServiceRule) -> Policy:
    return replace(
        policy,
        firewalls=tuple(
            replace(
                entry,
                services=tuple(service if s.name == name else s for s in entry.services),
            )
            if entry.enclave == enclave
            else entry
            for entry in policy.firewalls
        ),
    )


def remove_policy_service(policy: Policy, enclave: str, name: str) -> Policy:
    return replace(
        policy,
        firewalls=tuple(
            replace(entry, services=tuple(s for s in entry.services if s.name != name))
            if entry.enclave == enclave
            else entry
            for entry in policy.firewalls
        ),
    )


def alias_references(policy: Policy, name: str) -> tuple[str, ...]:
    """Rules and dependencies that would match nothing without this alias."""
    out: list[str] = []
    for entry in policy.firewalls:
        for service in entry.services:
            if service.alias == name or service.source.alias == name:
                out.append(f"{entry.enclave}/{service.name}")
        for index, allow in enumerate(entry.egress.allow, start=1):
            if name in (allow.source.alias, allow.destination.alias):
                out.append(f"{entry.enclave}/egress allow {index}")
    for dependency in policy.dependencies:
        if dependency.to_alias == name:
            out.append(f"dependency {dependency.name}")
    for alias in policy.aliases:
        if name in alias.nested_aliases:
            out.append(f"alias {alias.name}")
    return tuple(out)


def update_alias(policy: Policy, name: str, alias: PolicyAlias) -> Policy:
    return replace(policy, aliases=tuple(alias if a.name == name else a for a in policy.aliases))


def remove_alias(policy: Policy, name: str) -> Policy:
    """An alias with rules pointing at it is never quietly removed.

    `V-ALIAS-MISSING` would catch it at the gate, but catching it here means the
    operator finds out while they still remember why they were deleting it.
    """
    used_by = alias_references(policy, name)
    if used_by:
        raise InUse(
            f"{name} is referenced by: "
            + ", ".join(used_by[:8])
            + ("…" if len(used_by) > 8 else "")
            + ". Those rules would match nothing."
        )
    target = next((a for a in policy.aliases if a.name == name), None)
    if target is not None and target.lockout_critical:
        raise InUse(
            f"{name} is lockout-critical. Removing it is how a team loses access to its "
            "own firewall, from a change they made themselves. Clear the flag first if "
            "you genuinely mean to."
        )
    return replace(policy, aliases=tuple(a for a in policy.aliases if a.name != name))
