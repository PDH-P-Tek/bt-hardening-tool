"""What each router must permit to itself.

Kept beside the estate rather than inside it, for the same reason `progress.py` is: the
estate document is the declared range and is read by the generator, the topology and the
monitor alike, and widening its schema to carry per-router firewall settings would make
every one of those a stakeholder in a change that concerns one page.

Most of it is derived rather than asked for. The peers come from which firewalls declare
this router as an upstream, and the management sources from the `Mgmt_Sources` alias the
policy already defines. The operator confirms and overrides; they do not retype.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from btht.app.generate.emit_router import RouterPolicy
from btht.app.model.estate import Estate
from btht.app.model.policy import Policy

#: The alias the policy already uses for "where we manage from".
MGMT_ALIAS = "Mgmt_Sources"


@dataclass
class Stored:
    """Operator overrides, per router. Absent fields fall back to what is derived."""

    overrides: dict[str, dict[str, object]] = field(default_factory=dict)

    def for_router(self, name: str) -> dict[str, object]:
        return self.overrides.get(name, {})

    def set(self, name: str, values: dict[str, object]) -> None:
        self.overrides[name] = values

    def clear(self, name: str) -> None:
        self.overrides.pop(name, None)


def path_for(estate_path: Path) -> Path:
    return estate_path.with_name("router-policy.json")


def load(estate_path: Path) -> Stored:
    path = path_for(estate_path)
    if not path.exists():
        return Stored()
    try:
        raw = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return Stored()
    if not isinstance(raw, dict):
        return Stored()
    return Stored(overrides={str(k): dict(v) for k, v in raw.items() if isinstance(v, dict)})


def save(stored: Stored, estate_path: Path) -> None:
    path = path_for(estate_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(stored.overrides, indent=2, sort_keys=True))


def derived_peers(estate: Estate, router: str) -> tuple[str, ...]:
    """Addresses this router forms adjacencies with, from what was already declared.

    An interface naming this router as an upstream *is* the declaration that the two
    peer. Asking the operator to type the same fact twice is how the two get out of
    step, and a stale peer list here silently refuses an adjacency.
    """
    peers: list[str] = []
    for firewall in estate.firewalls:
        for interface in firewall.interfaces:
            if router not in interface.upstreams:
                continue
            for address in (interface.v4, interface.v6):
                if not address:
                    continue
                peers.append(str(address).split("/")[0])
    return tuple(dict.fromkeys(peers))


def derived_mgmt(policy: Policy, alias_name: str = MGMT_ALIAS) -> tuple[str, ...]:
    """Addresses in the management alias, following nesting.

    `Mgmt_Sources` is usually defined by nesting rather than by listing addresses —
    on the shipped baseline it nests `Remote_Access` and names a segment. Reading only
    the direct entries therefore returns nothing for the common case, which here means
    silently refusing to generate a ruleset that should have generated fine.

    Segment members are not resolved: a segment is a role, and turning it into an
    address needs the firewall it sits on. The operator is shown what was found and
    can add the rest.
    """
    by_name = {alias.name: alias for alias in policy.aliases}
    out: list[str] = []
    seen: set[str] = set()

    def walk(name: str) -> None:
        if name in seen:  # aliases can nest each other into a cycle
            return
        seen.add(name)
        alias = by_name.get(name)
        if alias is None:
            return
        out.extend(alias.entries)
        for nested in alias.nested_aliases:
            walk(nested)

    walk(alias_name)
    return tuple(dict.fromkeys(out))


def _tuple(value: object) -> tuple[str, ...]:
    if isinstance(value, list):
        return tuple(str(v).strip() for v in value if str(v).strip())
    if isinstance(value, str):
        return tuple(part.strip() for part in value.split(",") if part.strip())
    return ()


def resolve(estate: Estate, policy: Policy, stored: Stored, router: str) -> RouterPolicy:
    """Derived facts, with the operator's overrides on top."""
    override = stored.for_router(router)
    mgmt = _tuple(override.get("mgmt_sources")) or derived_mgmt(policy)
    peers = _tuple(override.get("peers")) or derived_peers(estate, router)
    return RouterPolicy(
        name=router,
        mgmt_sources=mgmt,
        peers=peers,
        ospf=bool(override.get("ospf", True)),
        bgp=bool(override.get("bgp", False)),
        allow_groups=_tuple(override.get("allow_groups")),
        listen_address=str(override.get("listen_address", "")),
    )
