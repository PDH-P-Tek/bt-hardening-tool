"""Rules, aliases and NAT — the objects a firewall configuration is made of.

`SPEC.md` §4. Value objects throughout: frozen, tuple-valued, hashable. Two
reasons, both load-bearing. Generation is a pure function whose output must be
byte-identical across runs, and identity comes from fingerprinting these objects
rather than from their descriptions, so they must not change under anyone's feet.

Fields cover what the baseline and the generator need today. The parser will meet
pfSense elements this does not model; add them here when it does, rather than
carrying a bag of untyped extras.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from typing import TypeAlias


class Action(StrEnum):
    """What a rule does. Never inferred from its description — `EVIDENCE.md` E3."""

    PASS = "pass"
    BLOCK = "block"
    REJECT = "reject"


class Family(StrEnum):
    """pfSense `<ipprotocol>`. `INET46` is the default for generated rules (§7.2)."""

    INET = "inet"
    INET6 = "inet6"
    INET46 = "inet46"


class Direction(StrEnum):
    IN = "in"
    OUT = "out"
    ANY = "any"


class Role(StrEnum):
    """What an item is for. Drives validators — `SPEC.md` §4.3."""

    REMOTE_ACCESS = "remote_access"
    ROUTING = "routing"
    ESSENTIAL_SERVICES = "essential_services"
    MANAGEMENT = "management"
    SCORING = "scoring"
    OUT_OF_BOUNDS = "out_of_bounds"
    PERMISSIVE_DEFAULT = "permissive_default"
    ENCLAVE_POLICY = "enclave_policy"
    THREAT_BLOCK = "threat_block"
    UNKNOWN = "unknown"
    """Blocks export. An unresolved item is never guessed."""


class Disposition(StrEnum):
    """What happens to an item on the way out — `SPEC.md` §4.3."""

    KEEP_VERBATIM = "keep_verbatim"
    KEEP_EDIT = "keep_edit"
    REPLACE_GENERATED = "replace_generated"
    DROP = "drop"


class AliasType(StrEnum):
    HOST = "host"
    NETWORK = "network"
    PORT = "port"
    URL = "url"


# --- Endpoints -------------------------------------------------------------
# The tagged union of `SPEC.md` §4. Named to avoid colliding with `typing.Any`
# and with `estate.Host`; the spec names are given per class.


@dataclass(frozen=True, slots=True)
class AnyEndpoint:
    """Spec: `Any`. Matches everything, in both families."""


@dataclass(frozen=True, slots=True)
class SelfEndpoint:
    """Spec: `Self`. This firewall."""


@dataclass(frozen=True, slots=True)
class Network:
    """Spec: `Network(cidr)`."""

    cidr: IPv4Network | IPv6Network


@dataclass(frozen=True, slots=True)
class HostAddress:
    """Spec: `Host(addr)`."""

    address: IPv4Address | IPv6Address


@dataclass(frozen=True, slots=True)
class AliasRef:
    """Spec: `AliasRef(name)`."""

    name: str


@dataclass(frozen=True, slots=True)
class InterfaceNet:
    """Spec: `InterfaceNet(role)`. Keyed on the derived role, never on `lan`/`opt1`."""

    role: str


@dataclass(frozen=True, slots=True)
class Negated:
    """Spec: `Not(Endpoint)`. pfSense `<not>`."""

    endpoint: Endpoint


Endpoint: TypeAlias = (
    AnyEndpoint | SelfEndpoint | Network | HostAddress | AliasRef | InterfaceNet | Negated
)


@dataclass(frozen=True, slots=True)
class PortSpec:
    """A single port or an inclusive range. `53` and `53-53` normalise to one value."""

    low: int
    high: int

    def __post_init__(self) -> None:
        if not 0 < self.low <= self.high <= 65535:
            raise ValueError(f"invalid port range: {self.low}-{self.high}")


# --- Items -----------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Alias:
    name: str
    type: AliasType
    entries: tuple[str, ...]
    descr: str = ""
    detail: tuple[str, ...] = ()
    role: Role = Role.UNKNOWN
    disposition: Disposition = Disposition.KEEP_VERBATIM
    lockout_critical: bool = False
    """Cannot be dropped without typed confirmation. Set on `Remote_Access`."""


@dataclass(frozen=True, slots=True)
class Rule:
    action: Action
    interfaces: tuple[str, ...] = ()
    """Derived role tokens. Plural: a floating rule names several, and the strict
    fingerprint hashes them sorted (`SPEC.md` §6.2). Emission maps each back to an
    ifname; nothing else may look at ifnames."""

    family: Family = Family.INET46
    direction: Direction = Direction.IN
    quick: bool = False
    floating: bool = False
    protocol: str | None = None
    icmp_types: tuple[str, ...] = ()
    """Sorted into the fingerprint. `V-ICMP6-MINIMUM` reads this."""

    state_type: str = ""
    """pfSense `<statetype>`. In the strict fingerprint, so it is parsed, not dropped."""
    source: Endpoint = AnyEndpoint()
    destination: Endpoint = AnyEndpoint()
    source_ports: tuple[PortSpec, ...] = ()
    destination_ports: tuple[PortSpec, ...] = ()
    descr: str = ""
    """Display only. Never identity — `SPEC.md` §12.6."""

    tracker: str | None = None
    log: bool = False
    disabled: bool = False
    role: Role = Role.UNKNOWN
    disposition: Disposition = Disposition.KEEP_VERBATIM
    lockout_critical: bool = False


@dataclass(frozen=True, slots=True)
class NatRule:
    interface: str
    """Single, unlike a filter rule: a port forward binds to one interface."""

    protocol: str | None
    source: Endpoint
    destination: Endpoint
    destination_ports: tuple[PortSpec, ...]
    target: HostAddress | None
    local_port: int | None
    descr: str = ""
    disabled: bool = False


@dataclass(frozen=True, slots=True)
class NatConfig:
    """The baseline is `disabled` with no port forwards — pure routed (`SPEC.md` §7.3).

    A mode change is blocking (`V-NAT-MODE-CHANGED`). The tool never generates
    port forwards.
    """

    outbound_mode: str = "disabled"
    port_forwards: tuple[NatRule, ...] = ()
