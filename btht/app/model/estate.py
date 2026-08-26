"""The estate inventory — the spine both halves of the tool are built on.

`SPEC.md` §4 defines what the generator needs. `MONITORING.md` §11 requires the
same inventory to carry the monitor's managed estate, which is wider: it includes
the FRR routers, which are not firewalls and have no ruleset.

So there are two layers here. A `Node` is anything the monitor polls. A `Firewall`
is a node the generator also has a ruleset for. Defining these together, once, is
the point — two inventories would drift and then disagree about what the estate is.

**The estate is declared, never assumed.** Enclave names, interface role tokens and
side labels are whatever the operator sets up on day one — this module stores them
and never supplies them. No vocabulary from any particular exercise appears in this
package. The shipped profile and enclave templates offer *suggestions* the operator
confirms; the fixtures reproduce one observed estate for testing. Neither is a
default the code may fall back on.

Nothing in this module reaches the network, reads a file or holds a secret. A node
carries the *name* of a credential, never the credential.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from ipaddress import IPv4Address, IPv4Interface, IPv6Address, IPv6Interface

from btht.app.model.rules import Alias, NatConfig, Rule


class Platform(StrEnum):
    """Which adapter collects from this node — `MONITORING.md` §3.2."""

    PFSENSE = "pfsense"
    LINUX = "linux"
    FRR = "frr"


class SourceOfTruth(StrEnum):
    ANNEX = "annex"
    WIZARD = "wizard"
    NMAP = "nmap"


@dataclass(frozen=True, slots=True)
class Node:
    """Anything the monitor polls. Firewalls, routers and hosts alike."""

    name: str
    platform: Platform
    mgmt_address: IPv4Address | IPv6Address
    """Where the collector connects. The management path, and nothing else."""

    credential_ref: str = ""
    """Name of the key or account in the operator's store. Never the secret itself."""

    enclave: str | None = None
    poll_seconds: int = 60
    """`MONITORING.md` §3.5. Below 30s the poll cost on pfSense starts to matter."""

    def __post_init__(self) -> None:
        if self.poll_seconds < 30:
            raise ValueError(f"{self.name}: poll interval below the 30s floor")


@dataclass(frozen=True, slots=True)
class Interface:
    ifname: str
    """Emission target: `wan`, `lan`, `opt1`. Used for output, never for matching."""

    role: str
    """Matching token, declared or derived at setup — `SPEC.md` §4.1.

    At least one enclave in the observed estate maps `lan` to servers while the rest
    map it to workstations (`BASELINE-ANALYSIS.md` F2), so `ifname` is never a safe
    key for anything but emission. Use this."""

    descr: str = ""
    nic: str = ""
    v4: IPv4Interface | None = None
    v6: IPv6Interface | None = None
    is_lan: bool = False
    """The interface anti-lockout binds to."""


@dataclass(frozen=True, slots=True)
class Host:
    hostname: str
    v4: IPv4Address | None = None
    v6: IPv6Address | None = None
    segment_role: str = ""
    service_role: str = ""
    """From `service-catalogue.yaml` hostname patterns."""

    isa_checks: tuple[str, ...] = ()
    """From `isa-checks.yaml`. Drives SCORING rules and the verification manifest."""

    out_of_bounds: bool = False
    """EXCON. Protected, never blocked, never a policy target — `BASELINE-ANALYSIS.md` F8.
    `scoringbot` and `npc-server` live inside the workstation segment and appear on no
    diagram; tightening that segment kills scoring from the inside."""

    source_of_truth: SourceOfTruth = SourceOfTruth.WIZARD


@dataclass(frozen=True, slots=True)
class Firewall:
    """A node the generator also holds a ruleset for."""

    enclave: str
    """The operator's name for this enclave, from estate setup. Free-form: the tool
    has no list of valid enclaves and must never acquire one."""

    fqdn: str
    node: Node
    side: str = ""
    """Operator-declared grouping label, where an estate has one.

    Derive it from the **WAN address**, never from internal ranges — `SPEC.md` §4.2.
    A firewall can sit on one side while its internal segments address into another,
    so inferring from internals gets those cases backwards."""
    config_version: str = ""
    """Must be `23.3` — `V-CONFIG-VERSION` blocks otherwise."""

    interfaces: tuple[Interface, ...] = ()
    hosts: tuple[Host, ...] = ()
    aliases: tuple[Alias, ...] = ()
    rules: tuple[Rule, ...] = ()
    nat: NatConfig = field(default_factory=NatConfig)
    baseline_sha256: str = ""
    """Binds generated output to one firewall identity. A mismatched import is
    refused, not warned — `SPEC.md` §7.4."""

    def interface_by_role(self, role: str) -> Interface | None:
        for iface in self.interfaces:
            if iface.role == role:
                return iface
        return None

    def role_to_ifname(self) -> dict[str, str]:
        """The map that travels with generated output so emission can be reversed."""
        return {iface.role: iface.ifname for iface in self.interfaces}


@dataclass(frozen=True, slots=True)
class CrossEnclaveDep:
    """An egress allow on one firewall that needs a matching ingress on another.

    Unmatched pairs raise `V-CROSS-ENCLAVE-ORPHAN`, which is why the tool models
    the whole team estate rather than one enclave at a time.
    """

    source_enclave: str
    dest_enclave: str
    dest_host: str = ""
    ports: tuple[int, ...] = ()
    why: str = ""


@dataclass(frozen=True, slots=True)
class Estate:
    """One team's whole estate. The unit of work, so cross-enclave deps validate."""

    team: int
    team_padded: str
    """Stored, not derived. Whether a single-digit team pads in *addresses* is
    `OPEN-QUESTIONS.md` Q3 and unresolved; deriving it here would bake in a guess."""

    role_vocabulary: tuple[str, ...] = ()
    """Interface role tokens this estate uses, declared at setup. Empty means nothing
    has been declared yet, not "anything goes" — an interface whose role is outside
    this set surfaces in triage rather than being guessed."""

    firewalls: tuple[Firewall, ...] = ()
    nodes: tuple[Node, ...] = ()
    """Every managed node, routers included. Firewalls appear here too, via
    `Firewall.node`, so the monitor has one list to poll."""

    shared_aliases: tuple[Alias, ...] = ()
    dependencies: tuple[CrossEnclaveDep, ...] = ()

    def knows_role(self, role: str) -> bool:
        """Whether a role token was declared for this estate."""
        return role in self.role_vocabulary

    def firewall(self, enclave: str) -> Firewall | None:
        for fw in self.firewalls:
            if fw.enclave == enclave:
                return fw
        return None

    def all_nodes(self) -> tuple[Node, ...]:
        """Firewall nodes first, then anything else the monitor manages."""
        seen: dict[str, Node] = {fw.node.name: fw.node for fw in self.firewalls}
        for node in self.nodes:
            seen.setdefault(node.name, node)
        return tuple(seen.values())
