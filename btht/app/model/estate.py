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

from dataclasses import dataclass, field, replace
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
    gui_url: str = ""
    """Management GUI, where the device has one. Empty means the tool offers no GUI
    link rather than inventing a URL that may not answer."""

    ssh_user: str = ""
    """The account **the operator** logs in as. Never the monitor's account, and never
    a credential — this is only what to prefill in their own SSH client."""

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

    upstreams: tuple[str, ...] = ()
    """Names of the routers this interface peers with. Normally set on the WAN.

    Declared, not inferred. Drawing a line from every firewall to every router looks
    like knowledge and is a guess: which router an enclave actually peers with decides
    whether a routing rule covers the adjacency it needs, and the tool has no business
    inventing that. An interface with none declared is drawn unconnected, which is
    visible and therefore fixable."""


@dataclass(frozen=True, slots=True)
class Host:
    hostname: str
    os: str = ""
    """What it runs, as the operator would say it — `Windows 10 22H2`, `Ubuntu 24.04`.

    Free text on purpose. It drives nothing automatically; it is there because the
    person deciding whether RDP or SSH belongs on a box needs to know which it is."""

    services: tuple[str, ...] = ()
    """Named services from the catalogue. What this host actually runs, which is not
    the same question as what is *scored* on it."""

    v4: IPv4Address | None = None
    v6: IPv6Address | None = None
    segment_role: str = ""
    service_role: str = ""
    """The host type. From `service-catalogue.yaml` hostname patterns as a suggestion,
    confirmed by the operator."""

    group: str = ""
    """The host group this was expanded from, if any. Empty for a host declared alone."""

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
    """The short code, as it appears in the FQDN and in generated rule descriptions —
    `do`. Free-form: the tool has no list of valid enclaves and must never acquire one."""

    fqdn: str
    node: Node
    display_name: str = ""
    """What the enclave is actually called — `Deployed Official`. Shown wherever there
    is room; the short code is what appears in a rule description, where there is not."""

    side: str = ""
    """Operator-declared grouping label, where an estate has one.

    Derive it from the **WAN address**, never from internal ranges — `SPEC.md` §4.2.
    A firewall can sit on one side while its internal segments address into another,
    so inferring from internals gets those cases backwards."""
    config_version: str = ""
    """Must be `23.3` — `V-CONFIG-VERSION` blocks otherwise."""

    interfaces: tuple[Interface, ...] = ()
    hosts: tuple[Host, ...] = ()
    host_groups: tuple[HostGroup, ...] = ()
    """Declared groups. `all_hosts()` is what everything else should read."""

    aliases: tuple[Alias, ...] = ()
    rules: tuple[Rule, ...] = ()
    nat: NatConfig = field(default_factory=NatConfig)
    baseline_sha256: str = ""
    """Binds generated output to one firewall identity. A mismatched import is
    refused, not warned — `SPEC.md` §7.4."""

    def _template_services(self, catalogue: object, host_type: str) -> tuple[str, ...]:
        """What a template says a machine runs. Empty when there is no template.

        `catalogue` is loosely typed on purpose: the estate model is read by the
        generator, the monitor and the topology alike, and none of them should have to
        carry a service catalogue just to list hosts.
        """
        if catalogue is None or not host_type:
            return ()
        kind = getattr(catalogue, "host_types", {}).get(host_type)
        return tuple(kind.services) if kind is not None else ()

    def all_hosts(self, catalogue: object = None) -> tuple[Host, ...]:
        """Individually declared hosts plus every host expanded from a group.

        Everything downstream reads this rather than `hosts`, so a machine declared in
        a group of ten is as real as one typed in alone.

        **An empty service list means "whatever the template says", for a single
        machine exactly as for a group.** Groups already worked that way and the rules
        relied on it; individually declared hosts did not, so a host carrying a template
        and no services of its own generated no service rules at all while every screen
        showed the template's set. Whichever way that inconsistency is resolved, it has
        to be resolved in one place — this is it. To say a machine runs nothing, clear
        its template as well.
        """
        expanded: list[Host] = [
            host
            if host.services
            else replace(
                host,
                services=self._template_services(catalogue, host.service_role),
            )
            for host in self.hosts
        ]
        for group in self.host_groups:
            expanded.extend(
                group.expand(self._template_services(catalogue, group.host_type))
            )
        return tuple(expanded)

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
    """The team's number. It appears in almost every address in the range."""

    team_name: str = ""
    """What the team calls itself — `BT14`. Display only; nothing keys on it."""

    team_padded: str = ""
    """The team number as it appears in host and domain names, where that differs.

    For most teams it does not: team 14 is `14` in both. It matters only for a
    single-digit team, where the documents write the number unpadded in addresses and
    zero-padded in names — and whether that is really true is `OPEN-QUESTIONS.md` Q3,
    still open. Derived by `padded_default()` unless the operator says otherwise, so
    nobody is asked a question they cannot answer."""

    role_vocabulary: tuple[str, ...] = ()
    """The kinds of network segment this range has — workstations, servers, DMZ.

    Not the pfSense interface names. `lan` is workstations on most enclaves and servers
    on at least one, so the segment a rule is *about* has to be named separately from
    the interface it happens to sit on. Empty means nothing has been declared yet, not
    "anything goes": an interface whose segment is outside this set surfaces for a
    decision rather than being guessed."""

    firewalls: tuple[Firewall, ...] = ()
    nodes: tuple[Node, ...] = ()
    """Every managed node, routers included. Firewalls appear here too, via
    `Firewall.node`, so the monitor has one list to poll."""

    shared_aliases: tuple[Alias, ...] = ()
    dependencies: tuple[CrossEnclaveDep, ...] = ()

    @property
    def label(self) -> str:
        """What to call this range on screen."""
        return self.team_name or f"team {self.team}"

    def padded_default(self) -> str:
        """The team number as it usually appears in names: zero-padded to two digits."""
        return self.team_padded or f"{self.team:02d}"

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


@dataclass(frozen=True, slots=True)
class HostGroup:
    """Many machines of one kind, declared once.

    An estate is a few kinds of machine repeated: ten Windows 10 workstations, five
    Ubuntu desktops, two domain controllers. Declaring each by hand is tedious, and
    tedium is how a host gets missed — and a host nobody declared is a host whose
    ports nobody opened.

    Expansion is deliberate and visible rather than implicit: the group produces real
    hosts that appear individually everywhere else in the tool, so a rule, a scoring
    assertion or a topology node always refers to one machine.
    """

    name_prefix: str
    """`ws1` gives `ws101`, `ws102`… when `first_index` is 01. Written as the operator
    writes it on the diagram."""

    count: int = 1
    first_index: int = 1
    index_width: int = 2
    segment_role: str = ""
    host_type: str = ""
    os: str = ""
    v4_start: IPv4Address | None = None
    v6_start: IPv6Address | None = None
    v6_prefix: str = ""
    """Mirrors the v4 host octet into the v6 address rather than counting.

    The observed range addresses `25.X.17.13` as `fd81:25:X:17::13` — the last group
    is the v4 octet written out, not the thirteenth address in the block. Counting
    from a start address gives `::d` for the thirteenth host, which is a different
    machine. Set this to `fd81:25:42:17` and the group reproduces the real convention;
    leave it empty and `v6_start` counts."""

    services: tuple[str, ...] = ()
    """Overrides the host type's services when set. Empty means use the type's."""

    out_of_bounds: bool = False
    note: str = ""

    def __post_init__(self) -> None:
        if self.count < 1:
            raise ValueError(f"{self.name_prefix}: a group of {self.count} hosts is not a group")
        if self.count > 512:
            raise ValueError(
                f"{self.name_prefix}: {self.count} hosts in one group. That is almost "
                "certainly a typo in the count or the address range."
            )

    def names(self) -> tuple[str, ...]:
        return tuple(
            f"{self.name_prefix}{str(self.first_index + n).zfill(self.index_width)}"
            for n in range(self.count)
        )

    def _v6_for(self, v4: IPv4Address | None, offset: int) -> IPv6Address | None:
        if self.v6_prefix and v4 is not None:
            last_octet = str(v4).rsplit(".", 1)[-1]
            try:
                return IPv6Address(f"{self.v6_prefix}::{last_octet}")
            except ValueError:
                return None
        if self.v6_start is not None:
            return self.v6_start + offset
        return None

    def expand(self, catalogue_services: tuple[str, ...] = ()) -> tuple[Host, ...]:
        """The individual machines. Addresses run consecutively from the start address.

        A group with no start address still expands — the hosts exist and are visible,
        they simply have nothing to address yet, which is a state the operator can see
        and fix rather than one that silently drops them.
        """
        services = self.services or catalogue_services
        hosts = []
        for offset, name in enumerate(self.names()):
            v4 = self.v4_start + offset if self.v4_start is not None else None
            v6 = self._v6_for(v4, offset)
            hosts.append(
                Host(
                    hostname=name,
                    os=self.os,
                    services=services,
                    v4=v4,
                    v6=v6,
                    segment_role=self.segment_role,
                    service_role=self.host_type,
                    group=self.name_prefix,
                    out_of_bounds=self.out_of_bounds,
                    source_of_truth=SourceOfTruth.WIZARD,
                )
            )
        return tuple(hosts)
