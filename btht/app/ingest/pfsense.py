"""pfSense configuration ingest — `SPEC.md` §5.4.

Reads `<aliases>`, `<filter>` and `<nat>`, plus a short fixed fact list, and
**retains nothing else**. A source configuration carries password hashes, the
webConfigurator private key, SSH keys and cleartext service passwords in the same
file; none of it is read, stored or emitted. The allow-list below is the whole of
what this module will look at, and it is deliberately boring to audit.

Accepts a full export or the partial section exports that `WORKFLOW.md` §5
recommends, which is the path where no credential material leaves the box at all.
Missing sections are recorded rather than invented.

Interface tokens are carried through exactly as they appear. Mapping them to role
tokens is Phase 1.2's job and needs the operator's declared vocabulary, which this
module does not have and must not guess.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass
from ipaddress import IPv4Interface, IPv6Interface, ip_address, ip_network
from pathlib import Path

from btht.app.model.rules import (
    Action,
    Alias,
    AliasRef,
    AliasType,
    AnyEndpoint,
    Direction,
    Endpoint,
    Family,
    HostAddress,
    InterfaceNet,
    NatConfig,
    NatRule,
    Negated,
    Network,
    PortSpec,
    Rule,
    SelfEndpoint,
)

#: Everything this module is permitted to read. Anything not named here is not
#: looked at, which is easier to verify than a list of things to avoid.
READS = (
    "aliases",
    "filter",
    "nat",
    "interfaces",
    "version",
    "system/noantilockout",
    "system/webgui/noantilockout",
    "syslog/filterdescriptions",
    "installedpackages/frr",
)


class ParseError(Exception):
    """The input is not a configuration this tool will guess about."""


def pf_bool(element: ET.Element | None) -> bool:
    """pfSense boolean, per `BASELINE-ANALYSIS.md` §1: empty element is False, `yes` is True.

    Presence means nothing. Read the other way round, the tool reports anti-lockout
    as disabled on every real configuration.
    """
    if element is None:
        return False
    return (element.text or "").strip().lower() == "yes"


def pf_flag_present(element: ET.Element | None) -> bool:
    """The *other* pfSense convention, where an empty element means the flag is set.

    Rule-level `<disabled>` is written this way by the GUI. It contradicts `pf_bool`,
    which is why the two are separate named functions rather than one that guesses:
    the reader can see which convention a given field was parsed under.

    Unverified against a live box — `OPEN-QUESTIONS.md` Q12. Erring towards "the rule
    is disabled" is the safe direction: it surfaces in triage rather than silently
    treating an inactive rule as live.
    """
    return element is not None


@dataclass(frozen=True, slots=True)
class RawInterface:
    """An interface exactly as the configuration states it. No role derived yet."""

    ifname: str
    nic: str
    descr: str
    v4: IPv4Interface | None = None
    v6: IPv6Interface | None = None
    enabled: bool = False


@dataclass(frozen=True, slots=True)
class PlatformFacts:
    """The fixed fact list of `SPEC.md` §5.4. Nothing here is credential material."""

    config_version: str = ""
    antilockout_enabled: bool = True
    """Note the inversion: the element is `noantilockout`, so an empty element means
    anti-lockout is **on**. `H-PF-01` turns on this being read correctly."""

    filter_descriptions: bool = False
    """`<filterdescriptions>`. When set, the firewall log names the matching rule,
    which is how a team debugs at speed."""

    frr_bfd_peers: tuple[str, ...] = ()
    frr_ospf_router_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ParsedConfig:
    facts: PlatformFacts
    interfaces: tuple[RawInterface, ...] = ()
    aliases: tuple[Alias, ...] = ()
    rules: tuple[Rule, ...] = ()
    nat: NatConfig = NatConfig()
    sections_present: frozenset[str] = frozenset()
    """Which of `aliases` / `filter` / `nat` / `interfaces` the input actually held.
    A partial export is normal; a silently empty section is not."""


# --- endpoints -------------------------------------------------------------


def _looks_like_address(text: str) -> bool:
    try:
        ip_address(text)
    except ValueError:
        return False
    return True


def _looks_like_network(text: str) -> bool:
    try:
        ip_network(text, strict=False)
    except ValueError:
        return False
    return "/" in text


def _endpoint(node: ET.Element | None) -> tuple[Endpoint, tuple[PortSpec, ...]]:
    """Parse one `<source>` or `<destination>` into an endpoint and its ports."""
    if node is None:
        return AnyEndpoint(), ()

    ports = _ports(node.findtext("port"))
    inner: Endpoint

    if node.find("any") is not None:
        inner = AnyEndpoint()
    elif (network := node.findtext("network")) is not None:
        text = network.strip()
        if text == "(self)":
            inner = SelfEndpoint()
        elif _looks_like_network(text):
            inner = Network(ip_network(text, strict=False))
        else:
            # An interface token — `lan`, `opt1`, or `lanip`. Carried through as
            # written; 1.2 maps it to the operator's role.
            inner = InterfaceNet(text)
    elif (address := node.findtext("address")) is not None:
        text = address.strip()
        if _looks_like_network(text):
            inner = Network(ip_network(text, strict=False))
        elif _looks_like_address(text):
            inner = HostAddress(ip_address(text))
        else:
            inner = AliasRef(text)
    else:
        inner = AnyEndpoint()

    if node.find("not") is not None:
        inner = Negated(inner)
    return inner, ports


def _ports(text: str | None) -> tuple[PortSpec, ...]:
    """`53` and `53-53` both normalise to one spec. An alias name yields nothing here."""
    if not text:
        return ()
    raw = text.strip()
    try:
        if "-" in raw:
            low, high = raw.split("-", 1)
            return (PortSpec(int(low), int(high)),)
        return (PortSpec(int(raw), int(raw)),)
    except ValueError:
        # A port alias. Resolution needs the alias table, which is §6.1's job.
        return ()


# --- sections --------------------------------------------------------------


def _interfaces(root: ET.Element) -> tuple[RawInterface, ...]:
    node = root.find("interfaces")
    if node is None:
        return ()
    out: list[RawInterface] = []
    for iface in node:
        v4 = None
        v6 = None
        addr = (iface.findtext("ipaddr") or "").strip()
        mask = (iface.findtext("subnet") or "").strip()
        if addr and mask and _looks_like_address(addr):
            v4 = IPv4Interface(f"{addr}/{mask}")
        addr6 = (iface.findtext("ipaddrv6") or "").strip()
        mask6 = (iface.findtext("subnetv6") or "").strip()
        if addr6 and mask6 and _looks_like_address(addr6):
            v6 = IPv6Interface(f"{addr6}/{mask6}")
        out.append(
            RawInterface(
                ifname=iface.tag,
                nic=(iface.findtext("if") or "").strip(),
                descr=(iface.findtext("descr") or "").strip(),
                v4=v4,
                v6=v6,
                enabled=iface.find("enable") is not None,
            )
        )
    return tuple(out)


def _aliases(root: ET.Element) -> tuple[Alias, ...]:
    node = root.find("aliases")
    if node is None:
        return ()
    out: list[Alias] = []
    for alias in node.findall("alias"):
        raw_type = (alias.findtext("type") or "").strip().lower()
        try:
            alias_type = AliasType(raw_type)
        except ValueError as exc:
            raise ParseError(
                f"alias {alias.findtext('name')!r}: unknown type {raw_type!r}"
            ) from exc
        entries = tuple((alias.findtext("address") or "").split())
        detail = tuple((alias.findtext("detail") or "").split("||"))
        out.append(
            Alias(
                name=(alias.findtext("name") or "").strip(),
                type=alias_type,
                entries=entries,
                descr=(alias.findtext("descr") or "").strip(),
                detail=tuple(d for d in detail if d),
            )
        )
    return tuple(out)


#: What a rule bound to every interface says. The shipped floating rules use this
#: rather than naming each interface, which a comma-split silently turns into a single
#: interface literally called "any" — a rule that then matches nothing anywhere.
ANY_INTERFACE = "any"


def _interface_tokens(raw: str) -> tuple[str, ...]:
    """`wan,lan,opt1` or `any`. Both appear in real configurations."""
    text = raw.strip()
    if not text:
        return ()
    if text.lower() == ANY_INTERFACE:
        return (ANY_INTERFACE,)
    return tuple(part.strip() for part in text.split(",") if part.strip())


def _rules(root: ET.Element) -> tuple[Rule, ...]:
    node = root.find("filter")
    if node is None:
        return ()
    out: list[Rule] = []
    for rule in node.findall("rule"):
        raw_action = (rule.findtext("type") or "").strip().lower()
        try:
            action = Action(raw_action)
        except ValueError as exc:
            raise ParseError(f"rule: unknown action {raw_action!r}") from exc

        raw_family = (rule.findtext("ipprotocol") or "inet").strip().lower()
        try:
            family = Family(raw_family)
        except ValueError as exc:
            raise ParseError(f"rule: unknown ipprotocol {raw_family!r}") from exc

        raw_direction = (rule.findtext("direction") or "in").strip().lower()
        direction = Direction(raw_direction) if raw_direction in set(Direction) else Direction.IN

        source, source_ports = _endpoint(rule.find("source"))
        destination, destination_ports = _endpoint(rule.find("destination"))

        icmp = (rule.findtext("icmptype") or "").strip()
        out.append(
            Rule(
                action=action,
                interfaces=_interface_tokens(rule.findtext("interface") or ""),
                family=family,
                direction=direction,
                quick=pf_bool(rule.find("quick")),
                floating=pf_bool(rule.find("floating")),
                protocol=(rule.findtext("protocol") or "").strip() or None,
                icmp_types=tuple(sorted(p.strip() for p in icmp.split(",") if p.strip())),
                state_type=(rule.findtext("statetype") or "").strip(),
                source=source,
                destination=destination,
                source_ports=source_ports,
                destination_ports=destination_ports,
                descr=(rule.findtext("descr") or "").strip(),
                tracker=(rule.findtext("tracker") or "").strip() or None,
                log=pf_flag_present(rule.find("log")),
                disabled=pf_flag_present(rule.find("disabled")),
            )
        )
    return tuple(out)


def _nat(root: ET.Element) -> NatConfig:
    node = root.find("nat")
    if node is None:
        return NatConfig()
    mode = (node.findtext("outbound/mode") or "disabled").strip() or "disabled"
    forwards: list[NatRule] = []
    for rule in node.findall("rule"):
        source, _ = _endpoint(rule.find("source"))
        destination, destination_ports = _endpoint(rule.find("destination"))
        target_text = (rule.findtext("target") or "").strip()
        target = HostAddress(ip_address(target_text)) if _looks_like_address(target_text) else None
        local_text = (rule.findtext("local-port") or "").strip()
        forwards.append(
            NatRule(
                interface=(rule.findtext("interface") or "").strip(),
                protocol=(rule.findtext("protocol") or "").strip() or None,
                source=source,
                destination=destination,
                destination_ports=destination_ports,
                target=target,
                local_port=int(local_text) if local_text.isdigit() else None,
                descr=(rule.findtext("descr") or "").strip(),
                disabled=pf_flag_present(rule.find("disabled")),
            )
        )
    return NatConfig(outbound_mode=mode, port_forwards=tuple(forwards))


def _facts(root: ET.Element) -> PlatformFacts:
    """The fixed fact list, and nothing beyond it."""
    noantilockout = root.find("system/noantilockout")
    if noantilockout is None:
        noantilockout = root.find("system/webgui/noantilockout")

    # `frrbfdpeers` and `frrospfd` are siblings of `frr` under `installedpackages`,
    # not children of it. Nesting them cost nothing visible — the peer list simply
    # came back empty, and `V-ROUTING-PEERS` would have stayed silent on every real
    # configuration while looking like it had checked.
    peers = tuple(
        (p.text or "").strip()
        for p in root.findall("installedpackages/frrbfdpeers/config/peer")
        if (p.text or "").strip()
    )
    router_ids = tuple(
        (r.text or "").strip()
        for r in root.findall("installedpackages/")
        if r.tag.startswith("frrospf")
        for r in r.findall("config/routerid")
        if (r.text or "").strip()
    )
    return PlatformFacts(
        config_version=(root.findtext("version") or "").strip(),
        antilockout_enabled=not pf_bool(noantilockout),
        filter_descriptions=(root.findtext("syslog/filterdescriptions") or "").strip() == "1",
        frr_bfd_peers=peers,
        frr_ospf_router_ids=router_ids,
    )


# --- entry points ----------------------------------------------------------


def parse_string(text: str) -> ParsedConfig:
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ParseError(f"not well-formed XML: {exc}") from exc
    if root.tag != "pfsense":
        raise ParseError(f"root element is {root.tag!r}, expected 'pfsense'")

    present = {
        name for name in ("aliases", "filter", "nat", "interfaces") if root.find(name) is not None
    }
    return ParsedConfig(
        facts=_facts(root),
        interfaces=_interfaces(root),
        aliases=_aliases(root),
        rules=_rules(root),
        nat=_nat(root),
        sections_present=frozenset(present),
    )


def parse_file(path: Path) -> ParsedConfig:
    return parse_string(path.read_text(encoding="utf-8"))
