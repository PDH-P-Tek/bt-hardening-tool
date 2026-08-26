"""The estate document — the durable artefact, and the tool's source of truth.

`SPEC.md` §9. YAML, human-editable, diffable, one per team. Everything the operator
declares on day one lives here: which enclaves exist and what they are called, what
each device is and which platform it runs, how to reach it, what its interfaces are
and what each segment is for, and what the hosts run.

Two consumers, one file. The generator reads it to know what it is writing rules for;
the monitor reads it to know what to poll (`MONITORING.md` §11). Declaring the estate
twice is how the two halves would drift into disagreeing about what the estate is.

**Save is deterministic.** Same document, byte-identical YAML, so a diff between two
saves shows what the operator changed and nothing else.

Policy — the rules the operator wants — arrives here at Phase 2.3. This module carries
the inventory it will hang from.
"""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Interface, IPv6Interface, ip_address, ip_interface, ip_network
from pathlib import Path
from typing import Any

import yaml

from btht.app.ingest.roles import RoleConvention, SideRule
from btht.app.model.estate import (
    CrossEnclaveDep,
    Estate,
    Firewall,
    Host,
    Interface,
    Node,
    Platform,
    SourceOfTruth,
)

SCHEMA_VERSION = 1


class EstateFileError(Exception):
    """The document says something the tool will not silently interpret."""


# --- reading ---------------------------------------------------------------


def _interface(data: dict[str, Any]) -> Interface:
    v4 = data.get("v4")
    v6 = data.get("v6")
    return Interface(
        ifname=str(data["ifname"]),
        role=str(data.get("role", "")),
        descr=str(data.get("descr", "")),
        nic=str(data.get("nic", "")),
        v4=IPv4Interface(str(v4)) if v4 else None,
        v6=IPv6Interface(str(v6)) if v6 else None,
        is_lan=bool(data.get("is_lan", False)),
    )


def _host(data: dict[str, Any]) -> Host:
    v4 = data.get("v4")
    v6 = data.get("v6")
    return Host(
        hostname=str(data["hostname"]),
        v4=ip_address(str(v4)) if v4 else None,  # type: ignore[arg-type]
        v6=ip_address(str(v6)) if v6 else None,  # type: ignore[arg-type]
        segment_role=str(data.get("segment_role", "")),
        service_role=str(data.get("service_role", "")),
        isa_checks=tuple(str(c) for c in data.get("isa_checks", ())),
        out_of_bounds=bool(data.get("out_of_bounds", False)),
        source_of_truth=SourceOfTruth(str(data.get("source_of_truth", "wizard"))),
    )


def _node(data: dict[str, Any], enclave: str | None = None) -> Node:
    try:
        platform = Platform(str(data["platform"]))
    except ValueError as exc:
        raise EstateFileError(
            f"{data.get('name', '?')}: unknown platform {data.get('platform')!r}. "
            f"Supported: {', '.join(p.value for p in Platform)}"
        ) from exc
    return Node(
        name=str(data["name"]),
        platform=platform,
        mgmt_address=ip_address(str(data["mgmt_address"])),
        credential_ref=str(data.get("credential_ref", "")),
        enclave=str(data.get("enclave", enclave)) if (data.get("enclave") or enclave) else None,
        gui_url=str(data.get("gui_url", "")),
        ssh_user=str(data.get("ssh_user", "")),
        poll_seconds=int(data.get("poll_seconds", 60)),
    )


def _firewall(enclave_name: str, data: dict[str, Any]) -> Firewall:
    node_data = dict(data.get("node") or {})
    node_data.setdefault("name", data.get("fqdn", enclave_name))
    return Firewall(
        enclave=enclave_name,
        fqdn=str(data.get("fqdn", "")),
        node=_node(node_data, enclave=enclave_name),
        side=str(data.get("side", "")),
        config_version=str(data.get("config_version", "")),
        interfaces=tuple(_interface(i) for i in data.get("interfaces", ())),
        hosts=tuple(_host(h) for h in data.get("hosts", ())),
        baseline_sha256=str(data.get("baseline_sha256", "")),
    )


def load_estate(path: Path) -> Estate:
    data: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    version = int(data.get("version", 0))
    if version != SCHEMA_VERSION:
        raise EstateFileError(
            f"{path.name}: schema version {version}, this tool writes {SCHEMA_VERSION}"
        )

    firewalls: list[Firewall] = []
    nodes: list[Node] = []
    for enclave in data.get("enclaves", ()):
        name = str(enclave["name"])
        if enclave.get("firewall"):
            firewalls.append(_firewall(name, enclave["firewall"]))
        for node in enclave.get("nodes", ()):
            nodes.append(_node(node, enclave=name))

    roles = data.get("interface_roles", {}) or {}
    return Estate(
        team=int(data.get("team", 0)),
        team_padded=str(data.get("team_padded", "")),
        role_vocabulary=tuple(str(r) for r in roles.get("recognised", ())),
        firewalls=tuple(firewalls),
        nodes=tuple(nodes),
        dependencies=tuple(
            CrossEnclaveDep(
                source_enclave=str(d.get("from", "")),
                dest_enclave=str(d.get("to", "")),
                dest_host=str(d.get("host", "")),
                ports=tuple(int(p) for p in d.get("ports", ())),
                why=str(d.get("why", "")),
            )
            for d in data.get("dependencies", ())
        ),
    )


def convention_of(path: Path) -> RoleConvention:
    """The declared naming convention, for the role derivation of `SPEC.md` §4.1."""
    data: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    roles = data.get("interface_roles", {}) or {}
    return RoleConvention(
        vocabulary=tuple(str(r) for r in roles.get("recognised", ())),
        enclave_tokens=tuple(str(t) for t in roles.get("enclave_tokens", ())),
    )


def side_rules_of(path: Path) -> tuple[SideRule, ...]:
    data: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return tuple(
        SideRule(network=ip_network(str(s["network"]), strict=False), label=str(s["label"]))
        for s in data.get("sides", ())
    )


# --- writing ---------------------------------------------------------------


def _interface_out(iface: Interface) -> dict[str, Any]:
    out: dict[str, Any] = {"ifname": iface.ifname, "role": iface.role}
    if iface.descr:
        out["descr"] = iface.descr
    if iface.nic:
        out["nic"] = iface.nic
    if iface.v4:
        out["v4"] = str(iface.v4)
    if iface.v6:
        out["v6"] = str(iface.v6)
    if iface.is_lan:
        out["is_lan"] = True
    return out


def _host_out(host: Host) -> dict[str, Any]:
    out: dict[str, Any] = {"hostname": host.hostname}
    if host.v4:
        out["v4"] = str(host.v4)
    if host.v6:
        out["v6"] = str(host.v6)
    for key, value in (
        ("segment_role", host.segment_role),
        ("service_role", host.service_role),
    ):
        if value:
            out[key] = value
    if host.isa_checks:
        out["isa_checks"] = list(host.isa_checks)
    if host.out_of_bounds:
        out["out_of_bounds"] = True
    out["source_of_truth"] = host.source_of_truth.value
    return out


def _node_out(node: Node) -> dict[str, Any]:
    out: dict[str, Any] = {
        "name": node.name,
        "platform": node.platform.value,
        "mgmt_address": str(node.mgmt_address),
    }
    if node.credential_ref:
        out["credential_ref"] = node.credential_ref
    if node.gui_url:
        out["gui_url"] = node.gui_url
    if node.ssh_user:
        out["ssh_user"] = node.ssh_user
    if node.poll_seconds != 60:
        out["poll_seconds"] = node.poll_seconds
    return out


def estate_to_document(
    estate: Estate,
    enclave_tokens: tuple[str, ...] = (),
    sides: tuple[SideRule, ...] = (),
) -> dict[str, Any]:
    """The document form. Ordered for a human reading the diff, not for a parser."""
    by_enclave: dict[str, dict[str, Any]] = {}
    for firewall in estate.firewalls:
        entry = by_enclave.setdefault(firewall.enclave, {"name": firewall.enclave})
        fw: dict[str, Any] = {"fqdn": firewall.fqdn, "node": _node_out(firewall.node)}
        if firewall.side:
            fw["side"] = firewall.side
        if firewall.config_version:
            fw["config_version"] = firewall.config_version
        if firewall.baseline_sha256:
            fw["baseline_sha256"] = firewall.baseline_sha256
        fw["interfaces"] = [_interface_out(i) for i in firewall.interfaces]
        if firewall.hosts:
            fw["hosts"] = [_host_out(h) for h in firewall.hosts]
        entry["firewall"] = fw

    for node in estate.nodes:
        entry = by_enclave.setdefault(node.enclave or "", {"name": node.enclave or ""})
        entry.setdefault("nodes", []).append(_node_out(node))

    document: dict[str, Any] = {
        "version": SCHEMA_VERSION,
        "team": estate.team,
        "team_padded": estate.team_padded,
        "interface_roles": {
            "recognised": list(estate.role_vocabulary),
            "enclave_tokens": list(enclave_tokens),
        },
    }
    if sides:
        document["sides"] = [{"network": str(s.network), "label": s.label} for s in sides]
    document["enclaves"] = [by_enclave[name] for name in sorted(by_enclave)]
    if estate.dependencies:
        document["dependencies"] = [
            {
                "from": d.source_enclave,
                "to": d.dest_enclave,
                "host": d.dest_host,
                "ports": list(d.ports),
                "why": d.why,
            }
            for d in estate.dependencies
        ]
    return document


def save_estate(
    estate: Estate,
    path: Path,
    enclave_tokens: tuple[str, ...] = (),
    sides: tuple[SideRule, ...] = (),
) -> None:
    """Write the document. Deterministic: the same estate always writes the same bytes."""
    document = estate_to_document(estate, enclave_tokens, sides)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump(document, sort_keys=False, default_flow_style=False, allow_unicode=True),
        encoding="utf-8",
    )


def interface_from_parsed(ifname: str, role: str, raw: Any) -> Interface:
    """Build an interface from a parsed configuration, for the import accelerator."""
    return Interface(
        ifname=ifname,
        role=role,
        descr=getattr(raw, "descr", ""),
        nic=getattr(raw, "nic", ""),
        v4=getattr(raw, "v4", None),
        v6=getattr(raw, "v6", None),
        is_lan=ifname == "lan",
    )


def parse_address(text: str) -> Any:
    """Accept either a bare address or one with a prefix, as a person would type it."""
    raw = text.strip()
    if not raw:
        return None
    return ip_interface(raw) if "/" in raw else ip_address(raw)


# ===========================================================================
#  Policy — what the operator wants permitted
# ===========================================================================
#
# The inventory above says what the estate *is*. This says what it should *do*.
# Both live in one document because a policy that refers to a segment the estate
# does not have is a mistake worth catching at load, not at generation.
#
# Only enclave policy is declared. The management, scoring and essential-services
# blocks and the trailing deny are generated in the right positions — hand-writing
# them is how a rule ends up below the catch-all that was supposed to be beneath it.


@dataclass(frozen=True, slots=True)
class Selector:
    """Who a rule applies to. Empty means unset, which is never read as `any`."""

    any: bool = False
    alias: str = ""
    host: str = ""
    segments: tuple[str, ...] = ()
    enclaves: tuple[str, ...] = ()

    @property
    def declared(self) -> bool:
        return bool(self.any or self.alias or self.host or self.segments or self.enclaves)


@dataclass(frozen=True, slots=True)
class ServiceRule:
    """One thing that must work. The unit the operator actually thinks in."""

    name: str
    segment: str = ""
    host: str = ""
    alias: str = ""
    protocol: str = "tcp"
    ports: tuple[int, ...] = ()
    source: Selector = Selector()
    notes: str = ""


@dataclass(frozen=True, slots=True)
class EgressAllow:
    source: Selector = Selector()
    destination: Selector = Selector()
    protocol: str = "tcp"
    ports: tuple[int, ...] = ()


@dataclass(frozen=True, slots=True)
class EgressPolicy:
    default: str = "deny_and_log"
    allow: tuple[EgressAllow, ...] = ()
    notes: str = ""


@dataclass(frozen=True, slots=True)
class PolicyAlias:
    name: str
    type: str = "network"
    entries: tuple[str, ...] = ()
    nested_aliases: tuple[str, ...] = ()
    segments: tuple[str, ...] = ()
    lockout_critical: bool = False
    descr: str = ""

    @property
    def is_empty(self) -> bool:
        return not (self.entries or self.nested_aliases or self.segments)


@dataclass(frozen=True, slots=True)
class Dependency:
    """A path between enclaves, declared once.

    The generator emits the egress rule on the source firewall *and* the ingress rule
    on the destination, so the pair cannot drift apart. `V-CROSS-ENCLAVE-ORPHAN` fires
    if one later goes missing.
    """

    name: str
    from_enclaves: tuple[str, ...] = ()
    from_segments: tuple[str, ...] = ()
    to_enclave: str = ""
    to_alias: str = ""
    to_host: str = ""
    protocol: str = "tcp"
    ports: tuple[int, ...] = ()
    notes: str = ""


@dataclass(frozen=True, slots=True)
class Options:
    mandatory_blocks_placement: str = "floating"
    emit_separators: bool = True
    emit_trackers: bool = True
    dual_stack: str = "require"
    icmp6_minimum: tuple[int, ...] = (2, 128, 129, 133, 134, 135, 136)


@dataclass(frozen=True, slots=True)
class FirewallPolicy:
    enclave: str
    baseline: str = ""
    services: tuple[ServiceRule, ...] = ()
    egress: EgressPolicy = EgressPolicy()


@dataclass(frozen=True, slots=True)
class Policy:
    aliases: tuple[PolicyAlias, ...] = ()
    dependencies: tuple[Dependency, ...] = ()
    firewalls: tuple[FirewallPolicy, ...] = ()
    options: Options = Options()

    def for_enclave(self, enclave: str) -> FirewallPolicy | None:
        for entry in self.firewalls:
            if entry.enclave == enclave:
                return entry
        return None


def _selector(value: Any) -> Selector:
    if value in (None, ""):
        return Selector()
    if value == "any":
        return Selector(any=True)
    if isinstance(value, dict):
        enclave = value.get("enclave")
        return Selector(
            any=bool(value.get("any", False)),
            alias=str(value.get("alias", "")),
            host=str(value.get("host", "")),
            segments=tuple(str(s) for s in value.get("segments", ())),
            enclaves=(
                (str(enclave),) if enclave else tuple(str(e) for e in value.get("enclaves", ()))
            ),
        )
    raise EstateFileError(f"policy: cannot read selector {value!r}")


def _ports(value: Any) -> tuple[int, ...]:
    ports = tuple(int(p) for p in value or ())
    for port in ports:
        if not 0 < port <= 65535:
            raise EstateFileError(f"policy: port {port} is not a port")
    return ports


def _policy_alias(data: dict[str, Any]) -> PolicyAlias:
    plain: list[str] = []
    nested: list[str] = []
    segments: list[str] = []
    for entry in data.get("entries", ()) or ():
        if isinstance(entry, dict):
            if "alias" in entry:
                nested.append(str(entry["alias"]))
            elif "segment" in entry:
                segments.append(str(entry["segment"]))
            else:
                raise EstateFileError(f"policy: cannot read alias entry {entry!r}")
        else:
            plain.append(str(entry))
    return PolicyAlias(
        name=str(data["name"]),
        type=str(data.get("type", "network")),
        entries=tuple(plain),
        nested_aliases=tuple(nested),
        segments=tuple(segments),
        lockout_critical=bool(data.get("lockout_critical", False)),
        descr=str(data.get("descr", "")),
    )


def load_policy(path: Path) -> Policy:
    data: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    options = data.get("options", {}) or {}

    firewalls: list[FirewallPolicy] = []
    for entry in data.get("firewalls", ()) or ():
        egress = entry.get("egress", {}) or {}
        firewalls.append(
            FirewallPolicy(
                enclave=str(entry["enclave"]),
                baseline=str(entry.get("baseline", "")),
                services=tuple(
                    ServiceRule(
                        name=str(s.get("name", "")),
                        segment=str(s.get("segment", "")),
                        host=str(s.get("host", "")),
                        alias=str(s.get("alias", "")),
                        protocol=str(s.get("protocol", "tcp")),
                        ports=_ports(s.get("ports")),
                        source=_selector(s.get("from")),
                        notes=str(s.get("notes", "")).strip(),
                    )
                    for s in entry.get("services", ()) or ()
                ),
                egress=EgressPolicy(
                    default=str(egress.get("default", "deny_and_log")),
                    allow=tuple(
                        EgressAllow(
                            source=_selector(a.get("from")),
                            destination=_selector(a.get("to")),
                            protocol=str(a.get("protocol", "tcp")),
                            ports=_ports(a.get("ports")),
                        )
                        for a in egress.get("allow", ()) or ()
                    ),
                    notes=str(egress.get("notes", "")).strip(),
                ),
            )
        )

    return Policy(
        aliases=tuple(_policy_alias(a) for a in data.get("aliases", ()) or ()),
        dependencies=tuple(
            Dependency(
                name=str(d.get("name", "")),
                from_enclaves=tuple(str(e) for e in (d.get("from", {}) or {}).get("enclaves", ())),
                from_segments=tuple(str(s) for s in (d.get("from", {}) or {}).get("segments", ())),
                to_enclave=str((d.get("to", {}) or {}).get("enclave", "")),
                to_alias=str((d.get("to", {}) or {}).get("alias", "")),
                to_host=str((d.get("to", {}) or {}).get("host", "")),
                protocol=str(d.get("protocol", "tcp")),
                ports=_ports(d.get("ports")),
                notes=str(d.get("notes", "")).strip(),
            )
            for d in data.get("dependencies", ()) or ()
        ),
        firewalls=tuple(firewalls),
        options=Options(
            mandatory_blocks_placement=str(options.get("mandatory_blocks_placement", "floating")),
            emit_separators=bool(options.get("emit_separators", True)),
            emit_trackers=bool(options.get("emit_trackers", True)),
            dual_stack=str(options.get("dual_stack", "require")),
            icmp6_minimum=tuple(int(t) for t in options.get("icmp6_minimum", ()) or ())
            or Options().icmp6_minimum,
        ),
    )


def validate_policy(policy: Policy, estate: Estate) -> list[str]:
    """Check the policy against the declared estate. Returns problems, in words.

    Every one of these is a case where generating anyway would produce a ruleset that
    looks right and is not: a rule for a segment that does not exist silently protects
    nothing, and an alias that resolves to nothing produces a rule matching nothing.
    Refusing beats generating something plausible — `SPEC.md` §2.
    """
    problems: list[str] = []
    enclaves = {fw.enclave for fw in estate.firewalls}
    segments_by_enclave = {fw.enclave: {i.role for i in fw.interfaces} for fw in estate.firewalls}
    all_segments = {role for roles in segments_by_enclave.values() for role in roles}
    alias_names = {a.name for a in policy.aliases}

    def check_selector(where: str, selector: Selector, enclave: str | None) -> None:
        if not selector.declared:
            problems.append(f"{where}: no source declared. 'any' has to be said out loud")
        if selector.alias and selector.alias not in alias_names:
            problems.append(f"{where}: alias {selector.alias!r} is not declared")
        known = segments_by_enclave.get(enclave or "", all_segments)
        for segment in selector.segments:
            if segment not in known:
                problems.append(
                    f"{where}: segment {segment!r} is not a segment of {enclave or 'this estate'}"
                )
        for name in selector.enclaves:
            if name not in enclaves:
                problems.append(f"{where}: enclave {name!r} is not in the estate")

    for entry in policy.firewalls:
        if entry.enclave not in enclaves:
            problems.append(f"policy for {entry.enclave!r}: no such enclave in the estate")
            continue
        segments = segments_by_enclave[entry.enclave]
        for service in entry.services:
            where = f"{entry.enclave}/{service.name or 'unnamed service'}"
            if not service.name:
                problems.append(f"{entry.enclave}: a service has no name to show the operator")
            if service.segment and service.segment not in segments:
                problems.append(
                    f"{where}: segment {service.segment!r} is not a segment of {entry.enclave}"
                )
            if service.alias and service.alias not in alias_names:
                problems.append(f"{where}: alias {service.alias!r} is not declared")
            if not service.ports:
                problems.append(f"{where}: no ports. An allow-all needs saying deliberately")
            check_selector(where, service.source, entry.enclave)

        if entry.egress.default not in ("deny_and_log", "deny", "allow"):
            problems.append(
                f"{entry.enclave}: egress default {entry.egress.default!r} is not one of "
                "deny_and_log, deny, allow"
            )
        for index, allow in enumerate(entry.egress.allow, start=1):
            where = f"{entry.enclave}/egress allow {index}"
            check_selector(where, allow.source, entry.enclave)
            check_selector(where, allow.destination, None)

    for dependency in policy.dependencies:
        where = f"dependency {dependency.name or '(unnamed)'}"
        for name in dependency.from_enclaves:
            if name not in enclaves:
                problems.append(f"{where}: source enclave {name!r} is not in the estate")
        if dependency.to_enclave and dependency.to_enclave not in enclaves:
            problems.append(
                f"{where}: destination enclave {dependency.to_enclave!r} is not in the estate"
            )
        if dependency.to_alias and dependency.to_alias not in alias_names:
            problems.append(f"{where}: alias {dependency.to_alias!r} is not declared")
        if not dependency.ports:
            problems.append(f"{where}: no ports declared")

    for alias in policy.aliases:
        for nested in alias.nested_aliases:
            if nested not in alias_names and nested not in {"Remote_Access", "Routers"}:
                problems.append(
                    f"alias {alias.name}: nests {nested!r}, which is neither declared here "
                    "nor a baseline alias"
                )
        for segment in alias.segments:
            if segment not in all_segments:
                problems.append(
                    f"alias {alias.name}: segment {segment!r} is not a segment of this estate"
                )

    return problems


def empty_aliases(policy: Policy) -> list[str]:
    """Aliases declared but not yet filled in.

    Not an error — the worked example ships several awaiting an answer from Green
    Team — but every one produces a rule that matches nothing, so it is surfaced
    rather than left to be discovered at scoring time.
    """
    return [alias.name for alias in policy.aliases if alias.is_empty]
