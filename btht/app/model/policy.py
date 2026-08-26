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
