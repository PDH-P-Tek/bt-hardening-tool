"""Field definitions for every editable thing — Phase 9.7.

One description of what a form contains, used by both the add and the edit path. Before
this the same fields were written twice: once inline on the page and once on a separate
edit page, and the two drifted — the add form had router tick boxes while the edit form
still had a comma-separated text box for the same value.

A field is a dictionary rather than a class because a template reads it. The shapes:

    text        {name, label, value, hint, placeholder}
    select      + {options: [...]}, an option is a string or {value, label}
    checkboxes  + {checkboxes: [...]}, value is a list
    hidden      + {hidden: True} — submitted, never shown

A select may also carry `fills`: a map from option to the other fields that option
should populate. Picking a host template then fills in the operating system and ticks
the services it runs — which is the entire reason templates exist. It fills on change
only, never on load, so opening an existing host to edit it never quietly rewrites what
was already declared.
"""

from __future__ import annotations

from typing import Any

from btht.app.ingest.isa import Catalogue as IsaCatalogue
from btht.app.model.estate import Estate, Firewall, Host, HostGroup, Interface, Node
from btht.app.model.services import Catalogue, HostType, Service, services_for

Field = dict[str, Any]


def _template_fills(
    catalogue: Catalogue, isa: IsaCatalogue | None = None
) -> dict[str, dict[str, Any]]:
    """What each host template should put in the rest of the form.

    Includes the ISA scoring checks the role usually carries, so picking a template
    proposes them the same way it proposes services — `HOST` (the ICMP-reachability
    check) among them for anything the scoring bot pings.
    """
    return {
        name: {
            "os": kind.default_os,
            "services": list(kind.services),
            # From the template itself now, alongside its services — one place that
            # says what this kind of machine is, rather than a parallel role map.
            "isa_checks": list(kind.isa_checks),
        }
        for name, kind in catalogue.host_types.items()
    }


def _isa_field(
    name: str, value: list[str], isa: IsaCatalogue | None
) -> Field:
    """The scoring-check tick list. This is what makes a host reachable to the board —
    including ICMP, which is the `HOST` check and not a service you add by hand."""
    options = sorted(isa.checks) if isa is not None else []
    return {
        "name": name,
        "label": "Scoring checks (ISA board)",
        "value": value,
        "checkboxes": options,
        "hint": "What the ISA board tests on this machine. HOST is the ICMP ping — tick "
        "it for anything the scoring bot must see as up. Each ticked check emits a "
        "non-removable scoring rule."
        if options
        else "No ISA catalogue loaded, so no scoring checks can be assigned.",
    }


def _template_options(catalogue: Catalogue) -> list[Any]:
    """Templates named with the operating system they carry.

    An estate has several kinds of workstation that differ only by version, and
    `windows_workstation` on its own does not say which one you are about to create.
    The name is still what gets submitted — the OS is there to pick by.
    """
    options: list[Any] = [""]
    for name in sorted(catalogue.host_types):
        kind = catalogue.host_types[name]
        options.append(
            {"value": name, "label": f"{name} — {kind.default_os}" if kind.default_os else name}
        )
    return options


def _text(name: str, label: str, value: Any = "", **extra: Any) -> Field:
    field: Field = {"name": name, "label": label, "value": "" if value is None else str(value)}
    field.update(extra)
    return field


def interface_fields(estate: Estate, interface: Interface | None = None) -> list[Field]:
    routers = sorted(n.name for n in estate.nodes)
    return [
        _text(
            "ifname",
            "Interface name",
            interface.ifname if interface else "",
            hint="As pfSense shows it: wan, lan, opt1.",
            placeholder="opt1",
        ),
        {
            "name": "role",
            "label": "Segment",
            "value": interface.role if interface else "",
            "options": ["", *sorted(estate.role_vocabulary)],
            "hint": "What this segment is for. Manage the list under Segment types.",
        },
        _text(
            "v4",
            "IPv4 address and prefix",
            interface.v4 if interface else "",
            hint="CIDR notation.",
            placeholder="25.42.10.1/24",
        ),
        _text(
            "v6",
            "IPv6 address and prefix",
            interface.v6 if interface else "",
            placeholder="fd81:25:42:10::1/64",
        ),
        _text("descr", "Description", interface.descr if interface else ""),
        {
            "name": "upstreams",
            "label": "Peers with",
            "value": list(interface.upstreams) if interface else [],
            "checkboxes": routers,
            "hint": "Which routers this interface peers with. Normally the WAN.",
        },
    ]


def host_fields(
    catalogue: Catalogue,
    host: Host | None = None,
    segment: str = "",
    isa: IsaCatalogue | None = None,
) -> list[Field]:
    """`host` is None when adding, which changes two things.

    The template question comes second, straight after the name, because answering it
    fills in most of what follows — asking it last means typing the answers first. And
    the segment is not asked at all: you got here by opening a segment, so the machine
    goes on that one. It stays editable when amending an existing host, which is the
    only time moving one between segments makes sense.
    """
    adding = host is None
    return [
        _text("hostname", "Hostname", host.hostname if host else "", placeholder="dc01"),
        {
            "name": "host_type",
            "label": "What kind of machine is this?",
            "value": host.service_role if host else "",
            "options": _template_options(catalogue),
            "fills": _template_fills(catalogue, isa),
            "hint": "Picking one fills in the operating system and ticks what it runs, "
            "and proposes its scoring checks. Change anything afterwards — the template "
            "is a starting point.",
        },
        _text(
            "os",
            "Operating system",
            host.os if host else "",
            placeholder="Windows Server 2022",
        ),
        _text("v4", "IPv4", host.v4 if host else "", placeholder="25.42.10.11"),
        _text("v6", "IPv6", host.v6 if host else "", placeholder="fd81:25:42:10::11"),
        {
            "name": "segment_role",
            "label": "Segment",
            "value": host.segment_role if host else segment,
            "hidden": adding,
        },
        {
            "name": "services",
            "label": "Services it runs",
            # The template's set when nothing was declared, so opening an existing
            # machine shows what it actually runs rather than an empty list.
            "value": list(services_for(catalogue, host.service_role, host.services))
            if host
            else [],
            "checkboxes": sorted(catalogue.services),
            "hint": "Ports come from the service catalogue, so you pick RDP, not 3389.",
        },
        _isa_field("isa_checks", list(host.isa_checks) if host else [], isa),
        {
            "name": "out_of_bounds",
            "label": "Out of bounds",
            "value": "yes" if host and host.out_of_bounds else "",
            "options": ["", "yes"],
            "hint": "Must keep working, and never a policy target.",
        },
    ]


def group_fields(
    catalogue: Catalogue,
    group: HostGroup | None = None,
    segment: str = "",
    isa: IsaCatalogue | None = None,
) -> list[Field]:
    return [
        _text(
            "name_prefix",
            "Name prefix",
            group.name_prefix if group else "",
            hint="ws1 with first number 1 gives ws101, ws102…",
            placeholder="ws1",
        ),
        _text("count", "How many", group.count if group else 10),
        _text("first_index", "First number", group.first_index if group else 1),
        _text("index_width", "Digits in the number", group.index_width if group else 2),
        {
            "name": "host_type",
            "label": "What kind of machine are these?",
            "value": group.host_type if group else "",
            "options": _template_options(catalogue),
            "fills": _template_fills(catalogue, isa),
            "hint": "Picking one fills in the operating system, ticks what they run and "
            "proposes their scoring checks.",
        },
        _text("os", "Operating system", group.os if group else "", placeholder="Windows 10 22H2"),
        {
            "name": "segment_role",
            "label": "Segment",
            "value": group.segment_role if group else segment,
            "hidden": group is None,
        },
        _text(
            "v4_start",
            "First IPv4",
            group.v4_start if group else "",
            hint="The rest follow on consecutively.",
            placeholder="25.42.9.2",
        ),
        _text(
            "v6_prefix",
            "IPv6 prefix",
            group.v6_prefix if group else "",
            hint="Mirrors the v4 octet: 25.42.9.11 becomes fd81:25:42:9::11.",
            placeholder="fd81:25:42:9",
        ),
        {
            "name": "services",
            "label": "Services they run",
            "value": list(services_for(catalogue, group.host_type, group.services))
            if group
            else [],
            "checkboxes": sorted(catalogue.services),
            "hint": "Ports come from the service catalogue, so you pick RDP, not 3389.",
        },
        _isa_field("isa_checks", list(group.isa_checks) if group else [], isa),
    ]


def enclave_fields(platforms: list[str], firewall: Firewall | None = None) -> list[Field]:
    node = firewall.node if firewall else None
    return [
        _text(
            "display_name",
            "Enclave name",
            firewall.display_name if firewall else "",
            hint="What it is called.",
            placeholder="Deployed Official",
        ),
        _text(
            "name" if firewall is None else "enclave",
            "Short code",
            firewall.enclave if firewall else "",
            hint="As it appears in the FQDN and in generated rule descriptions.",
            placeholder="do",
        ),
        _text(
            "fqdn",
            "Firewall FQDN",
            firewall.fqdn if firewall else "",
            placeholder="fw1.do.42.dcm.ex",
        ),
        _text(
            "mgmt_address",
            "Management address",
            node.mgmt_address if node else "",
            placeholder="25.42.0.10",
        ),
        _text(
            "gui_url",
            "Management GUI URL",
            node.gui_url if node else "",
            hint="Blank offers no GUI link. One that does not answer is worse than none.",
        ),
        _text("ssh_user", "Your SSH username", node.ssh_user if node else ""),
        _text(
            "credential_ref",
            "Credential name",
            node.credential_ref if node else "",
            hint="The name of a key in your own store — never the key.",
        ),
    ] + (
        []
        if firewall
        else [{"name": "platform", "label": "Platform", "value": "pfsense", "options": platforms}]
    )


def router_fields(node: Node | None = None) -> list[Field]:
    return [
        _text("name", "Name", node.name if node else "", placeholder="r1"),
        _text(
            "mgmt_address",
            "Management address",
            node.mgmt_address if node else "",
            placeholder="25.42.0.1",
        ),
        _text("ssh_user", "Your SSH username", node.ssh_user if node else ""),
        _text("gui_url", "Management GUI URL", node.gui_url if node else ""),
        _text("credential_ref", "Credential name", node.credential_ref if node else ""),
        _text("poll_seconds", "Poll interval, seconds", node.poll_seconds if node else 60),
    ]


def service_fields(service: Service | None = None) -> list[Field]:
    return [
        _text("name", "Name", service.name if service else "", placeholder="Range scoring agent"),
        _text(
            "tcp",
            "TCP ports",
            ", ".join(str(p) for p in service.tcp) if service else "",
            placeholder="8443, 9000",
        ),
        _text("udp", "UDP ports", ", ".join(str(p) for p in service.udp) if service else ""),
        _text(
            "tcp_dynamic",
            "TCP range",
            service.tcp_dynamic if service else "",
            placeholder="49152-65535",
        ),
        {
            "name": "confidence",
            "label": "Confidence",
            "value": service.confidence.value if service else "standard",
            "options": ["standard", "assumed", "unverified"],
            "hint": "Unverified keeps a rule open until somebody closes it.",
        },
        _text("descr", "Description", service.descr if service else ""),
        _text(
            "note",
            "Note",
            service.note if service else "",
            hint="Anything a tired reader needs to know when they pick this.",
        ),
    ]


def host_type_fields(
    catalogue: Catalogue,
    host_type: HostType | None = None,
    isa: IsaCatalogue | None = None,
) -> list[Field]:
    return [
        _text(
            "name", "Name", host_type.name if host_type else "", placeholder="uav_ground_station"
        ),
        _text("default_os", "Default operating system", host_type.default_os if host_type else ""),
        {
            "name": "services",
            "label": "Services it runs",
            "value": list(host_type.services) if host_type else [],
            "checkboxes": sorted(catalogue.services),
            "hint": "The default set a machine of this kind runs. Adjustable per host.",
        },
        _isa_field(
            "isa_checks", list(host_type.isa_checks) if host_type else [], isa
        ),
        _text("descr", "Description", host_type.descr if host_type else ""),
    ]
