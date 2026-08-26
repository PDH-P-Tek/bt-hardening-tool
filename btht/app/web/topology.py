"""The estate drawn — Phase 9.4.

A **view**, never a second place the estate can be defined. It renders what was
declared; it does not edit it.

**Progressive disclosure**, because the real thing does not fit on a screen. The range
diagram this is modelled on is sixteen thousand pixels wide — a wall poster. So the top
level is one firewall per enclave and the links between them; click a firewall to open
its interfaces; click an interface to see the machines on it. Or open a whole firewall
at once when you want the wall-poster view of one enclave.

**Expansion lives in the URL.** Three reasons, and the first is the one that matters:
the layout stays a pure function of `(estate, what is open, what is filtered)`, so the
same view always draws the same picture and the determinism test still means something.
It also makes a particular view a link you can send someone, and it means four hundred
hosts are not rendered into the page just to sit hidden.

Why it earns its place at all: the estate is declared form by form, and that is where
setup errors hide — a segment attached to the wrong interface, a host addressed outside
its subnet, an out-of-bounds machine sitting inside a segment somebody is about to
tighten. A picture is where those become obvious.
"""

from __future__ import annotations

import html
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode

from btht.app.model.estate import Estate, Firewall, Host, Interface, Node

CARD_WIDTH = 250
CARD_HEIGHT = 54
HOST_WIDTH = 132
HOST_HEIGHT = 46
GAP = 20
PADDING = 22
LABEL_BASELINE = 19
SUBLABEL_BASELINE = 34
HOSTS_PER_ROW = 4
UPLINK_HEIGHT = 46


@dataclass(frozen=True, slots=True)
class Shape:
    """One thing on the diagram. `href` is where clicking it goes."""

    detail_id: str
    kind: str
    label: str
    sublabel: str
    x: int
    y: int
    width: int
    height: int
    accent: str = "line"
    href: str = ""
    badge: str = ""


@dataclass(frozen=True, slots=True)
class Link:
    """A line between two things. Drawn as an elbow, so crossings stay readable."""

    x1: int
    y1: int
    x2: int
    y2: int


@dataclass
class Diagram:
    width: int = 0
    height: int = 0
    shapes: list[Shape] = field(default_factory=list)
    links: list[Link] = field(default_factory=list)
    focus: dict[str, Any] = field(default_factory=dict)
    hidden_by_filter: int = 0


@dataclass(frozen=True, slots=True)
class View:
    """What the operator currently has open and filtered."""

    open_ids: frozenset[str] = frozenset()
    focus_id: str = ""
    host_type: str = ""
    service: str = ""
    only_scored: bool = False
    only_out_of_bounds: bool = False

    def is_open(self, node_id: str) -> bool:
        return node_id in self.open_ids

    def toggled(self, node_id: str) -> frozenset[str]:
        if node_id in self.open_ids:
            # Closing a firewall closes everything inside it, or its interfaces stay
            # open invisibly and reopening it produces a picture nobody asked for.
            return frozenset(
                i for i in self.open_ids if i != node_id and not i.startswith(f"{node_id}:")
            )
        return self.open_ids | {node_id}

    def link_for(self, node_id: str, slug: str) -> str:
        params = [("open", i) for i in sorted(self.toggled(node_id))]
        params.append(("focus", node_id))
        params.extend(self._filter_params())
        return f"/estates/{slug}/topology?{urlencode(params)}"

    def focus_link(self, node_id: str, slug: str) -> str:
        params = [("open", i) for i in sorted(self.open_ids)]
        params.append(("focus", node_id))
        params.extend(self._filter_params())
        return f"/estates/{slug}/topology?{urlencode(params)}"

    def open_all_link(self, firewall: Firewall, slug: str) -> str:
        """One click for the whole enclave — the wall-poster view of one firewall."""
        everything = (
            self.open_ids
            | {firewall.enclave}
            | {f"{firewall.enclave}:{i.ifname}" for i in firewall.interfaces if i.role != "wan"}
        )
        params = [("open", i) for i in sorted(everything)]
        params.append(("focus", firewall.enclave))
        params.extend(self._filter_params())
        return f"/estates/{slug}/topology?{urlencode(params)}"

    def _filter_params(self) -> list[tuple[str, str]]:
        out = []
        if self.host_type:
            out.append(("host_type", self.host_type))
        if self.service:
            out.append(("service", self.service))
        if self.only_scored:
            out.append(("scored", "1"))
        if self.only_out_of_bounds:
            out.append(("oob", "1"))
        return out

    @property
    def filtering(self) -> bool:
        return bool(self.host_type or self.service or self.only_scored or self.only_out_of_bounds)

    def matches(self, host: Host) -> bool:
        if self.host_type and host.service_role != self.host_type:
            return False
        if self.service and self.service not in host.services:
            return False
        if self.only_scored and not host.isa_checks:
            return False
        return not (self.only_out_of_bounds and not host.out_of_bounds)


def _host_accent(host: Host) -> str:
    if host.out_of_bounds:
        return "warn"
    if host.isa_checks:
        return "accent"
    return "line"


def _connect_actions(node: Node) -> list[dict[str, str]]:
    """What the operator can launch from here.

    Both hand off to software they already have: a browser tab, and their own SSH
    client via the `ssh://` scheme. The tool holds no session and no credential of its
    own — a built-in web terminal would mean this tool carrying a shell credential to a
    firewall, which `MONITORING.md` §2 and §13 rule out. The plain command is offered
    alongside because `ssh://` handlers are not registered on every desktop.
    """
    actions: list[dict[str, str]] = []
    if node.gui_url:
        actions.append({"kind": "gui", "label": "Open GUI", "href": node.gui_url})
    target = f"{node.ssh_user}@{node.mgmt_address}" if node.ssh_user else str(node.mgmt_address)
    actions.append({"kind": "ssh", "label": "SSH", "href": f"ssh://{target}"})
    actions.append({"kind": "copy", "label": "Copy command", "href": f"ssh {target}"})
    return actions


def _firewall_detail(firewall: Firewall, hosts: tuple[Host, ...]) -> dict[str, Any]:
    warnings: list[str] = []
    scored = [h for h in hosts if h.isa_checks]
    if hosts and not scored:
        warnings.append(
            "No host here has a scored check assigned. Confirm on the board that this "
            "enclave really is unscored."
        )
    return {
        "title": firewall.fqdn or firewall.enclave,
        "fields": [
            ("enclave", firewall.enclave),
            ("side", firewall.side or "not declared"),
            ("config format", firewall.config_version or "unknown"),
            ("platform", firewall.node.platform.value),
            ("management address", str(firewall.node.mgmt_address)),
            ("credential", firewall.node.credential_ref or "not declared"),
            ("segments", str(len([i for i in firewall.interfaces if i.role != "wan"]))),
            ("hosts declared", str(len(hosts))),
        ],
        "actions": _connect_actions(firewall.node),
        "warnings": warnings,
    }


def _interface_detail(
    firewall: Firewall, interface: Interface, hosts: tuple[Host, ...]
) -> dict[str, Any]:
    out_of_bounds = [h for h in hosts if h.out_of_bounds]
    warnings = []
    if interface.is_lan:
        warnings.append(
            "Anti-lockout binds to this interface. Whatever segment it is, that is the "
            "one with a safety net — and the others do not have one."
        )
    if out_of_bounds:
        warnings.append(
            "Out of bounds in this segment: "
            + ", ".join(sorted(h.hostname for h in out_of_bounds))
            + ". Tightening this segment can break them from the inside, and they "
            "appear on no diagram."
        )
    if not interface.v4 and not interface.v6:
        warnings.append("No address declared for this interface.")
    for host in hosts:
        if host.v4 and interface.v4 and host.v4 not in interface.v4.network:
            warnings.append(
                f"{host.hostname} is addressed {host.v4}, which is outside this "
                f"segment's {interface.v4.network}."
            )
    return {
        "title": f"{firewall.enclave} · {interface.role}",
        "fields": [
            ("interface", interface.ifname),
            ("role", interface.role),
            ("IPv4", str(interface.v4) if interface.v4 else "none"),
            ("IPv6", str(interface.v6) if interface.v6 else "none"),
            ("description", interface.descr or "none"),
            ("hosts", str(len(hosts))),
        ],
        "warnings": warnings,
        "actions": [],
    }


def _host_detail(host: Host, catalogue: Any) -> dict[str, Any]:
    ports = ""
    if catalogue is not None and host.services:
        pairs = catalogue.ports_for(host.services)
        ports = ", ".join(f"{proto}/{port}" for proto, port in pairs) or "none"
    warnings = []
    if host.out_of_bounds:
        warnings.append("Out of bounds. It must keep working and must never be a policy target.")
    if not host.services:
        warnings.append("No services declared, so nothing will be opened to it.")
    return {
        "title": host.hostname,
        "fields": [
            ("operating system", host.os or "not declared"),
            ("IPv4", str(host.v4) if host.v4 else "none"),
            ("IPv6", str(host.v6) if host.v6 else "none"),
            ("segment", host.segment_role or "not declared"),
            ("host type", host.service_role or "not declared"),
            ("services", ", ".join(host.services) or "none"),
            ("ports that implies", ports or "unknown"),
            ("scored checks", ", ".join(host.isa_checks) or "none"),
            ("from", host.group and f"group {host.group}" or host.source_of_truth.value),
        ],
        "warnings": warnings,
        "actions": [],
    }


def _hosts_on(
    firewall: Firewall, interface: Interface, catalogue: Any, view: View
) -> tuple[Host, ...]:
    return tuple(
        h
        for h in firewall.all_hosts(catalogue)
        if h.segment_role == interface.role and view.matches(h)
    )


def _column_width(firewall: Firewall, view: View) -> int:
    """How wide this enclave's column needs to be for what is open inside it."""
    if not view.is_open(firewall.enclave):
        return CARD_WIDTH
    widest = CARD_WIDTH
    for interface in firewall.interfaces:
        if interface.role == "wan" or not view.is_open(f"{firewall.enclave}:{interface.ifname}"):
            continue
        widest = max(widest, HOSTS_PER_ROW * (HOST_WIDTH + 10) + 2 * GAP)
    return widest


def layout(
    estate: Estate,
    view: View | None = None,
    slug: str = "",
    catalogue: Any = None,
    status: dict[str, str] | None = None,
) -> Diagram:
    """Geometry as a pure function of the estate, what is open, and what is filtered."""
    view = view or View()
    diagram = Diagram()
    firewalls = sorted(estate.firewalls, key=lambda f: f.enclave)
    routers = sorted(
        (n for n in estate.nodes if n.name not in {f.node.name for f in estate.firewalls}),
        key=lambda n: n.name,
    )

    # Tier 1 — what the enclaves connect through. A single uplink when no routers are
    # declared, because a firewall drawn connected to nothing reads as an error.
    uplink_y = PADDING
    uplink_labels = [
        (n.name, f"{n.platform.value} · {n.mgmt_address}", f"node:{n.name}") for n in routers
    ]
    if not uplink_labels:
        uplink_labels = [("uplink", "no routers declared", "uplink")]

    total_width = 0
    widths = [_column_width(f, view) for f in firewalls]
    total_width = sum(widths) + GAP * max(len(widths) - 1, 0)
    canvas_width = max(total_width + 2 * PADDING, 900)

    uplink_span = canvas_width - 2 * PADDING
    slot = uplink_span // max(len(uplink_labels), 1)
    uplink_points: list[int] = []
    for index, (name, sub, node_id) in enumerate(uplink_labels):
        x = PADDING + index * slot + (slot - min(slot - GAP, CARD_WIDTH)) // 2
        width = min(slot - GAP, CARD_WIDTH)
        health = (status or {}).get(name, "")
        diagram.shapes.append(
            Shape(
                detail_id=node_id,
                kind="uplink",
                label=name,
                sublabel=sub + (f" · {health}" if health else ""),
                x=x,
                y=uplink_y,
                width=width,
                height=UPLINK_HEIGHT,
                accent="warn" if health.startswith("unreachable") else "ok",
                href=view.focus_link(node_id, slug) if slug else "",
            )
        )
        uplink_points.append(x + width // 2)

    # Tier 2 — one firewall per enclave, and everything open beneath it.
    row_y = uplink_y + UPLINK_HEIGHT + GAP * 2
    x_cursor = PADDING
    tallest = 0

    for firewall, width in zip(firewalls, widths, strict=True):
        node_id = firewall.enclave
        hosts_here = firewall.all_hosts(catalogue)
        health = (status or {}).get(firewall.node.name, "")
        open_here = view.is_open(node_id)
        segments = [i for i in firewall.interfaces if i.role != "wan"]

        diagram.shapes.append(
            Shape(
                detail_id=node_id,
                kind="firewall",
                label=firewall.enclave,
                sublabel=f"{firewall.fqdn or firewall.node.platform.value}"
                + (f" · {health}" if health else ""),
                x=x_cursor,
                y=row_y,
                width=width,
                height=CARD_HEIGHT,
                accent="warn" if health.startswith("unreachable") else "accent",
                href=view.link_for(node_id, slug) if slug else "",
                badge=f"{len(segments)} segments · {len(hosts_here)} hosts"
                if not open_here
                else "click to close",
            )
        )
        for point in uplink_points:
            diagram.links.append(
                Link(point, uplink_y + UPLINK_HEIGHT, x_cursor + width // 2, row_y)
            )

        inner_y = row_y + CARD_HEIGHT + GAP
        if open_here:
            for interface in segments:
                segment_id = f"{firewall.enclave}:{interface.ifname}"
                on_it = _hosts_on(firewall, interface, catalogue, view)
                all_on_it = tuple(
                    h for h in firewall.all_hosts(catalogue) if h.segment_role == interface.role
                )
                diagram.hidden_by_filter += len(all_on_it) - len(on_it)
                segment_open = view.is_open(segment_id)
                address = str(interface.v4.ip) if interface.v4 else ""

                diagram.shapes.append(
                    Shape(
                        detail_id=segment_id,
                        kind="segment",
                        label=interface.role,
                        sublabel=f"{interface.ifname}  {address}",
                        x=x_cursor + GAP // 2,
                        y=inner_y,
                        width=width - GAP,
                        height=CARD_HEIGHT,
                        accent="warn" if interface.role.startswith("other:") else "line",
                        href=view.link_for(segment_id, slug) if slug else "",
                        badge=("anti-lockout" if interface.is_lan else "")
                        + (f" · {len(on_it)} hosts" if on_it else " · no hosts"),
                    )
                )
                diagram.links.append(
                    Link(
                        x_cursor + width // 2,
                        row_y + CARD_HEIGHT,
                        x_cursor + width // 2,
                        inner_y,
                    )
                )
                inner_y += CARD_HEIGHT + GAP // 2

                if segment_open and on_it:
                    for index, host in enumerate(on_it):
                        column = index % HOSTS_PER_ROW
                        row = index // HOSTS_PER_ROW
                        diagram.shapes.append(
                            Shape(
                                detail_id=f"host:{firewall.enclave}:{host.hostname}",
                                kind="host",
                                label=host.hostname,
                                sublabel=host.os or "no OS declared",
                                x=x_cursor + GAP + column * (HOST_WIDTH + 10),
                                y=inner_y + row * (HOST_HEIGHT + 8),
                                width=HOST_WIDTH,
                                height=HOST_HEIGHT,
                                accent=_host_accent(host),
                                href=view.focus_link(
                                    f"host:{firewall.enclave}:{host.hostname}", slug
                                )
                                if slug
                                else "",
                                badge=str(host.v4 or ""),
                            )
                        )
                    rows = (len(on_it) + HOSTS_PER_ROW - 1) // HOSTS_PER_ROW
                    inner_y += rows * (HOST_HEIGHT + 8) + GAP // 2

        tallest = max(tallest, inner_y - row_y)
        x_cursor += width + GAP

    diagram.width = canvas_width
    diagram.height = row_y + tallest + PADDING * 2

    # The focused item's detail, rendered server-side. No client-side state to drift.
    diagram.focus = _focus_detail(estate, view, catalogue)
    return diagram


def _focus_detail(estate: Estate, view: View, catalogue: Any) -> dict[str, Any]:
    target = view.focus_id
    if not target:
        return {}
    if target.startswith("host:"):
        _prefix, enclave, hostname = target.split(":", 2)
        firewall = estate.firewall(enclave)
        if firewall is None:
            return {}
        host = next((h for h in firewall.all_hosts(catalogue) if h.hostname == hostname), None)
        return _host_detail(host, catalogue) if host else {}
    if target.startswith("node:"):
        name = target.split(":", 1)[1]
        node = next((n for n in estate.nodes if n.name == name), None)
        if node is None:
            return {}
        return {
            "title": node.name,
            "fields": [
                ("platform", node.platform.value),
                ("management address", str(node.mgmt_address)),
                ("credential", node.credential_ref or "not declared"),
                ("poll interval", f"{node.poll_seconds}s"),
            ],
            "actions": _connect_actions(node),
            "warnings": [],
        }
    if ":" in target:
        enclave, ifname = target.split(":", 1)
        firewall = estate.firewall(enclave)
        if firewall is None:
            return {}
        interface = next((i for i in firewall.interfaces if i.ifname == ifname), None)
        if interface is None:
            return {}
        hosts = tuple(h for h in firewall.all_hosts(catalogue) if h.segment_role == interface.role)
        return _interface_detail(firewall, interface, hosts)
    firewall = estate.firewall(target)
    if firewall is None:
        return {}
    return _firewall_detail(firewall, firewall.all_hosts(catalogue))


def render_svg(diagram: Diagram) -> str:
    """Inline SVG. No external references, so it renders with no network at all."""
    parts = [
        f'<svg viewBox="0 0 {diagram.width} {diagram.height}" width="100%" '
        f'height="{diagram.height}" xmlns="http://www.w3.org/2000/svg" '
        'role="img" aria-label="estate topology">'
    ]
    for link in diagram.links:
        middle = (link.y1 + link.y2) // 2
        parts.append(
            f'<path class="link" d="M {link.x1} {link.y1} V {middle} H {link.x2} '
            f'V {link.y2}" fill="none"/>'
        )
    for shape in diagram.shapes:
        label = html.escape(shape.label)
        sublabel = html.escape(shape.sublabel)
        body = (
            f'<rect x="{shape.x}" y="{shape.y}" width="{shape.width}" '
            f'height="{shape.height}" rx="6"/>'
            f'<text x="{shape.x + 11}" y="{shape.y + LABEL_BASELINE}" class="label">'
            f"{label}</text>"
            f'<text x="{shape.x + 11}" y="{shape.y + SUBLABEL_BASELINE}" class="sub">'
            f"{sublabel}</text>"
        )
        if shape.badge:
            body += (
                f'<text x="{shape.x + shape.width - 11}" y="{shape.y + LABEL_BASELINE}" '
                f'class="badge" text-anchor="end">{html.escape(shape.badge)}</text>'
            )
        group = (
            f'<g class="shape {shape.kind} accent-{shape.accent}" '
            f'data-detail="{html.escape(shape.detail_id)}">{body}</g>'
        )
        if shape.href:
            parts.append(f'<a href="{html.escape(shape.href)}">{group}</a>')
        else:
            parts.append(group)
    parts.append("</svg>")
    return "".join(parts)
