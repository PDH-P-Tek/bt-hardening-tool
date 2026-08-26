"""The estate drawn — Phase 2.2.

A **view**, never a second place the estate can be defined. It renders what was
declared; it does not edit it.

Why it exists: the estate is declared form by form, and that is where setup errors
hide. A segment attached to the wrong interface, a host addressed outside its subnet,
a firewall whose WAN sits on one side while its internals address into another. A
picture is where those become obvious. It is also the only view that shows an
out-of-bounds host sitting *inside* a segment someone is about to tighten.

**Deterministic tiered layout, no library.** The estate is a tree — enclave, firewall,
segments, hosts — so the geometry is a pure function of the declared estate. Same
estate, same picture. A force-directed layout would need a library the offline
container cannot fetch, and would move things between runs for no gain.
"""

from __future__ import annotations

import html
import json
from dataclasses import dataclass, field
from typing import Any

from btht.app.model.estate import Estate, Firewall, Node

CARD_WIDTH = 300
CARD_GAP = 26
ROW_HEIGHT = 46
HEADER_HEIGHT = 62
PADDING = 18
COLUMNS = 3

#: Text baselines measured from the top of a shape. Both must fall inside the shape,
#: which `test_topology.py` asserts: text escaping its box is the one layout fault
#: that looks fine in code and obviously broken on screen.
LABEL_BASELINE = 18
SUBLABEL_BASELINE = 33


@dataclass(frozen=True, slots=True)
class Shape:
    """One clickable thing on the diagram."""

    detail_id: str
    kind: str
    label: str
    sublabel: str
    x: int
    y: int
    width: int
    height: int
    accent: str = "line"


@dataclass
class Diagram:
    width: int = 0
    height: int = 0
    shapes: list[Shape] = field(default_factory=list)
    details: dict[str, dict[str, Any]] = field(default_factory=dict)


def _connect_actions(node: Node) -> list[dict[str, str]]:
    """What the operator can launch from here.

    Both hand off to software the operator already has: a browser tab, and their own
    SSH client via the `ssh://` scheme. The tool holds no session and no credential of
    its own — a built-in web terminal would mean this tool carrying a shell credential
    to a firewall, which is exactly what `MONITORING.md` §2 and §13 rule out. The
    plain command is offered alongside because `ssh://` handlers are not registered on
    every desktop.
    """
    actions: list[dict[str, str]] = []
    if node.gui_url:
        actions.append({"kind": "gui", "label": "Open GUI", "href": node.gui_url})
    target = f"{node.ssh_user}@{node.mgmt_address}" if node.ssh_user else str(node.mgmt_address)
    actions.append({"kind": "ssh", "label": "SSH", "href": f"ssh://{target}"})
    actions.append({"kind": "copy", "label": "Copy command", "href": f"ssh {target}"})
    return actions


def _node_detail(node: Node) -> dict[str, Any]:
    return {
        "title": node.name,
        "kind": node.platform.value,
        "fields": [
            ("platform", node.platform.value),
            ("management address", str(node.mgmt_address)),
            ("credential", node.credential_ref or "not declared"),
            ("poll interval", f"{node.poll_seconds}s"),
        ],
        "actions": _connect_actions(node),
    }


def _firewall_detail(firewall: Firewall) -> dict[str, Any]:
    detail = _node_detail(firewall.node)
    detail["title"] = firewall.fqdn or firewall.enclave
    detail["fields"] = [
        ("enclave", firewall.enclave),
        ("side", firewall.side or "not declared"),
        ("config format", firewall.config_version or "unknown"),
        *detail["fields"],
    ]
    return detail


def _interface_detail(firewall: Firewall, index: int) -> dict[str, Any]:
    iface = firewall.interfaces[index]
    hosts = [h for h in firewall.hosts if h.segment_role == iface.role]
    out_of_bounds = [h for h in hosts if h.out_of_bounds]
    fields = [
        ("interface", iface.ifname),
        ("role", iface.role),
        ("IPv4", str(iface.v4) if iface.v4 else "none"),
        ("IPv6", str(iface.v6) if iface.v6 else "none"),
        ("description", iface.descr or "none"),
        ("hosts declared", str(len(hosts))),
    ]
    warnings = []
    if iface.is_lan:
        warnings.append(
            "Anti-lockout binds to this interface. Whatever segment it is, that is the "
            "one with a safety net — and the others do not have one."
        )
    if out_of_bounds:
        names = ", ".join(sorted(h.hostname for h in out_of_bounds))
        warnings.append(
            f"Out of bounds inside this segment: {names}. Tightening this segment can "
            "break them from the inside, and they appear on no diagram."
        )
    if not iface.v4 and not iface.v6:
        warnings.append("No address declared for this interface.")
    return {"title": f"{firewall.enclave} · {iface.role}", "fields": fields, "warnings": warnings}


def layout(estate: Estate) -> Diagram:
    """Geometry as a pure function of the declared estate."""
    diagram = Diagram()
    firewalls = sorted(estate.firewalls, key=lambda f: f.enclave)
    loose = sorted(
        (n for n in estate.nodes if n.name not in {f.node.name for f in estate.firewalls}),
        key=lambda n: (n.enclave or "", n.name),
    )

    column = 0
    row = 0
    row_top = PADDING
    tallest = 0

    def place(card_index: int) -> tuple[int, int]:
        return (PADDING + card_index * (CARD_WIDTH + CARD_GAP), row_top)

    for firewall in firewalls:
        x, y = place(column)
        interfaces = sorted(firewall.interfaces, key=lambda i: (i.role != "wan", i.role))
        height = HEADER_HEIGHT + max(len(interfaces), 1) * ROW_HEIGHT + PADDING

        detail_id = f"fw:{firewall.enclave}"
        diagram.shapes.append(
            Shape(
                detail_id=detail_id,
                kind="firewall",
                label=firewall.enclave,
                sublabel=f"{firewall.node.platform.value} · {firewall.node.mgmt_address}",
                x=x,
                y=y,
                width=CARD_WIDTH,
                height=HEADER_HEIGHT - 12,
                accent="accent",
            )
        )
        diagram.details[detail_id] = _firewall_detail(firewall)

        for position, iface in enumerate(interfaces):
            original = firewall.interfaces.index(iface)
            segment_id = f"if:{firewall.enclave}:{iface.ifname}"
            address = str(iface.v4.ip) if iface.v4 else (str(iface.v6.ip) if iface.v6 else "")
            accent = "warn" if iface.role.startswith("other:") else "line"
            diagram.shapes.append(
                Shape(
                    detail_id=segment_id,
                    kind="segment",
                    label=iface.role,
                    sublabel=f"{iface.ifname}  {address}",
                    x=x + 16,
                    y=y + HEADER_HEIGHT + position * ROW_HEIGHT,
                    width=CARD_WIDTH - 32,
                    height=ROW_HEIGHT - 10,
                    accent=accent,
                )
            )
            diagram.details[segment_id] = _interface_detail(firewall, original)

        tallest = max(tallest, height)
        column += 1
        if column >= COLUMNS:
            column, row = 0, row + 1
            row_top += tallest + CARD_GAP
            tallest = 0

    for node in loose:
        x, y = place(column)
        detail_id = f"node:{node.name}"
        diagram.shapes.append(
            Shape(
                detail_id=detail_id,
                kind="node",
                label=node.name,
                sublabel=f"{node.platform.value} · {node.mgmt_address}",
                x=x,
                y=y,
                width=CARD_WIDTH,
                height=HEADER_HEIGHT - 12,
                accent="ok",
            )
        )
        diagram.details[detail_id] = _node_detail(node)
        tallest = max(tallest, HEADER_HEIGHT)
        column += 1
        if column >= COLUMNS:
            column, row = 0, row + 1
            row_top += tallest + CARD_GAP
            tallest = 0

    diagram.width = PADDING * 2 + COLUMNS * CARD_WIDTH + (COLUMNS - 1) * CARD_GAP
    diagram.height = row_top + tallest + PADDING * 2
    return diagram


def render_svg(diagram: Diagram) -> str:
    """Inline SVG. No external references, so it renders with no network at all."""
    parts = [
        f'<svg viewBox="0 0 {diagram.width} {diagram.height}" width="100%" '
        f'height="{diagram.height}" xmlns="http://www.w3.org/2000/svg" '
        'role="img" aria-label="estate topology">'
    ]
    for shape in diagram.shapes:
        label = html.escape(shape.label)
        sublabel = html.escape(shape.sublabel)
        parts.append(
            f'<g class="shape {shape.kind} accent-{shape.accent}" '
            f'data-detail="{html.escape(shape.detail_id)}" tabindex="0" role="button">'
            f'<rect x="{shape.x}" y="{shape.y}" width="{shape.width}" '
            f'height="{shape.height}" rx="6"/>'
            f'<text x="{shape.x + 12}" y="{shape.y + 20}" class="label">{label}</text>'
            f'<text x="{shape.x + 12}" y="{shape.y + 36}" class="sub">{sublabel}</text>'
            "</g>"
        )
    parts.append("</svg>")
    return "".join(parts)


def details_json(diagram: Diagram) -> str:
    return json.dumps(diagram.details, sort_keys=True, separators=(",", ":"))
