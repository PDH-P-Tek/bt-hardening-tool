"""FRR router collector — `MONITORING.md` §5.8, §6.3.

The platform where the config-versus-state distinction bites hardest, and the reason
it is stated so plainly elsewhere. `show running-config` is configuration: it changes
when somebody changes it, and every change is worth an alert. `show ip route` is state:
it churns constantly, and diffing it would produce a stream of findings that mean
nothing, every single poll, until the operator stops reading any of them.

Neighbour *definitions* are config. Neighbour *up or down* is state. Those two live one
line apart in the same output, which is exactly how they get confused.
"""

from __future__ import annotations

from btht.app.monitor.items import Collection, Item, Kind, Severity
from btht.app.monitor.transport import Transport, TransportError

COMMANDS = {
    "M-RT-01": "vtysh -c 'show running-config'",
    "M-RT-02": "vtysh -c 'show ip ospf neighbor'",
    "M-RT-03": "vtysh -c 'show ip route'",
    "M-RT-04": "vtysh -c 'show bfd peers brief'",
}

#: Lines that describe intent. Everything else in a running-config is noise or timing.
CONFIG_PREFIXES = (
    "router ",
    "network ",
    "neighbor ",
    "ip route ",
    "ipv6 route ",
    "access-list ",
    "ip prefix-list ",
    "route-map ",
    "username ",
    "line vty",
    "interface ",
    "log ",
)


def _running_config(output: str) -> list[Item]:
    """Config. Every line is its own item, so a single added route is one finding."""
    items = []
    for line in output.splitlines():
        entry = line.strip()
        if not entry or entry.startswith("!") or entry.startswith("Building configuration"):
            continue
        if not entry.startswith(CONFIG_PREFIXES):
            continue
        severity = (
            Severity.CRITICAL
            if entry.startswith(("username ", "line vty", "access-list "))
            else Severity.HIGH
        )
        items.append(
            Item(
                key=f"frr:config:{entry}",
                collector="M-RT-01",
                kind=Kind.CONFIG,
                value=entry,
                severity=severity,
                label="routing configuration",
            )
        )
    return items


def _neighbour_state(output: str, collector: str, label: str) -> list[Item]:
    """State. Collected and shown, never diffed.

    An adjacency flapping is operationally interesting and is not a configuration
    change. Alerting on it would bury the one line that says a *new* neighbour was
    configured.
    """
    return [
        Item(
            key=f"frr:state:{collector}",
            collector=collector,
            kind=Kind.STATE,
            value=output.strip(),
            severity=Severity.INFO,
            label=label,
        )
    ]


def collect(transport: Transport, secret: str = "btht") -> Collection:
    items: list[Item] = []
    try:
        running = transport.run(COMMANDS["M-RT-01"])
        if not running.ok:
            return Collection(host=transport.host, reachable=False, error=running.stderr.strip())
        items += _running_config(running.stdout)

        for collector, label in (
            ("M-RT-02", "OSPF neighbours"),
            ("M-RT-03", "routing table"),
            ("M-RT-04", "BFD peers"),
        ):
            result = transport.run(COMMANDS[collector])
            if result.ok:
                items += _neighbour_state(result.stdout, collector, label)
    except TransportError as exc:
        return Collection(host=transport.host, reachable=False, error=str(exc))

    return Collection(host=transport.host, items=tuple(items))
