"""The verification manifest — `VERIFICATION.md`.

A generated ruleset is a claim. This is how the claim gets tested from the segment it
applies to, because a rule permitting `ws → svrs:445` can only be proved from the
workstation segment. So there is one manifest **per source position**, not one per
firewall.

Three rules make a manifest worth running:

- every scored check becomes an `expect: open` assertion — a failure there is points
- every assertion exists in both address families, because a v4-only pass is a partial
  pass and IPv6 asymmetry is the most common silent failure in this estate
- some assertions are `expect: closed`, which is the half people skip and the half that
  catches a catch-all somebody thought they had removed

**Scan targets are hard-limited to the estate's own declared subnets**, and that is
enforced here rather than written in a warning. Scanning space you are not responsible
for is a hostile act under the rules of engagement, and it is exactly the mistake
someone makes at speed by pasting the wrong range.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address, ip_address

import yaml

from btht.app.ingest.isa import Catalogue, required_ports
from btht.app.model.estate import Firewall
from btht.app.model.policy import FirewallPolicy


class OutOfScope(Exception):
    """A target outside the estate's declared space. Refused, never warned about."""


@dataclass(frozen=True, slots=True)
class Assertion:
    target: str
    port: int
    proto: str
    expect: str
    """`open` or `closed`."""

    why: str

    @property
    def family(self) -> int:
        return ip_address(self.target).version


@dataclass(frozen=True, slots=True)
class Manifest:
    firewall: str
    segment: str
    assertions: tuple[Assertion, ...] = ()
    policy_sha256: str = ""

    @property
    def note(self) -> str:
        return f"Run from any host on the {self.segment} segment"

    def to_document(self) -> dict[str, dict[str, object]]:
        return {
            "manifest": {
                "firewall": self.firewall,
                "policy_sha256": self.policy_sha256,
                "position": {"segment": self.segment, "note": self.note},
                "assertions": [
                    {
                        "target": a.target,
                        "port": a.port,
                        "proto": a.proto,
                        "expect": a.expect,
                        "why": a.why,
                    }
                    for a in self.assertions
                ],
            }
        }

    def to_yaml(self) -> str:
        return yaml.safe_dump(self.to_document(), sort_keys=False, default_flow_style=False)


def in_scope(target: str, firewall: Firewall) -> bool:
    """Whether an address is inside this firewall's own declared segments."""
    try:
        address = ip_address(target)
    except ValueError:
        return False
    for interface in firewall.interfaces:
        for own in (interface.v4, interface.v6):
            if own is not None and address.version == own.version and address in own.network:
                return True
    return False


def build(
    firewall: Firewall,
    entry: FirewallPolicy,
    catalogue: Catalogue,
    segment: str,
    policy_text: str = "",
) -> Manifest:
    """One manifest for one source position."""
    assertions: list[Assertion] = []

    for host in firewall.hosts:
        addresses: list[IPv4Address | IPv6Address] = [
            a for a in (host.v4, host.v6) if a is not None
        ]
        for proto, port in required_ports(host.isa_checks, catalogue):
            if not port:
                continue
            for address in addresses:
                assertions.append(
                    Assertion(
                        target=str(address),
                        port=port,
                        proto=proto,
                        expect="open",
                        why=f"scored check: {host.hostname}",
                    )
                )
        if addresses and host.isa_checks and len(addresses) == 1:
            # Stated rather than silently omitted: half the assertions are missing.
            assertions.append(
                Assertion(
                    target=str(addresses[0]),
                    port=0,
                    proto="note",
                    expect="open",
                    why=f"{host.hostname} has one address family declared, so this "
                    "manifest can only prove half of it",
                )
            )

    for service in entry.services:
        if service.segment != segment or not service.host:
            continue
        for port in service.ports:
            assertions.append(
                Assertion(
                    target=service.host,
                    port=port,
                    proto=service.protocol,
                    expect="open",
                    why=f"policy: {service.name}",
                )
            )

    # Proving something is shut is the half people skip.
    declared_ports = {a.port for a in assertions if a.expect == "open"}
    for host in firewall.hosts:
        if host.v4 is None:
            continue
        for port in (3389, 3306, 22):
            if port not in declared_ports:
                assertions.append(
                    Assertion(
                        target=str(host.v4),
                        port=port,
                        proto="tcp",
                        expect="closed",
                        why="not in policy — proving it is shut catches a catch-all "
                        "you thought you had removed",
                    )
                )
                break

    for assertion in assertions:
        if assertion.proto != "note" and not in_scope(assertion.target, firewall):
            raise OutOfScope(
                f"{assertion.target} is not in any declared segment of "
                f"{firewall.enclave}. Scanning space you are not responsible for is a "
                "hostile act under the rules of engagement, so the manifest refuses "
                "rather than warning."
            )

    return Manifest(
        firewall=firewall.fqdn or firewall.enclave,
        segment=segment,
        assertions=tuple(assertions),
        policy_sha256=hashlib.sha256(policy_text.encode()).hexdigest() if policy_text else "",
    )


def nmap_command(manifest: Manifest, family: int = 4) -> str:
    """The command to run. Conservative timing on purpose — `VERIFICATION.md`.

    Availability checks run throughout the exercise, and an aggressive scan muddies
    the team's own detection baseline for no benefit.
    """
    targets = sorted(
        {a.target for a in manifest.assertions if a.proto != "note" and a.family == family}
    )
    ports = sorted({a.port for a in manifest.assertions if a.port and a.proto == "tcp"})
    if not targets or not ports:
        return ""
    flag = "-6 " if family == 6 else ""
    return (
        f"nmap {flag}-Pn -T3 -p {','.join(str(p) for p in ports)} "
        f"{' '.join(targets)} -oX verify-{manifest.segment}-v{family}.xml"
    )


@dataclass(frozen=True, slots=True)
class ScanResult:
    target: str
    port: int
    open: bool


def parse_nmap(xml_text: str) -> tuple[ScanResult, ...]:
    """Read an nmap XML report. Import only — the tool never runs the scan itself."""
    import xml.etree.ElementTree as ET

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return ()
    results: list[ScanResult] = []
    for host in root.findall("host"):
        address_element = host.find("address")
        if address_element is None:
            continue
        target = address_element.get("addr", "")
        for port in host.findall("ports/port"):
            state = port.find("state")
            results.append(
                ScanResult(
                    target=target,
                    port=int(port.get("portid", "0")),
                    open=state is not None and state.get("state") == "open",
                )
            )
    return tuple(results)


@dataclass(frozen=True, slots=True)
class Verification:
    assertion: Assertion
    observed: str
    passed: bool


def verify(manifest: Manifest, results: tuple[ScanResult, ...]) -> tuple[Verification, ...]:
    """Compare what was asserted against what answered.

    An assertion with no result is a failure, not a pass: a target that was never
    scanned has proved nothing, and treating silence as success is how a manifest
    comes back green having tested half of what it claimed.
    """
    observed = {(r.target, r.port): r.open for r in results}
    out = []
    for assertion in manifest.assertions:
        if assertion.proto == "note":
            continue
        key = (assertion.target, assertion.port)
        if key not in observed:
            out.append(Verification(assertion, "not scanned", False))
            continue
        is_open = observed[key]
        expected_open = assertion.expect == "open"
        out.append(
            Verification(
                assertion,
                "open" if is_open else "closed",
                is_open == expected_open,
            )
        )
    return tuple(out)
