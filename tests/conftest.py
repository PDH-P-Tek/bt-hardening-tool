"""Shared builders for the generator tests.

Here rather than imported between test modules: a test importing another test makes
the suite a package, and the ordering tests and the output tests should be able to
run independently of each other.
"""

from __future__ import annotations

import os

# The collector runs in-process with the app. The suite is offline by construction, so
# it is switched off here rather than relied upon to fail politely — a test that shells
# out to `ssh` does not fail, it hangs.
os.environ.setdefault("BTHT_MONITOR", "0")

from ipaddress import IPv4Address, IPv4Interface, IPv6Address, IPv6Interface
from pathlib import Path

import pytest

from btht.app.generate.order import Ruleset, generate
from btht.app.ingest.isa import Catalogue, load_catalogue
from btht.app.model.estate import Firewall, Host, Interface, Node, Platform
from btht.app.model.policy import (
    EgressPolicy,
    FirewallPolicy,
    Policy,
    PolicyAlias,
    Selector,
    ServiceRule,
)

ROOT = Path(__file__).resolve().parents[1]

#: A DNS destination and an NTP destination, both declared. The generator refuses to
#: emit a deny without them, so every ruleset built here has to supply them.
ESSENTIAL = {"dns": Selector(alias="DNS_Servers"), "ntp": Selector(alias="NTP_Servers")}


def a_firewall() -> Firewall:
    """A small firewall with the awkward parts kept: a scored host and one out of bounds."""
    return Firewall(
        enclave="alpha",
        fqdn="fw1.alpha",
        node=Node(
            name="fw1.alpha", platform=Platform.PFSENSE, mgmt_address=IPv4Address("10.9.0.1")
        ),
        interfaces=(
            Interface(ifname="wan", role="wan", v4=IPv4Interface("198.51.100.2/24")),
            Interface(
                ifname="lan",
                role="users",
                v4=IPv4Interface("192.0.2.1/24"),
                v6=IPv6Interface("2001:db8:2::1/64"),
                is_lan=True,
            ),
            Interface(
                ifname="opt1",
                role="servers",
                v4=IPv4Interface("192.0.3.1/24"),
                v6=IPv6Interface("2001:db8:3::1/64"),
            ),
        ),
        hosts=(
            Host(
                hostname="dc01",
                v4=IPv4Address("192.0.3.5"),
                v6=IPv6Address("2001:db8:3::5"),
                segment_role="servers",
                service_role="domain_controller",
                isa_checks=("HOST", "LDAP"),
            ),
            Host(
                hostname="npc",
                v4=IPv4Address("192.0.2.249"),
                v6=IPv6Address("2001:db8:2::249"),
                segment_role="users",
                out_of_bounds=True,
            ),
        ),
    )


def a_policy(**overrides: object) -> Policy:
    entry = FirewallPolicy(
        enclave="alpha",
        services=(
            ServiceRule(
                name="AD / DC",
                segment="servers",
                host="192.0.3.5",
                protocol="tcp",
                ports=(389,),
                source=Selector(segments=("users",)),
            ),
        ),
        egress=EgressPolicy(default="deny_and_log"),
    )
    base: dict[str, object] = {
        "aliases": (
            PolicyAlias(name="Mgmt_Sources", lockout_critical=True),
            PolicyAlias(name="DNS_Servers", type="host"),
            PolicyAlias(name="NTP_Servers", type="host"),
        ),
        "firewalls": (entry,),
    }
    base.update(overrides)
    return Policy(**base)  # type: ignore[arg-type]


@pytest.fixture(scope="session")
def catalogue() -> Catalogue:
    return load_catalogue(ROOT / "isa-checks.yaml")


def a_ruleset(**overrides: object) -> Ruleset:
    """The standard generated ruleset. Annotated here so no test module re-declares it."""
    firewall = overrides.pop("firewall", None) or a_firewall()
    policy = overrides.pop("policy", None) or a_policy()
    return generate(
        firewall,  # type: ignore[arg-type]
        policy,  # type: ignore[arg-type]
        load_catalogue(overrides.pop("catalogue_path", None)),  # type: ignore[arg-type]
        scoring_source=Selector(alias="Scoring_Sources"),
        essential=ESSENTIAL,
    )
