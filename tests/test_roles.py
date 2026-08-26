"""Phase 1.2 — role derivation and side labels.

`SPEC.md` §10.2 names two of these as required tests. Both are cases where reading
the pfSense ifname, or reading an internal address range, produces a confidently
wrong answer:

- one enclave maps `lan` to servers while the rest map it to workstations
- one firewall's WAN sits on one side while its internals address into another

The rest of this file asserts the thing that makes those safe: **the tool proposes
from what it was told, and proposes nothing when it was told nothing.**
"""

from __future__ import annotations

from ipaddress import ip_network
from pathlib import Path

import pytest

from btht.app.ingest.pfsense import parse_file
from btht.app.ingest.roles import (
    RoleConvention,
    SideRule,
    convention_from_mapping,
    derive_interfaces,
    derive_side,
    is_unresolved,
    propose_role,
    side_rules_from_mapping,
)

BASELINE = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "baseline"

#: What an operator declares at setup for this particular estate. It lives in the test
#: because it belongs to the estate, not to the tool — the package must contain no
#: copy of it.
DECLARED = RoleConvention(
    vocabulary=("wan", "ws", "svrs", "dmz", "uav", "port1", "port2", "stbd1", "stbd2"),
    enclave_tokens=("bt_wan_", "hn_wan_", "dsoc_", "do_", "ds_", "mcu_"),
)

DECLARED_SIDES = (
    SideRule(network=ip_network("25.0.0.0/8"), label="deployed"),
    SideRule(network=ip_network("10.0.0.0/8"), label="host_nation"),
)


def interfaces(enclave: str, convention: RoleConvention = DECLARED):  # type: ignore[no-untyped-def]
    parsed = parse_file(BASELINE / f"{enclave}-baseline.xml")
    return derive_interfaces(parsed.interfaces, convention)


def roles(enclave: str) -> dict[str, str]:
    return {i.ifname: i.role for i in interfaces(enclave)}


# --- the inversion ---------------------------------------------------------


def test_the_inverted_enclave_resolves_lan_to_servers() -> None:
    """`SPEC.md` §10.2, required test. `BASELINE-ANALYSIS.md` F2."""
    assert roles("dsoc") == {"wan": "wan", "lan": "svrs", "opt1": "ws"}


def test_a_conventional_enclave_resolves_lan_to_workstations() -> None:
    """The same code, the same convention, the opposite answer. That is the point."""
    assert roles("do") == {"wan": "wan", "lan": "ws", "opt1": "svrs", "opt2": "dmz"}


def test_the_same_ifname_means_different_things_on_different_firewalls() -> None:
    """Stated as its own test because it is the assumption that breaks estates."""
    assert roles("do")["lan"] != roles("dsoc")["lan"]


# --- the straddle ----------------------------------------------------------


def test_side_comes_from_the_wan_not_the_internals() -> None:
    """`SPEC.md` §10.2, required test.

    This firewall's internal segments are all in one side's range and its WAN is in
    the other's. Reading the internals gives the wrong label with total confidence.
    """
    ifaces = interfaces("mcu")
    assert derive_side(ifaces, DECLARED_SIDES) == "host_nation"

    internal = [i for i in ifaces if i.ifname != "wan"]
    assert internal and all(
        i.v4 is not None and i.v4.ip in ip_network("25.0.0.0/8") for i in internal
    ), "the internals really are in the other side's range, or this test proves nothing"


def test_a_non_straddling_firewall_labels_from_its_wan_too() -> None:
    assert derive_side(interfaces("do"), DECLARED_SIDES) == "deployed"


def test_side_is_empty_when_no_rule_matches() -> None:
    """Empty means undeclared. It never falls back to a guess."""
    assert derive_side(interfaces("do"), ()) == ""


# --- declared, never assumed -----------------------------------------------


def test_an_empty_convention_resolves_nothing() -> None:
    """The tool ships no vocabulary, so with nothing declared everything is unresolved."""
    derived = roles_for_empty = {i.ifname: i.role for i in interfaces("do", RoleConvention())}
    assert derived["wan"] == "wan", "the pfSense outside interface is a platform fact"
    unresolved = [r for name, r in roles_for_empty.items() if name != "wan"]
    assert unresolved and all(is_unresolved(r) for r in unresolved)


def test_an_unrecognised_description_surfaces_rather_than_being_guessed() -> None:
    """`SPEC.md` §4.1 — `other:<descr>`, carrying the original text for triage."""
    role = propose_role("opt3", "do_medical", DECLARED)
    assert is_unresolved(role)
    assert "do_medical" in role


def test_enclave_tokens_strip_longest_first() -> None:
    """A shorter token that is also a prefix must not win and leave a fragment."""
    convention = RoleConvention(vocabulary=("ws",), enclave_tokens=("ab_", "abc_"))
    assert propose_role("opt1", "abc_ws", convention) == "ws"


def test_anti_lockout_binds_to_the_pfsense_lan_whatever_its_role() -> None:
    """On the inverted enclave that means anti-lockout protects the servers.

    The flag follows the ifname because pfSense binds it to the ifname. Which segment
    that leaves unprotected is exactly what the operator needs to be shown.
    """
    inverted = {i.ifname: i for i in interfaces("dsoc")}
    assert inverted["lan"].is_lan is True
    assert inverted["lan"].role == "svrs"
    assert inverted["opt1"].is_lan is False


# --- declaration comes from data -------------------------------------------


def test_convention_is_built_from_loaded_data() -> None:
    """One place where declared vocabulary enters the system."""
    convention = convention_from_mapping(
        {"recognised": ["ws", "svrs"], "enclave_tokens": ["site_"]}
    )
    assert propose_role("lan", "site_svrs", convention) == "svrs"


def test_convention_from_empty_data_declares_nothing() -> None:
    assert convention_from_mapping({}) == RoleConvention()


def test_side_rules_are_built_from_declared_pairs() -> None:
    rules = side_rules_from_mapping(
        [{"network": "192.0.2.0/24", "label": "whatever the operator calls it"}]
    )
    assert rules[0].label == "whatever the operator calls it"


@pytest.mark.parametrize("enclave", ("do", "dsoc", "mcu"))
def test_every_interface_keeps_its_ifname_for_emission(enclave: str) -> None:
    """Roles are for matching; ifnames are for emission. Both must survive."""
    for iface in interfaces(enclave):
        assert iface.ifname
        assert iface.role
