"""The fixtures carry specific traps. These tests assert the traps are still there.

Phase 1.2 re-asserts all of this through the parser, which is the test that
matters. This one is cheaper and answers a different question: has someone
tidied the awkwardness out of the fixtures? A fixture that has quietly become
well-behaved stops defending anything, and nothing else would notice.

Deliberately reads the raw XML rather than the domain model, so it keeps working
— and keeps meaning something — regardless of what the parser does later.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

BASELINE = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "baseline"
ENCLAVES = ("do", "dsoc", "mcu")


def load(enclave: str) -> ET.Element:
    return ET.parse(BASELINE / f"{enclave}-baseline.xml").getroot()


def interfaces(root: ET.Element) -> dict[str, dict[str, str]]:
    node = root.find("interfaces")
    assert node is not None
    return {
        iface.tag: {child.tag: (child.text or "") for child in iface}
        for iface in node
    }


@pytest.mark.parametrize("enclave", ENCLAVES)
def test_config_format_is_the_expected_version(enclave: str) -> None:
    """`V-CONFIG-VERSION` blocks on anything but 23.3."""
    assert (load(enclave).findtext("version") or "").strip() == "23.3"


@pytest.mark.parametrize("enclave", ENCLAVES)
def test_boolean_encoding_is_preserved(enclave: str) -> None:
    """Empty element = false, `yes` = true. Presence means nothing.

    `BASELINE-ANALYSIS.md` §1. Read backwards, the tool reports anti-lockout as
    disabled on every real config, so the fixtures must keep both forms.
    """
    system = load(enclave).find("system")
    assert system is not None
    antilockout = system.find("noantilockout")
    reflection = system.find("disablenatreflection")
    assert antilockout is not None, "the false-by-emptiness case must stay present"
    assert (antilockout.text or "") == "", "anti-lockout is enabled: empty element"
    assert reflection is not None and (reflection.text or "").strip() == "yes"


def test_dsoc_inverts_lan() -> None:
    """`BASELINE-ANALYSIS.md` F2 — the most common way to get this codebase wrong."""
    dsoc = interfaces(load("dsoc"))
    assert dsoc["lan"]["descr"] == "dsoc_svrs", "on dsoc, lan is the SERVER segment"
    assert dsoc["opt1"]["descr"] == "dsoc_ws", "and opt1 is workstations"

    do = interfaces(load("do"))
    assert do["lan"]["descr"] == "do_ws", "everywhere else, lan is workstations"
    assert do["opt1"]["descr"] == "do_svrs"


def test_mcu_straddles_the_two_estates() -> None:
    """WAN on Host Nation, internals in deployed space — `BASELINE-ANALYSIS.md` §2.

    `estate_side` comes from the WAN address. Anything reading `25.x` off an
    internal interface and concluding "deployed" gets this firewall wrong.
    """
    mcu = interfaces(load("mcu"))
    assert mcu["wan"]["ipaddr"].startswith("10."), "mcu WAN is Host Nation addressing"
    internal = [v["ipaddr"] for k, v in mcu.items() if k != "wan"]
    assert internal, "mcu must have internal interfaces"
    assert all(a.startswith("25.") for a in internal), "internals are deployed addressing"


@pytest.mark.parametrize("enclave", ENCLAVES)
def test_floating_rules_are_non_quick(enclave: str) -> None:
    """`BASELINE-ANALYSIS.md` F3. Generated output must never depend on this."""
    root = load(enclave)
    floating = [r for r in root.findall("filter/rule") if r.find("floating") is not None]
    assert len(floating) == 3, "DNS, NTP and ICMP"
    for rule in floating:
        assert rule.find("quick") is None, "the GT floating rules are not quick"


@pytest.mark.parametrize("enclave", ENCLAVES)
def test_permissive_defaults_are_present(enclave: str) -> None:
    """`EVIDENCE.md` E1 — every enclave shipped, and finished, with these."""
    root = load(enclave)
    permissive = [
        r
        for r in root.findall("filter/rule")
        if r.find("floating") is None
        and (r.findtext("type") or "") == "pass"
        and r.find("source/any") is not None
        and r.find("destination/any") is not None
    ]
    interface_count = len(interfaces(root))
    assert len(permissive) == interface_count, (
        "one pass any -> any per interface, WAN included"
    )


@pytest.mark.parametrize("enclave", ENCLAVES)
def test_lockout_critical_alias_is_present(enclave: str) -> None:
    """Narrow or drop `Remote_Access` and the team loses its own firewalls."""
    names = {a.findtext("name") for a in load(enclave).findall("aliases/alias")}
    assert {"Routers", "Remote_Access"} <= names


def test_routers_alias_carries_the_ipv6_defect() -> None:
    """`BASELINE-ANALYSIS.md` F1.

    On a deployed enclave the alias lists the Host Nation v6 prefix, so the
    routing rule never matches the real v6 peers. `V-ALIAS-FAMILY` and
    `V-ROUTING-PEERS` exist for this. Fixing it in the fixture would delete the
    evidence the validators are tested against.
    """
    do = load("do")
    routers = next(a for a in do.findall("aliases/alias") if a.findtext("name") == "Routers")
    address = routers.findtext("address") or ""
    assert "25.42.0.1" in address, "v4 peers are on the deployed prefix"
    assert "fd81:10:42::1" in address, "v6 entries are on the Host Nation prefix — the defect"
    assert "fd81:25:42::1" not in address, "the correct v6 peer is exactly what is missing"


@pytest.mark.parametrize("enclave", ENCLAVES)
def test_nat_is_disabled_and_has_no_port_forwards(enclave: str) -> None:
    """The baseline is pure routed — `SPEC.md` §7.3. A mode change is blocking."""
    root = load(enclave)
    assert (root.findtext("nat/outbound/mode") or "").strip() == "disabled"
    assert root.findall("nat/rule") == []
