"""Phase 8.2 — the verification manifest and nmap import.

A generated ruleset is a claim; this is how the claim gets tested. The two properties
that matter most are both about refusing to be comforting: an unscanned assertion is a
failure rather than a pass, and a target outside the estate's own space is refused
rather than warned about.
"""

from __future__ import annotations

from ipaddress import IPv4Address
from pathlib import Path

import pytest
from conftest import a_firewall

from btht.app.generate.manifest import (
    Assertion,
    Manifest,
    OutOfScope,
    ScanResult,
    build,
    in_scope,
    nmap_command,
    parse_nmap,
    verify,
)
from btht.app.ingest.isa import load_catalogue
from btht.app.model.policy import EgressPolicy, FirewallPolicy, Selector, ServiceRule

CATALOGUE = load_catalogue(Path(__file__).resolve().parents[1] / "isa-checks.yaml")


def an_entry() -> FirewallPolicy:
    return FirewallPolicy(
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


def a_manifest() -> Manifest:
    return build(a_firewall(), an_entry(), CATALOGUE, segment="servers", policy_text="x")


# --- the guardrail ----------------------------------------------------------


def test_a_target_outside_the_estate_is_refused_not_warned_about() -> None:
    """`VERIFICATION.md` — scanning space you are not responsible for is a hostile act.

    Made impossible rather than discouraged, because it is exactly the mistake someone
    makes at speed by pasting the wrong range.
    """
    from dataclasses import replace

    from btht.app.model.estate import Host

    stray = replace(
        a_firewall(),
        hosts=(
            Host(
                hostname="somebody-elses",
                v4=IPv4Address("10.99.99.9"),
                segment_role="servers",
                isa_checks=("SSH",),
            ),
        ),
    )
    with pytest.raises(OutOfScope, match="hostile act"):
        build(stray, an_entry(), CATALOGUE, segment="servers")


def test_in_scope_only_accepts_the_declared_segments() -> None:
    firewall = a_firewall()
    assert in_scope("192.0.3.5", firewall) is True
    assert in_scope("10.99.99.9", firewall) is False
    assert in_scope("not-an-address", firewall) is False


# --- what a good manifest contains ------------------------------------------


def test_every_scored_check_becomes_an_open_assertion() -> None:
    """A failure here is points lost, so these are the non-negotiable ones."""
    manifest = a_manifest()
    scored = [a for a in manifest.assertions if a.why.startswith("scored check")]
    assert scored
    assert all(a.expect == "open" for a in scored)


def test_assertions_exist_in_both_families_where_the_host_has_both() -> None:
    """A v4-only pass is a partial pass, and that is the most common silent failure."""
    manifest = a_manifest()
    families = {a.family for a in manifest.assertions if a.why.startswith("scored check")}
    assert families == {4, 6}


def test_a_single_family_host_says_it_can_only_be_half_proved() -> None:
    from dataclasses import replace

    single = replace(
        a_firewall(),
        hosts=tuple(replace(h, v6=None) for h in a_firewall().hosts),
    )
    manifest = build(single, an_entry(), CATALOGUE, segment="servers")
    assert any("only prove half of it" in a.why for a in manifest.assertions)


def test_it_includes_assertions_that_something_is_shut() -> None:
    """The half people skip, and the half that catches a catch-all."""
    closed = [a for a in a_manifest().assertions if a.expect == "closed"]
    assert closed
    assert "catch-all" in closed[0].why


def test_the_manifest_names_the_position_it_must_be_run_from() -> None:
    """A rule permitting ws to svrs can only be proved from the workstation segment."""
    manifest = a_manifest()
    assert manifest.segment == "servers"
    assert "servers segment" in manifest.note


def test_the_manifest_serialises_to_the_documented_shape() -> None:
    document = a_manifest().to_document()["manifest"]
    assert set(document) == {"firewall", "policy_sha256", "position", "assertions"}
    assert "assertions:" in a_manifest().to_yaml()


# --- running it -------------------------------------------------------------


def test_the_scan_command_is_conservative() -> None:
    """Availability checks run throughout; an aggressive scan muddies the baseline."""
    command = nmap_command(a_manifest())
    assert "-T3" in command
    assert "-Pn" in command
    assert "-A" not in command and "-T5" not in command


def test_the_ipv6_command_forces_the_v6_path() -> None:
    """The only reliable way to prove both families rather than assuming."""
    assert nmap_command(a_manifest(), family=6).startswith("nmap -6 ")


def test_nmap_output_is_imported_not_produced() -> None:
    xml = """<nmaprun><host><address addr="192.0.3.5" addrtype="ipv4"/>
      <ports><port portid="389"><state state="open"/></port>
      <port portid="3306"><state state="filtered"/></port></ports></host></nmaprun>"""
    results = parse_nmap(xml)
    assert ScanResult("192.0.3.5", 389, True) in results
    assert ScanResult("192.0.3.5", 3306, False) in results


def test_malformed_scan_output_yields_nothing_rather_than_raising() -> None:
    assert parse_nmap("<not xml") == ()


# --- the comparison ---------------------------------------------------------


def test_an_unscanned_assertion_is_a_failure_not_a_pass() -> None:
    """Otherwise a manifest comes back green having tested half of what it claimed."""
    manifest = Manifest(
        firewall="fw1",
        segment="servers",
        assertions=(Assertion("192.0.3.5", 389, "tcp", "open", "scored check: dc01"),),
    )
    outcome = verify(manifest, ())
    assert outcome[0].passed is False
    assert outcome[0].observed == "not scanned"


def test_an_expected_closed_port_that_answers_is_a_failure() -> None:
    manifest = Manifest(
        firewall="fw1",
        segment="servers",
        assertions=(Assertion("192.0.3.5", 3306, "tcp", "closed", "not in policy"),),
    )
    outcome = verify(manifest, (ScanResult("192.0.3.5", 3306, True),))
    assert outcome[0].passed is False
    assert outcome[0].observed == "open"


def test_a_match_passes_in_both_directions() -> None:
    manifest = Manifest(
        firewall="fw1",
        segment="servers",
        assertions=(
            Assertion("192.0.3.5", 389, "tcp", "open", "scored"),
            Assertion("192.0.3.5", 3306, "tcp", "closed", "not in policy"),
        ),
    )
    outcome = verify(
        manifest,
        (ScanResult("192.0.3.5", 389, True), ScanResult("192.0.3.5", 3306, False)),
    )
    assert all(v.passed for v in outcome)
