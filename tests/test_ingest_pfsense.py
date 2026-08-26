"""Phase 1.1 — the pfSense parser.

The test that matters most here is the last one: a configuration full of
credential material must produce a parse containing none of it. `SPEC.md` §10.2
requires that to be proved rather than assumed, which is what the synthetic
fixture exists for.
"""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path

import pytest

from btht.app.ingest.pfsense import ParseError, parse_file, pf_bool, pf_flag_present
from btht.app.model.rules import Action, AliasRef, AnyEndpoint, Family, SelfEndpoint

FIXTURES = Path(__file__).resolve().parents[1] / "tests" / "fixtures"
BASELINE = FIXTURES / "baseline"
ENCLAVES = ("do", "dsoc", "mcu")


def load(enclave: str):  # type: ignore[no-untyped-def]
    return parse_file(BASELINE / f"{enclave}-baseline.xml")


# --- the boolean trap ------------------------------------------------------


def test_pf_bool_reads_empty_as_false_and_yes_as_true() -> None:
    """`BASELINE-ANALYSIS.md` §1. Backwards, and every real config looks unlocked."""
    import xml.etree.ElementTree as ET

    assert pf_bool(ET.fromstring("<noantilockout></noantilockout>")) is False
    assert pf_bool(ET.fromstring("<disablenatreflection>yes</disablenatreflection>")) is True
    assert pf_bool(None) is False


def test_the_two_boolean_conventions_stay_separate() -> None:
    """`pf_flag_present` is the other convention and must not be confused with it."""
    import xml.etree.ElementTree as ET

    empty = ET.fromstring("<disabled></disabled>")
    assert pf_bool(empty) is False
    assert pf_flag_present(empty) is True


@pytest.mark.parametrize("enclave", ENCLAVES)
def test_antilockout_is_read_as_enabled(enclave: str) -> None:
    """The element is `noantilockout`, so empty means anti-lockout is ON."""
    assert load(enclave).facts.antilockout_enabled is True


# --- the fact list ---------------------------------------------------------


@pytest.mark.parametrize("enclave", ENCLAVES)
def test_facts_are_read(enclave: str) -> None:
    facts = load(enclave).facts
    assert facts.config_version == "23.3"
    assert facts.filter_descriptions is True


def test_frr_peers_are_read() -> None:
    """Needed by `V-ROUTING-PEERS`: the peers are how the alias defect is proved."""
    facts = load("do").facts
    assert facts.frr_bfd_peers == ("25.42.0.1", "25.42.0.2", "fd81:25:42::1", "fd81:25:42::2")
    assert facts.frr_ospf_router_ids == ("25.42.0.10",)


# --- sections --------------------------------------------------------------


@pytest.mark.parametrize("enclave", ENCLAVES)
def test_all_four_sections_present_in_a_full_export(enclave: str) -> None:
    assert load(enclave).sections_present == {"aliases", "filter", "nat", "interfaces"}


def test_partial_export_records_what_was_missing() -> None:
    """A section export is normal. A silently empty section is not."""
    parsed = parse_file(BASELINE / "do-baseline.xml")
    only_aliases = (
        "<pfsense><aliases>"
        + "".join(
            f"<alias><name>{a.name}</name><type>{a.type}</type>"
            f"<address>{' '.join(a.entries)}</address></alias>"
            for a in parsed.aliases
        )
        + "</aliases></pfsense>"
    )
    from btht.app.ingest.pfsense import parse_string

    partial = parse_string(only_aliases)
    assert partial.sections_present == {"aliases"}
    assert partial.rules == ()
    assert len(partial.aliases) == 2


def test_rejects_a_file_that_is_not_a_pfsense_config() -> None:
    from btht.app.ingest.pfsense import parse_string

    with pytest.raises(ParseError):
        parse_string("<opnsense><filter/></opnsense>")


# --- rules -----------------------------------------------------------------


@pytest.mark.parametrize("enclave", ENCLAVES)
def test_floating_rules_parse_as_non_quick_across_several_interfaces(enclave: str) -> None:
    """`BASELINE-ANALYSIS.md` F3 — and the plural is why `interfaces` is a tuple."""
    floating = [r for r in load(enclave).rules if r.floating]
    assert len(floating) == 3
    for rule in floating:
        assert rule.quick is False
        assert len(rule.interfaces) > 1
        assert rule.family is Family.INET46


def test_endpoints_normalise_to_the_tagged_union() -> None:
    rules = load("do").rules
    vpn = next(r for r in rules if r.descr == "VPN access for exercise participants")
    assert vpn.source == AliasRef("Remote_Access")
    assert isinstance(vpn.destination, AnyEndpoint)

    routing = next(r for r in rules if r.descr == "Routing information exchange")
    assert routing.source == AliasRef("Routers")
    assert isinstance(routing.destination, SelfEndpoint)

    outbound = next(r for r in rules if r.descr == "Firewall outbound traffic")
    assert isinstance(outbound.source, SelfEndpoint)


def test_ports_parse_to_specs() -> None:
    dns = next(r for r in load("do").rules if r.protocol == "tcp/udp")
    assert [(p.low, p.high) for p in dns.destination_ports] == [(53, 53)]
    ntp = next(r for r in load("do").rules if r.protocol == "udp")
    assert [(p.low, p.high) for p in ntp.destination_ports] == [(123, 123)]


@pytest.mark.parametrize("enclave", ENCLAVES)
def test_permissive_defaults_survive_the_parse(enclave: str) -> None:
    """`EVIDENCE.md` E1. The parser must not quietly tidy these away."""
    parsed = load(enclave)
    permissive = [
        r
        for r in parsed.rules
        if r.action is Action.PASS
        and isinstance(r.source, AnyEndpoint)
        and isinstance(r.destination, AnyEndpoint)
        and not r.floating
    ]
    assert len(permissive) == len(parsed.interfaces)


@pytest.mark.parametrize("enclave", ENCLAVES)
def test_nat_is_disabled_with_no_forwards(enclave: str) -> None:
    nat = load(enclave).nat
    assert nat.outbound_mode == "disabled"
    assert nat.port_forwards == ()


# --- the one that matters --------------------------------------------------


def test_parsing_a_credential_bearing_config_retains_no_credential_material() -> None:
    """`SPEC.md` §10.2 and non-negotiable 2.

    The fixture carries a bcrypt hash, a private key, an authorised key and a
    cleartext service password alongside the three sections the tool reads. None
    of it may appear anywhere in the result — not in a field, not in a nested
    object, not in a description carried along for display.
    """
    source = FIXTURES / "credentials" / "synthetic-secrets.xml"
    parsed = parse_file(source)
    haystack = repr(asdict(parsed)).lower()

    forbidden = (
        "$2y$",
        "begin private key",
        "syntheticnotarealhash",
        "syntheticservicepassword",
        "c3nolwvkmju1mtkg",  # the authorised-key blob, lowercased
        "rocommunity",
        "public",
    )
    # Guard against a vacuous pass. If the needles are not in the *input*, this
    # test proves nothing, and would keep proving nothing after someone edited
    # the fixture. Assert the material is there to be leaked before asserting
    # that it was not.
    original = source.read_text(encoding="utf-8").lower()
    absent = [needle for needle in forbidden if needle not in original]
    assert not absent, f"needles missing from the fixture, so the test is vacuous: {absent}"

    leaked = [needle for needle in forbidden if needle in haystack]
    assert not leaked, f"credential material survived the parse: {leaked}"

    # And it still did its actual job.
    assert parsed.facts.config_version == "23.3"
    assert len(parsed.rules) == 1
    assert parsed.rules[0].source == AliasRef("Remote_Access")


# --- against the shape of a real build template -----------------------------


def test_the_shipped_template_shape_parses() -> None:
    """Reproduces the real Green Team build template, and it contradicted three
    assumptions the hand-built fixtures had baked in."""
    parsed = parse_file(FIXTURES / "credentials" / "gt-build-template.xml")

    floating = [r for r in parsed.rules if r.floating]
    assert floating and all(r.interfaces == ("any",) for r in floating), (
        "the shipped floating rules bind to `any`, not to a comma-separated list"
    )
    assert floating[0].state_type == "keep state", "written as CDATA in the real file"


def test_a_rule_on_any_interface_is_the_same_identity_as_one_on_all_of_them() -> None:
    """Otherwise the shipped baseline and its generated equivalent never match."""
    from dataclasses import replace

    from btht.app.ingest.fingerprint import strict_fingerprint
    from btht.app.ingest.normalise import Template

    parsed = parse_file(FIXTURES / "credentials" / "gt-build-template.xml")
    on_any = next(r for r in parsed.rules if r.floating)
    spelled_out = replace(on_any, interfaces=("wan", "ws", "svrs", "dmz"))
    roles = frozenset({"wan", "ws", "svrs", "dmz"})
    assert strict_fingerprint(on_any, {}, Template(), roles) == strict_fingerprint(
        spelled_out, {}, Template(), roles
    )


def test_the_frr_peers_are_read_from_where_they_actually_live() -> None:
    """`frrbfdpeers` is a sibling of `frr`, not a child.

    Nested wrongly it cost nothing visible: the list came back empty and
    `V-ROUTING-PEERS` stayed silent on every real configuration while appearing to
    have checked. It is the evidence that proves the alias defect (F1).
    """
    facts = parse_file(FIXTURES / "credentials" / "gt-build-template.xml").facts
    assert facts.frr_bfd_peers == ("25.42.0.1", "25.42.0.2", "fd81:25:42::1", "fd81:25:42::2")
    assert facts.frr_ospf_router_ids == ("25.42.0.10",)


def test_the_routers_alias_defect_is_visible_against_the_real_peers() -> None:
    """F1, provable rather than asserted: the alias lists fd81:10, the peers are fd81:25."""
    parsed = parse_file(FIXTURES / "credentials" / "gt-build-template.xml")
    routers = next(a for a in parsed.aliases if a.name == "Routers")
    v6_in_alias = [e for e in routers.entries if e.startswith("fd81:")]
    v6_peers = [p for p in parsed.facts.frr_bfd_peers if p.startswith("fd81:")]
    assert v6_in_alias and v6_peers
    assert not set(v6_in_alias) & set(v6_peers), "the alias covers none of the real v6 peers"


def test_reading_the_template_retains_no_credential_material() -> None:
    from dataclasses import asdict

    parsed = parse_file(FIXTURES / "credentials" / "gt-build-template.xml")
    haystack = repr(asdict(parsed)).lower()
    for needle in ("$6$", "synthetichash", "syntheticpackagepassword", "rocommunity", "nopasswd"):
        assert needle not in haystack, f"{needle} survived the parse"
