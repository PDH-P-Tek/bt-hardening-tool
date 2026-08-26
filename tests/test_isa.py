"""Phase 2.6 — scoring check assignment.

The catalogue answers the question the estate documents do not: which ports are
*scored*. Everything here turns on it being a proposal. The mapping was read from one
board on one exercise, and both ways of being wrong are expensive — a check that runs
and was not allowed loses points silently, and a port assumed to be checked that is
not buys nothing while widening the firewall.
"""

from __future__ import annotations

from pathlib import Path

from btht.app.ingest.isa import EMPTY, assign, load_catalogue, required_ports

SHIPPED = Path(__file__).resolve().parents[1] / "isa-checks.yaml"


def catalogue():  # type: ignore[no-untyped-def]
    return load_catalogue(SHIPPED)


# --- the catalogue ---------------------------------------------------------


def test_the_shipped_catalogue_loads() -> None:
    loaded = catalogue()
    assert not loaded.is_empty
    assert "SSH" in loaded.checks
    assert loaded.checks["SSH"].ports == (22,)


def test_a_check_with_no_port_is_still_a_check() -> None:
    """An echo check has no port and is failed by blocking ICMP anywhere on the path."""
    host = catalogue().checks["HOST"]
    assert host.proto == "icmp"
    assert host.ports == ()


def test_roles_carry_the_check_sets_the_board_showed() -> None:
    loaded = catalogue()
    assert "RDP" in loaded.propose("windows_workstation")
    assert len(loaded.propose("domain_controller")) > 5, "the heaviest scored target"


def test_the_catalogue_warns_where_inference_would_be_wrong() -> None:
    """The database role is checked on SSH only. Assuming the engine port is scored
    would widen the firewall for nothing."""
    loaded = catalogue()
    assert loaded.propose("database") == ("HOST", "SSH")
    assert "do not infer the reverse" in loaded.role_notes["database"].lower()


# --- with no catalogue at all ----------------------------------------------


def test_with_no_catalogue_nothing_is_proposed() -> None:
    """The tool works without one. Inventing a scored port list would be worse."""
    assert load_catalogue(None) is EMPTY
    assert load_catalogue(Path("does-not-exist.yaml")).is_empty


def test_with_no_catalogue_the_operator_is_told_why_nothing_is_scored() -> None:
    result = assign("dc01", "domain_controller", (), EMPTY)
    assert result.proposed == ()
    assert any("No scoring catalogue is loaded" in w for w in result.warnings)


def test_with_no_catalogue_no_ports_are_required() -> None:
    assert required_ports(("SSH",), EMPTY) == ()


# --- proposing, and confirming ---------------------------------------------


def test_a_proposal_is_not_a_decision() -> None:
    """Nothing is confirmed until the operator confirms it against the board."""
    result = assign("ws01", "windows_workstation", (), catalogue())
    assert result.proposed != ()
    assert result.confirmed == ()
    assert result.needs_confirming is True


def test_confirming_the_proposal_settles_it() -> None:
    loaded = catalogue()
    proposed = loaded.propose("windows_workstation")
    result = assign("ws01", "windows_workstation", proposed, loaded)
    assert result.needs_confirming is False


def test_a_host_with_no_checks_is_asked_about_rather_than_assumed_unscored() -> None:
    """`V-SCORING-UNCHECKED` — confirm it really is unscored."""
    result = assign("mystery", "", (), catalogue())
    assert any("really is unscored" in w for w in result.warnings)


def test_an_unknown_check_name_is_surfaced() -> None:
    """A check the catalogue cannot price generates no rule. Silence would hide that."""
    result = assign("web01", "web_server", ("HTTPS", "QUANTUM"), catalogue())
    assert any("QUANTUM" in w for w in result.warnings)


def test_a_check_an_inbound_rule_cannot_satisfy_says_so() -> None:
    """`V-EGRESS-CHECK`. Two enclaves in the evidence shipped an egress block that
    failed exactly this kind of check outright."""
    loaded = catalogue()
    egress_checks = [c.name for c in loaded.checks.values() if not c.satisfiable_by_ingress]
    assert egress_checks, "the catalogue must still describe at least one"
    result = assign("host", "", (egress_checks[0],), loaded)
    assert any("No inbound rule satisfies it" in w for w in result.warnings)


def test_an_out_of_bounds_host_is_noted_as_never_a_target() -> None:
    result = assign("scoringbot", "", ("HOST",), catalogue(), out_of_bounds=True)
    assert any("never be a policy target" in n for n in result.notes)


def test_the_catalogues_own_warnings_reach_the_operator() -> None:
    """Notes in the catalogue exist to be read, not to sit in a YAML file."""
    result = assign("dc01", "domain_controller", (), catalogue())
    assert any("easiest to half-break" in n for n in result.notes)


# --- what generation and verification both read ----------------------------


def test_required_ports_is_one_list_for_both_consumers() -> None:
    """The scoring rules and the verification manifest are built from this.

    One list, so the ruleset and the thing that checks the ruleset cannot disagree
    about what was supposed to be open.
    """
    loaded = catalogue()
    ports = required_ports(loaded.propose("web_server"), loaded)
    assert ("tcp", 443) in ports
    assert ("icmp", 0) in ports, "the echo check carries no port but still must pass"
    assert ports == tuple(sorted(set(ports))), "deduplicated and ordered"


def test_ports_that_no_ingress_rule_can_open_are_left_out() -> None:
    loaded = catalogue()
    egress_checks = tuple(c.name for c in loaded.checks.values() if not c.satisfiable_by_ingress)
    assert required_ports(egress_checks, loaded) == ()
