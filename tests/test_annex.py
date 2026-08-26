"""Phase 2.5 — annex paste-parse.

Every case here is a shape the same table takes after a trip through a clipboard.
The parser is judged on two things: it must not lose a row, and it must not invent
one. Everything it produces is shown back for confirmation, so a row it got wrong
costs a correction — a row it silently dropped costs a host nobody notices is missing
until a probe fails.
"""

from __future__ import annotations

import pytest

from btht.app.ingest.annex import (
    Row,
    looks_out_of_bounds,
    parse_rows,
    split_kinds,
)

TAB_SEPARATED = """Hostname\tIPv4\tIPv6\tDescription
dc01\t192.0.2.5\t2001:db8:2::5\tDomain controller
web01\t192.0.2.10\t2001:db8:2::10\tPublic web server
"""

SPACE_ALIGNED = """Host name        IPv4            IPv6                 Description
dc01             192.0.2.5       2001:db8:2::5        Domain controller
web01            192.0.2.10      2001:db8:2::10       Public web server
"""

NO_HEADER_NO_V6 = """dc01   192.0.2.5    Domain controller
web01  192.0.2.10   Public web server
"""

SUBNETS = """Name              IPv4             IPv6              Domain
Workstations      192.0.2.0/24     2001:db8:2::/64   ws.example
Servers           192.0.3.0/24     2001:db8:3::/64   svrs.example
"""


@pytest.mark.parametrize("text", [TAB_SEPARATED, SPACE_ALIGNED, NO_HEADER_NO_V6])
def test_the_same_table_parses_whatever_the_clipboard_did_to_it(text: str) -> None:
    rows = parse_rows(text)
    assert len(rows) == 2, "no row lost to whitespace"
    assert [r.name for r in rows] == ["dc01", "web01"]
    assert [r.v4 for r in rows] == ["192.0.2.5", "192.0.2.10"]


def test_headings_are_dropped_and_data_is_not() -> None:
    assert len(parse_rows(TAB_SEPARATED)) == 2
    assert all("Hostname" not in r.name for r in parse_rows(TAB_SEPARATED))


def test_ipv6_is_read_when_present_and_not_invented_when_absent() -> None:
    """IPv6 is scored, so a missing address must be visibly missing, not assumed."""
    with_v6 = parse_rows(TAB_SEPARATED)
    without = parse_rows(NO_HEADER_NO_V6)
    assert all(r.v6 for r in with_v6)
    assert all(r.v6 == "" for r in without)


def test_descriptions_survive() -> None:
    rows = parse_rows(TAB_SEPARATED)
    assert rows[0].description == "Domain controller"
    assert rows[1].description == "Public web server"


def test_subnets_and_hosts_are_told_apart_by_their_addresses() -> None:
    """The operator does not have to say which table they pasted."""
    networks, hosts = split_kinds(parse_rows(SUBNETS + TAB_SEPARATED))
    assert [r.name for r in networks] == ["Workstations", "Servers"]
    assert [r.name for r in hosts] == ["dc01", "web01"]
    assert networks[0].v4 == "192.0.2.0/24"


def test_a_line_it_cannot_read_is_shown_rather_than_dropped() -> None:
    """Losing a host quietly is worse than showing a row that needs fixing."""
    rows = parse_rows("dc01\t192.0.2.5\tDomain controller\nsomething odd here\n")
    assert len(rows) == 2
    assert rows[1].looks_complete is False
    assert rows[1].source_line == "something odd here"


def test_every_row_keeps_the_line_it_came_from() -> None:
    """The preview shows the parse beside the paste, so a mis-parse is visible."""
    for row in parse_rows(TAB_SEPARATED):
        assert row.source_line.strip()
        assert row.name in row.source_line


def test_an_address_shaped_thing_that_is_not_an_address_is_not_accepted() -> None:
    """`999.1.1.1` is address-shaped and is not an address."""
    rows = parse_rows("thing\t999.1.1.1\tnot a real address\n")
    assert rows[0].v4 == ""


def test_out_of_bounds_hosts_are_detected_from_the_annexs_own_words() -> None:
    """`BASELINE-ANALYSIS.md` F8 — flagged for confirmation, never applied on a word."""
    rows = parse_rows(
        "scoringbot\t192.0.2.254\tEXCON. Out of Bounds. Not shown on diagram\n"
        "dc01\t192.0.2.5\tDomain controller\n"
    )
    assert looks_out_of_bounds(rows[0]) is True
    assert looks_out_of_bounds(rows[1]) is False


def test_prose_between_tables_does_not_become_a_host() -> None:
    """Annexes are documents. A sentence pasted with the table is not a device."""
    rows = parse_rows(
        "The following devices are known to exist within the enclave and are "
        "documented for your awareness during the exercise period.\n"
        "dc01\t192.0.2.5\tDomain controller\n"
    )
    assert len(rows) == 1
    assert rows[0].name == "dc01"


def test_an_empty_paste_produces_nothing_rather_than_failing() -> None:
    assert parse_rows("") == ()
    assert parse_rows("\n\n   \n") == ()


def test_parsing_never_raises_on_rubbish() -> None:
    """The operator pastes what they have. The tool reports, it does not crash."""
    for rubbish in ("<<<>>>", "\x00\x01", "192.0.2", "::::::::", "a" * 500):
        assert isinstance(parse_rows(rubbish), tuple)


def test_a_row_knows_whether_it_is_usable() -> None:
    assert Row(name="dc01", v4="192.0.2.5").looks_complete is True
    assert Row(name="dc01").looks_complete is False
    assert Row(name="", v4="192.0.2.5").looks_complete is False
