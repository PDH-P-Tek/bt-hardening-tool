"""Phase 9.4 — the topology, with progressive disclosure.

The range this is modelled on is a wall poster: sixteen thousand pixels wide, hundreds
of machines. Everything-at-once is unreadable on a laptop at three in the morning, so
the top level is one firewall per enclave, a click opens its segments, and another
opens the machines on one.

What is open lives in the URL. That keeps the layout a pure function of
`(estate, open, filtered)` — so the determinism test still means something, a
particular view is a link you can send someone, and four hundred hosts are not rendered
into the page to sit hidden.
"""

from __future__ import annotations

from collections.abc import Iterator
from ipaddress import IPv4Address, IPv4Interface, IPv6Address
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from btht.app import data as data_module
from btht.app.main import app
from btht.app.model.estate import Estate, Firewall, Host, HostGroup, Interface, Node, Platform
from btht.app.model.policy import save_estate
from btht.app.model.services import load_catalogue
from btht.app.web.topology import View, layout, render_svg

CATALOGUE = load_catalogue(Path(__file__).resolve().parents[1] / "service-catalogue.yaml")


def an_estate() -> Estate:
    node = Node(
        name="fw1.alpha",
        platform=Platform.PFSENSE,
        mgmt_address=IPv4Address("10.9.0.1"),
        enclave="alpha",
        gui_url="https://10.9.0.1/",
        ssh_user="analyst",
    )
    return Estate(
        team=42,
        team_padded="42",
        role_vocabulary=("wan", "users", "servers"),
        firewalls=(
            Firewall(
                enclave="alpha",
                fqdn="fw1.alpha.example",
                node=node,
                interfaces=(
                    Interface(ifname="wan", role="wan", v4=IPv4Interface("198.51.100.2/24")),
                    Interface(
                        ifname="lan",
                        role="users",
                        v4=IPv4Interface("192.0.2.1/24"),
                        is_lan=True,
                    ),
                    Interface(ifname="opt1", role="servers", v4=IPv4Interface("192.0.3.1/24")),
                ),
                hosts=(
                    Host(
                        hostname="dc01",
                        os="Windows Server 2022",
                        v4=IPv4Address("192.0.3.5"),
                        v6=IPv6Address("2001:db8:3::5"),
                        segment_role="servers",
                        service_role="domain_controller",
                        services=("RDP", "SMB"),
                        isa_checks=("HOST", "SMB"),
                    ),
                    Host(
                        hostname="npc-server",
                        os="Ubuntu 24.04",
                        v4=IPv4Address("192.0.2.249"),
                        segment_role="users",
                        out_of_bounds=True,
                    ),
                ),
                host_groups=(
                    HostGroup(
                        name_prefix="ws1",
                        count=6,
                        segment_role="users",
                        host_type="windows_workstation",
                        os="Windows 10 22H2",
                        v4_start=IPv4Address("192.0.2.10"),
                    ),
                ),
            ),
        ),
        nodes=(
            Node(
                name="r1",
                platform=Platform.FRR,
                mgmt_address=IPv4Address("198.51.100.254"),
                enclave="alpha",
            ),
        ),
    )


def shapes(view: View):  # type: ignore[no-untyped-def]
    return {s.detail_id: s for s in layout(an_estate(), view, "demo", CATALOGUE).shapes}


# --- progressive disclosure -------------------------------------------------


def test_the_top_level_is_one_firewall_per_enclave() -> None:
    """Not four hundred hosts. That is a wall poster, not a screen."""
    ids = shapes(View())
    assert "alpha" in ids
    assert "node:r1" in ids, "and what the enclaves connect through"
    assert not any(i.startswith("host:") for i in ids)
    assert "alpha:lan" not in ids


def test_a_collapsed_firewall_says_what_is_inside_it() -> None:
    """A closed box with no count gives no reason to open it."""
    assert "2 segments" in shapes(View())["alpha"].badge
    assert "hosts" in shapes(View())["alpha"].badge


def test_opening_a_firewall_shows_its_segments_and_not_its_hosts() -> None:
    ids = shapes(View(open_ids=frozenset({"alpha"})))
    assert "alpha:lan" in ids and "alpha:opt1" in ids
    assert not any(i.startswith("host:") for i in ids), "one level at a time"


def test_opening_a_segment_shows_the_machines_on_it() -> None:
    ids = shapes(View(open_ids=frozenset({"alpha", "alpha:opt1"})))
    assert "host:alpha:dc01" in ids
    assert "host:alpha:npc-server" not in ids, "that one is on the other segment"


def test_a_host_from_a_group_is_drawn_like_any_other() -> None:
    """A machine declared in a group of six is as real as one typed in alone."""
    ids = shapes(View(open_ids=frozenset({"alpha", "alpha:lan"})))
    assert "host:alpha:ws101" in ids
    assert "host:alpha:ws106" in ids


def test_closing_a_firewall_closes_what_was_open_inside_it() -> None:
    """Otherwise reopening it produces a picture nobody asked for."""
    view = View(open_ids=frozenset({"alpha", "alpha:lan", "alpha:opt1"}))
    assert view.toggled("alpha") == frozenset()


def test_open_everything_for_one_firewall_is_one_click() -> None:
    """The wall-poster view of a single enclave, when that is what you want."""
    link = View().open_all_link(an_estate().firewalls[0], "demo")
    assert "open=alpha" in link
    assert "open=alpha%3Alan" in link and "open=alpha%3Aopt1" in link


# --- what the picture is for ------------------------------------------------


def test_the_segment_with_the_safety_net_is_marked() -> None:
    marked = shapes(View(open_ids=frozenset({"alpha"})))["alpha:lan"]
    assert "anti-lockout" in marked.badge


def test_an_out_of_bounds_host_is_drawn_differently() -> None:
    open_users = View(open_ids=frozenset({"alpha", "alpha:lan"}))
    drawn = shapes(open_users)
    assert drawn["host:alpha:npc-server"].accent == "warn"
    assert drawn["host:alpha:ws101"].accent != "warn"


def test_a_host_addressed_outside_its_segment_is_reported() -> None:
    """The kind of setup error a form hides and a picture surfaces."""
    from dataclasses import replace

    estate = an_estate()
    wrong = replace(
        estate.firewalls[0],
        hosts=(replace(estate.firewalls[0].hosts[0], v4=IPv4Address("10.9.9.9")),),
    )
    diagram = layout(
        replace(estate, firewalls=(wrong,)),
        View(focus_id="alpha:opt1"),
        "demo",
        CATALOGUE,
    )
    assert any("outside this segment" in w for w in diagram.focus["warnings"])


def test_the_focused_host_shows_the_ports_its_services_imply() -> None:
    """The operator picks RDP; the tool says what that opens."""
    diagram = layout(an_estate(), View(focus_id="host:alpha:dc01"), "demo", CATALOGUE)
    fields = dict(diagram.focus["fields"])
    assert "tcp/3389" in fields["ports that implies"]
    assert fields["operating system"] == "Windows Server 2022"


# --- filters ----------------------------------------------------------------


def test_filtering_by_out_of_bounds_hides_the_rest_and_says_how_many() -> None:
    """A filtered view is not the estate, and must not be mistaken for it."""
    view = View(open_ids=frozenset({"alpha", "alpha:lan"}), only_out_of_bounds=True)
    diagram = layout(an_estate(), view, "demo", CATALOGUE)
    ids = {s.detail_id for s in diagram.shapes}
    assert "host:alpha:npc-server" in ids
    assert "host:alpha:ws101" not in ids
    # Seven, not six: the six workstations on the open segment plus dc01 on the
    # closed one. The filter hides them across the enclave, and the count says so
    # rather than only counting what happens to be expanded.
    assert diagram.hidden_by_filter == 7


def test_filtering_by_service_finds_what_runs_it() -> None:
    view = View(open_ids=frozenset({"alpha", "alpha:opt1"}), service="SMB")
    ids = {s.detail_id for s in layout(an_estate(), view, "demo", CATALOGUE).shapes}
    assert "host:alpha:dc01" in ids


def test_filtering_by_scored_finds_the_targets_that_cost_points() -> None:
    view = View(open_ids=frozenset({"alpha", "alpha:lan"}), only_scored=True)
    diagram = layout(an_estate(), view, "demo", CATALOGUE)
    assert not any(s.detail_id.startswith("host:") for s in diagram.shapes)
    assert diagram.hidden_by_filter == 7, "nothing on this segment is scored"


# --- the drawing ------------------------------------------------------------


def test_the_same_view_always_draws_the_same_picture() -> None:
    view = View(open_ids=frozenset({"alpha", "alpha:lan"}), focus_id="alpha")
    first = render_svg(layout(an_estate(), view, "demo", CATALOGUE))
    second = render_svg(layout(an_estate(), view, "demo", CATALOGUE))
    assert first == second


def test_a_firewall_is_linked_only_to_what_it_declares() -> None:
    """A line to every router would look like knowledge and be a guess.

    Which router an enclave actually peers with is what decides whether its routing
    rule covers the adjacency it needs, so the diagram draws what was declared and
    leaves the rest unconnected — visibly, so somebody fixes it.
    """
    from dataclasses import replace

    estate = an_estate()
    assert layout(estate, View(), "demo", CATALOGUE).links == [], (
        "nothing declared, so nothing drawn"
    )

    firewall = estate.firewalls[0]
    wired = replace(
        firewall,
        interfaces=tuple(
            replace(i, upstreams=("r1",)) if i.ifname == "wan" else i
            for i in firewall.interfaces
        ),
    )
    assert layout(replace(estate, firewalls=(wired,)), View(), "demo", CATALOGUE).links


def test_an_unconnected_firewall_says_so() -> None:
    diagram = layout(an_estate(), View(focus_id="alpha"), "demo", CATALOGUE)
    assert any("drawn unconnected" in w for w in diagram.focus["warnings"])


def test_each_segment_hangs_off_the_firewall_not_off_its_neighbour() -> None:
    """Stacked interfaces on one shared vertical read as a chain, which is not the wiring.

    One spine drops from the firewall and each segment gets its own stub off it.
    """
    diagram = layout(an_estate(), View(open_ids=frozenset({"alpha"})), "demo", CATALOGUE)
    stubs = [link for link in diagram.links if link.shape == "line" and link.y1 == link.y2]
    spines = [link for link in diagram.links if link.shape == "line" and link.x1 == link.x2]
    assert len(stubs) == 2, "one per segment"
    assert len(spines) == 1, "and one spine for the firewall"
    assert len({stub.y1 for stub in stubs}) == 2, "each at its own height"


def test_no_text_escapes_its_box() -> None:
    from btht.app.web.topology import LABEL_BASELINE, SUBLABEL_BASELINE

    for shape in layout(
        an_estate(), View(open_ids=frozenset({"alpha", "alpha:lan"})), "demo", CATALOGUE
    ).shapes:
        assert shape.height > LABEL_BASELINE
        assert shape.height > SUBLABEL_BASELINE


def test_the_svg_references_nothing_external() -> None:
    svg = render_svg(layout(an_estate(), View(), "demo", CATALOGUE))
    fetchable = svg.replace('xmlns="http://www.w3.org/2000/svg"', "")
    assert "<image" not in fetchable and "<script" not in fetchable
    assert "http://" not in fetchable and "https://" not in fetchable


def test_connect_hands_off_and_never_holds_a_session() -> None:
    """`MONITORING.md` §2 and §13 — a built-in terminal would mean this tool holding a
    shell credential to a firewall."""
    diagram = layout(an_estate(), View(focus_id="alpha"), "demo", CATALOGUE)
    kinds = {a["kind"]: a for a in diagram.focus["actions"]}
    assert kinds["gui"]["href"] == "https://10.9.0.1/"
    assert kinds["ssh"]["href"] == "ssh://analyst@10.9.0.1"
    assert kinds["copy"]["href"] == "ssh analyst@10.9.0.1"


# --- served -----------------------------------------------------------------


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    store = tmp_path / "estates"
    monkeypatch.setattr(data_module, "ESTATES", store)
    monkeypatch.setattr("btht.app.web.routes.ESTATES", store)
    save_estate(an_estate(), store / "range.yaml")
    with TestClient(app) as test_client:
        yield test_client


def test_a_view_is_a_link_that_can_be_sent_to_someone(client: TestClient) -> None:
    body = client.get("/range/topology?open=alpha&open=alpha%3Aopt1&focus=alpha").text
    assert 'data-detail="host:alpha:dc01"' in body
    assert "fw1.alpha.example" in body, "the focused detail is rendered server-side"


def test_the_page_sends_you_elsewhere_to_change_anything(client: TestClient) -> None:
    """It must never read as a second place the range can be edited."""
    body = client.get("/range/topology").text
    assert "To change anything, go to" in body
    assert 'href="/range"' in body


def test_the_page_loads_no_external_assets(client: TestClient) -> None:
    body = client.get("/range/topology").text
    assert "<script src" not in body and "cdn." not in body
