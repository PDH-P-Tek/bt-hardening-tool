"""Phase 2.2 — the topology view and its connect actions.

Two things are asserted here that a screenshot would not show. The picture is a pure
function of the estate, so it cannot drift between runs; and the connect actions hand
off to the operator's own software rather than giving this tool a session of its own.
"""

from __future__ import annotations

from collections.abc import Iterator
from ipaddress import IPv4Address, IPv4Interface
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from btht.app import data as data_module
from btht.app.main import app
from btht.app.model.estate import (
    Estate,
    Firewall,
    Host,
    Interface,
    Node,
    Platform,
)
from btht.app.model.policy import save_estate
from btht.app.web.topology import details_json, layout, render_svg


def an_estate() -> Estate:
    firewall_node = Node(
        name="fw1.alpha",
        platform=Platform.PFSENSE,
        mgmt_address=IPv4Address("10.9.0.1"),
        credential_ref="monitor-key",
        enclave="alpha",
        gui_url="https://10.9.0.1/",
        ssh_user="analyst",
    )
    router = Node(
        name="r1",
        platform=Platform.FRR,
        mgmt_address=IPv4Address("10.9.0.254"),
        enclave="alpha",
    )
    return Estate(
        team=42,
        team_padded="42",
        role_vocabulary=("wan", "users", "servers"),
        firewalls=(
            Firewall(
                enclave="alpha",
                fqdn="fw1.alpha.example",
                node=firewall_node,
                side="north",
                config_version="23.3",
                interfaces=(
                    Interface(ifname="wan", role="wan", v4=IPv4Interface("198.51.100.2/24")),
                    Interface(
                        ifname="lan",
                        role="users",
                        v4=IPv4Interface("192.0.2.1/24"),
                        is_lan=True,
                    ),
                    Interface(ifname="opt1", role="other:mystery"),
                ),
                hosts=(
                    Host(
                        hostname="scoring",
                        v4=IPv4Address("192.0.2.254"),
                        segment_role="users",
                        out_of_bounds=True,
                    ),
                ),
            ),
        ),
        nodes=(router,),
    )


# --- the drawing -----------------------------------------------------------


def test_the_same_estate_always_draws_the_same_picture() -> None:
    """A view that shifts between runs is a view nobody can diff or trust."""
    assert render_svg(layout(an_estate())) == render_svg(layout(an_estate()))
    assert details_json(layout(an_estate())) == details_json(layout(an_estate()))


def test_the_svg_references_nothing_external() -> None:
    """The `xmlns` namespace is an identifier, not a fetch — everything else must be absent."""
    svg = render_svg(layout(an_estate()))
    fetchable = svg.replace('xmlns="http://www.w3.org/2000/svg"', "")
    assert "<image" not in fetchable
    assert "<script" not in fetchable
    assert "href" not in fetchable
    assert "http://" not in fetchable and "https://" not in fetchable


def test_every_declared_thing_is_on_the_diagram() -> None:
    diagram = layout(an_estate())
    ids = {shape.detail_id for shape in diagram.shapes}
    assert "fw:alpha" in ids
    assert "if:alpha:lan" in ids
    assert "node:r1" in ids, "a router is part of the estate even with no ruleset"
    assert ids == set(diagram.details), "everything clickable has a detail, and vice versa"


def test_no_text_escapes_its_box() -> None:
    """The one layout fault that reads fine in code and looks broken on screen."""
    from btht.app.web.topology import LABEL_BASELINE, SUBLABEL_BASELINE

    for shape in layout(an_estate()).shapes:
        assert shape.height > LABEL_BASELINE, f"{shape.detail_id}: label outside its box"
        assert shape.height > SUBLABEL_BASELINE, f"{shape.detail_id}: sublabel outside its box"


def test_shapes_do_not_overlap_each_other() -> None:
    """Overlapping boxes make the wrong thing clickable."""
    shapes = [s for s in layout(an_estate()).shapes if s.kind == "segment"]
    ordered = sorted(shapes, key=lambda s: s.y)
    for above, below in zip(ordered, ordered[1:], strict=False):
        assert above.y + above.height <= below.y, f"{above.detail_id} overlaps {below.detail_id}"


def test_an_unplaced_interface_is_drawn_differently() -> None:
    """An interface the declared vocabulary could not place must look wrong."""
    shapes = {s.detail_id: s for s in layout(an_estate()).shapes}
    assert shapes["if:alpha:opt1"].accent == "warn"
    assert shapes["if:alpha:lan"].accent != "warn"


# --- what the picture is for -----------------------------------------------


def test_the_segment_with_the_safety_net_says_so() -> None:
    details = layout(an_estate()).details
    warnings = " ".join(details["if:alpha:lan"]["warnings"])
    assert "Anti-lockout binds" in warnings
    assert "the others do not have one" in warnings


def test_an_out_of_bounds_host_warns_on_the_segment_it_hides_in() -> None:
    """`BASELINE-ANALYSIS.md` F8 — they are inside the segment, and on no diagram.

    Tightening that segment is exactly what the operator is there to do, and doing it
    blind breaks scoring from the inside. This is the view that can say so.
    """
    # Details are keyed by ifname, which is unique per firewall; here the user
    # segment is `lan`, which is also where an out-of-bounds host really would sit.
    warnings = " ".join(layout(an_estate()).details["if:alpha:lan"]["warnings"])
    assert "Out of bounds inside this segment" in warnings
    assert "scoring" in warnings


# --- connect ---------------------------------------------------------------


def test_a_device_offers_the_gui_and_an_ssh_handoff() -> None:
    actions = {a["kind"]: a for a in layout(an_estate()).details["fw:alpha"]["actions"]}
    assert actions["gui"]["href"] == "https://10.9.0.1/"
    assert actions["ssh"]["href"] == "ssh://analyst@10.9.0.1"
    assert actions["copy"]["href"] == "ssh analyst@10.9.0.1"


def test_no_gui_link_is_invented_for_a_device_that_declared_none() -> None:
    """A link to a GUI that does not answer is worse than no link."""
    kinds = {a["kind"] for a in layout(an_estate()).details["node:r1"]["actions"]}
    assert "gui" not in kinds
    assert "ssh" in kinds


def test_connect_hands_off_and_never_holds_a_session() -> None:
    """`MONITORING.md` §2 and §13.

    A built-in web terminal would mean this tool carrying a shell credential to a
    firewall — the write-capable path the whole design refuses. Every action is a
    handoff to software the operator already has, and no action posts anywhere.
    """
    for detail in layout(an_estate()).details.values():
        for action in detail.get("actions", []):
            assert action["href"].startswith(("https://", "ssh://", "ssh "))
            assert "password" not in action["href"]
            assert "credential" not in action["href"].lower()


# --- served ----------------------------------------------------------------


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    store = tmp_path / "estates"
    monkeypatch.setattr(data_module, "ESTATES", store)
    monkeypatch.setattr("btht.app.web.routes.ESTATES", store)
    save_estate(an_estate(), store / "team42.yaml")
    with TestClient(app) as test_client:
        yield test_client


def test_the_page_renders_the_diagram_and_its_details(client: TestClient) -> None:
    response = client.get("/estates/team42/topology")
    assert response.status_code == 200
    assert "<svg" in response.text
    assert 'data-detail="fw:alpha"' in response.text
    assert "ssh://analyst@10.9.0.1" in response.text


def test_the_page_says_it_is_a_view(client: TestClient) -> None:
    """It must never read as a second place the estate can be defined."""
    body = client.get("/estates/team42/topology").text
    assert "This is a view" in body


def test_the_topology_page_loads_no_external_assets(client: TestClient) -> None:
    body = client.get("/estates/team42/topology").text
    assert "<script src" not in body
    assert "cdn." not in body
