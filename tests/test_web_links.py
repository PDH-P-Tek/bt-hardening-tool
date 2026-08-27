"""Every link the tool renders must resolve.

This exists because it did not. The topology kept building its links against
`/estates/{slug}/topology` after the route space moved to `/range`, so every click on
the diagram returned 404 — the one interaction the feature is *for*. It shipped and
survived a full test suite, because the tests asserted the link's query string and
never that the path on the other end existed.

So this walks the app the way a person does: render a page, take every internal link on
it, and follow it. A route rename now breaks a test instead of breaking the tool.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from btht.app import data as data_module
from btht.app.main import app

HREF = re.compile(r'href="([^"]+)"')


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    store = tmp_path / "estates"
    monkeypatch.setattr(data_module, "ESTATES", store)
    monkeypatch.setattr("btht.app.web.routes.ESTATES", store)
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def furnished(client: TestClient) -> TestClient:
    """A range with enough in it that the diagram has something to draw."""
    client.post(
        "/range/create",
        data={"team": "42", "vocabulary": "wan, ws, svrs", "tokens": "do_"},
        follow_redirects=False,
    )
    client.post(
        "/range/enclaves",
        data={"name": "alpha", "platform": "pfsense", "mgmt_address": "10.0.0.1"},
        follow_redirects=False,
    )
    client.post(
        "/range/enclaves/alpha/interfaces",
        data={"ifname": "wan", "role": "wan", "v4": "10.0.0.1/24"},
        follow_redirects=False,
    )
    client.post(
        "/range/enclaves/alpha/interfaces",
        data={"ifname": "lan", "role": "ws", "v4": "192.0.2.1/24"},
        follow_redirects=False,
    )
    client.post(
        "/range/enclaves/alpha/hosts",
        data={"hostname": "ws101", "segment_role": "ws", "v4": "192.0.2.11"},
        follow_redirects=False,
    )
    return client


def internal_links(body: str) -> set[str]:
    """Only links this app is responsible for — not `#`, `mailto:` or anything remote."""
    return {
        href for href in HREF.findall(body) if href.startswith("/") and not href.startswith("//")
    }


def test_every_link_on_the_topology_resolves(furnished: TestClient) -> None:
    """The exact defect: the diagram's own links pointed at a retired route space."""
    opened = furnished.get("/range/topology?open=alpha&open=alpha%3Alan")
    assert opened.status_code == 200
    links = internal_links(opened.text)
    assert any("/range/topology?" in link for link in links), "the diagram must be clickable"
    for link in sorted(links):
        assert furnished.get(link).status_code != 404, f"topology link 404s: {link}"


@pytest.mark.parametrize(
    "page",
    ["/", "/range", "/range/topology", "/services", "/host-templates", "/segments"],
)
def test_every_link_on_every_main_page_resolves(furnished: TestClient, page: str) -> None:
    response = furnished.get(page)
    assert response.status_code == 200
    for link in sorted(internal_links(response.text)):
        assert furnished.get(link).status_code != 404, f"{page} links to a 404: {link}"


def test_the_template_libraries_are_reachable_from_the_range_page(
    furnished: TestClient,
) -> None:
    """They were not, for a while, and that read as though they had been removed.

    Reducing the navigation to the three phases moved host templates, services and
    segment types "behind Range" — and then nothing on Range linked to them. A page
    reachable only by typing its URL is a page nobody has.
    """
    links = internal_links(furnished.get("/range").text)
    for page in ("/host-templates", "/services", "/segments"):
        assert page in links, f"{page} has no way in from Range"


def test_every_library_page_offers_a_way_back(furnished: TestClient) -> None:
    for page in ("/host-templates", "/services", "/segments"):
        assert '/range"' in furnished.get(page).text, f"{page} is a dead end"


def test_the_add_tile_is_always_last(furnished: TestClient) -> None:
    """Routers first, enclaves in the middle, add at the end.

    A control that shifts position as the range grows is one you have to hunt for each
    time, and adding an enclave is exactly the thing done repeatedly in one sitting.
    """
    import re

    body = furnished.get("/range").text
    block = re.search(r"<h2>The range</h2>\s*<div class=\"tiles\">(.*?)\n</div>", body, re.S)
    assert block is not None
    headings = re.findall(r"<h3>(.*?)</h3>", block.group(1))
    assert headings[0] == "Routers"
    assert headings[-1] == "Add an enclave"
