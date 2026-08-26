"""Phase 2.1 — the setup flow, driven the way an operator drives it.

The flow these tests walk is the one the tool exists to support: declare an estate,
add an enclave, then either type the interfaces in or import a configuration and
confirm what came back. Both paths have to work, because the annex format changes
between exercises and the import will sometimes fail.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from btht.app import data as data_module
from btht.app.main import app
from btht.app.model.policy import load_estate

FIXTURE = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "baseline"


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    """Estates are working data. Never the repository, and never a shared directory."""
    store = tmp_path / "estates"
    monkeypatch.setattr(data_module, "ESTATES", store)
    monkeypatch.setattr("btht.app.web.routes.ESTATES", store)
    with TestClient(app) as test_client:
        yield test_client


def make_estate(client: TestClient, **overrides: str) -> str:
    form = {
        "slug": "team07",
        "team": "42",
        "team_padded": "42",
        "vocabulary": "wan, ws, svrs, dmz",
        "tokens": "bt_wan_, do_",
    }
    form.update(overrides)
    response = client.post("/estates", data=form, follow_redirects=False)
    assert response.status_code == 303
    return str(form["slug"])


def test_an_empty_install_says_nothing_is_declared(client: TestClient) -> None:
    body = client.get("/").text
    assert "No estate declared yet" in body
    assert "ships no vocabulary" in body


def test_declaring_an_estate_writes_the_document(client: TestClient, tmp_path: Path) -> None:
    slug = make_estate(client)
    path = tmp_path / "estates" / f"{slug}.yaml"
    assert path.exists(), "the estate file is the durable artefact"
    estate = load_estate(path)
    assert estate.team == 42
    assert estate.role_vocabulary == ("wan", "ws", "svrs", "dmz")


def test_an_enclave_is_named_by_the_operator(client: TestClient, tmp_path: Path) -> None:
    slug = make_estate(client)
    response = client.post(
        f"/estates/{slug}/enclaves",
        data={
            "name": "whatever-they-call-it",
            "fqdn": "fw1.example",
            "platform": "pfsense",
            "mgmt_address": "10.0.0.1",
            "credential_ref": "monitor-key",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    estate = load_estate(tmp_path / "estates" / f"{slug}.yaml")
    assert estate.firewalls[0].enclave == "whatever-they-call-it"
    assert estate.firewalls[0].node.credential_ref == "monitor-key"


def test_interfaces_can_always_be_typed_in(client: TestClient, tmp_path: Path) -> None:
    """The wizard is the spine. Every step must work without pasting anything."""
    slug = make_estate(client)
    client.post(
        f"/estates/{slug}/enclaves",
        data={"name": "alpha", "platform": "pfsense", "mgmt_address": "10.0.0.1"},
        follow_redirects=False,
    )
    response = client.post(
        f"/estates/{slug}/enclaves/alpha/interfaces",
        data={
            "ifname": "opt1",
            "role": "svrs",
            "v4": "192.0.2.1/24",
            "descr": "typed by hand",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    estate = load_estate(tmp_path / "estates" / f"{slug}.yaml")
    interface = estate.firewalls[0].interfaces[0]
    assert (interface.ifname, interface.role) == ("opt1", "svrs")
    assert str(interface.v4) == "192.0.2.1/24"


def test_importing_a_config_fills_interfaces_in_for_confirmation(
    client: TestClient, tmp_path: Path
) -> None:
    """The accelerator. It renders the parse back rather than applying it silently."""
    slug = make_estate(client)
    client.post(
        f"/estates/{slug}/enclaves",
        data={"name": "alpha", "platform": "pfsense", "mgmt_address": "10.0.0.1"},
        follow_redirects=False,
    )
    with (FIXTURE / "do-baseline.xml").open("rb") as handle:
        response = client.post(
            f"/estates/{slug}/enclaves/alpha/import",
            files={"config": ("do-baseline.xml", handle, "text/xml")},
        )
    assert response.status_code == 200
    assert "check them against the box" in response.text

    estate = load_estate(tmp_path / "estates" / f"{slug}.yaml")
    roles = {i.ifname: i.role for i in estate.firewalls[0].interfaces}
    assert roles == {"wan": "wan", "lan": "ws", "opt1": "svrs", "opt2": "dmz"}
    assert estate.firewalls[0].config_version == "23.3"


def test_an_import_that_cannot_be_placed_says_so_rather_than_guessing(
    client: TestClient,
) -> None:
    """An estate whose vocabulary does not cover the file gets told, not guessed at."""
    slug = make_estate(client, slug="sparse", vocabulary="wan", tokens="")
    client.post(
        f"/estates/{slug}/enclaves",
        data={"name": "alpha", "platform": "pfsense", "mgmt_address": "10.0.0.1"},
        follow_redirects=False,
    )
    with (FIXTURE / "do-baseline.xml").open("rb") as handle:
        response = client.post(
            f"/estates/{slug}/enclaves/alpha/import",
            files={"config": ("do-baseline.xml", handle, "text/xml")},
        )
    assert "could not be placed" in response.text
    assert "need a role" in response.text


def test_a_file_that_is_not_a_config_is_reported_not_swallowed(client: TestClient) -> None:
    slug = make_estate(client)
    client.post(
        f"/estates/{slug}/enclaves",
        data={"name": "alpha", "platform": "pfsense", "mgmt_address": "10.0.0.1"},
        follow_redirects=False,
    )
    response = client.post(
        f"/estates/{slug}/enclaves/alpha/import",
        files={"config": ("notes.xml", b"<opnsense/>", "text/xml")},
    )
    assert "could not read that file" in response.text


def test_the_page_loads_no_external_assets(client: TestClient) -> None:
    """Offline on team kit. A page that needs a CDN is a page that does not load."""
    body = client.get("/").text
    for marker in ("http://", "https://", "cdn.", "<script src"):
        assert marker not in body
