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


def make_estate(client: TestClient, **overrides: str) -> None:
    form = {
        "team": "42",
        "team_padded": "42",
        "vocabulary": "wan, ws, svrs, dmz",
        "tokens": "bt_wan_, do_",
    }
    form.update(overrides)
    response = client.post("/range/create", data=form, follow_redirects=False)
    assert response.status_code == 303


def test_an_empty_install_says_nothing_is_declared(client: TestClient) -> None:
    """A team has one range, so the front page is its setup rather than a list."""
    body = client.get("/").text
    assert "Nothing declared yet" in body
    assert "Set up the range" in body
    assert "add each" in body, "and it says what to do about it"


def test_declaring_an_estate_writes_the_document(client: TestClient, tmp_path: Path) -> None:
    make_estate(client)
    path = tmp_path / "estates" / "range.yaml"
    assert path.exists(), "the estate file is the durable artefact"
    estate = load_estate(path)
    assert estate.team == 42
    assert estate.role_vocabulary == ("wan", "ws", "svrs", "dmz")


def test_an_enclave_is_named_by_the_operator(client: TestClient, tmp_path: Path) -> None:
    make_estate(client)
    response = client.post(
        "/range/enclaves",
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
    estate = load_estate(tmp_path / "estates" / "range.yaml")
    assert estate.firewalls[0].enclave == "whatever-they-call-it"
    assert estate.firewalls[0].node.credential_ref == "monitor-key"


def test_interfaces_can_always_be_typed_in(client: TestClient, tmp_path: Path) -> None:
    """The wizard is the spine. Every step must work without pasting anything."""
    make_estate(client)
    client.post(
        "/range/enclaves",
        data={"name": "alpha", "platform": "pfsense", "mgmt_address": "10.0.0.1"},
        follow_redirects=False,
    )
    response = client.post(
        "/range/enclaves/alpha/interfaces",
        data={
            "ifname": "opt1",
            "role": "svrs",
            "v4": "192.0.2.1/24",
            "descr": "typed by hand",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    estate = load_estate(tmp_path / "estates" / "range.yaml")
    interface = estate.firewalls[0].interfaces[0]
    assert (interface.ifname, interface.role) == ("opt1", "svrs")
    assert str(interface.v4) == "192.0.2.1/24"


def test_importing_a_config_fills_interfaces_in_for_confirmation(
    client: TestClient, tmp_path: Path
) -> None:
    """The accelerator. It renders the parse back rather than applying it silently."""
    make_estate(client)
    client.post(
        "/range/enclaves",
        data={"name": "alpha", "platform": "pfsense", "mgmt_address": "10.0.0.1"},
        follow_redirects=False,
    )
    with (FIXTURE / "do-baseline.xml").open("rb") as handle:
        response = client.post(
            "/range/enclaves/alpha/import",
            files={"config": ("do-baseline.xml", handle, "text/xml")},
        )
    assert response.status_code == 200
    assert "check them against the box" in response.text

    estate = load_estate(tmp_path / "estates" / "range.yaml")
    roles = {i.ifname: i.role for i in estate.firewalls[0].interfaces}
    assert roles == {"wan": "wan", "lan": "ws", "opt1": "svrs", "opt2": "dmz"}
    assert estate.firewalls[0].config_version == "23.3"


def test_an_import_that_cannot_be_placed_says_so_rather_than_guessing(
    client: TestClient,
) -> None:
    """An estate whose vocabulary does not cover the file gets told, not guessed at."""
    make_estate(client, vocabulary="wan", tokens="")
    client.post(
        "/range/enclaves",
        data={"name": "alpha", "platform": "pfsense", "mgmt_address": "10.0.0.1"},
        follow_redirects=False,
    )
    with (FIXTURE / "do-baseline.xml").open("rb") as handle:
        response = client.post(
            "/range/enclaves/alpha/import",
            files={"config": ("do-baseline.xml", handle, "text/xml")},
        )
    assert "could not be placed" in response.text
    assert "need a role" in response.text


def test_a_file_that_is_not_a_config_is_reported_not_swallowed(client: TestClient) -> None:
    make_estate(client)
    client.post(
        "/range/enclaves",
        data={"name": "alpha", "platform": "pfsense", "mgmt_address": "10.0.0.1"},
        follow_redirects=False,
    )
    response = client.post(
        "/range/enclaves/alpha/import",
        files={"config": ("notes.xml", b"<opnsense/>", "text/xml")},
    )
    assert "could not read that file" in response.text


def test_the_page_loads_no_external_assets(client: TestClient) -> None:
    """Offline on team kit. A page that needs a CDN is a page that does not load."""
    body = client.get("/").text
    for marker in ("http://", "https://", "cdn.", "<script src"):
        assert marker not in body


# --- editing, Phase 9.6 -----------------------------------------------------


def with_an_enclave(client: TestClient) -> None:
    make_estate(client)
    client.post(
        "/range/enclaves",
        data={"name": "alpha", "platform": "pfsense", "mgmt_address": "10.0.0.1"},
        follow_redirects=False,
    )
    client.post(
        "/range/enclaves/alpha/interfaces",
        data={"ifname": "opt1", "role": "svrs", "v4": "192.0.2.1/24", "descr": "typo here"},
        follow_redirects=False,
    )


def test_a_mistyped_interface_can_be_corrected_in_the_ui(
    client: TestClient, tmp_path: Path
) -> None:
    """The reason this exists: a typo the night before should not mean editing YAML."""
    with_an_enclave(client)
    form = client.get("/range/edit/interface/alpha/opt1")
    assert form.status_code == 200
    assert "192.0.2.1/24" in form.text, "the form is pre-filled with what is there now"

    response = client.post(
        "/range/edit/interface/alpha/opt1",
        data={
            "ifname": "opt1",
            "role": "servers",
            "v4": "192.0.9.1/24",
            "v6": "",
            "descr": "fixed",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    estate = load_estate(tmp_path / "estates" / "range.yaml")
    interface = estate.firewalls[0].interfaces[0]
    assert interface.role == "servers"
    assert str(interface.v4) == "192.0.9.1/24"


def test_an_interface_with_hosts_on_it_is_refused_and_says_why(
    client: TestClient, tmp_path: Path
) -> None:
    """Refused in the UI, not just in the model — with the hosts named."""
    with_an_enclave(client)
    client.post(
        "/range/enclaves/alpha/paste/confirm",
        data={"text": "dc01\t192.0.2.5\tDomain controller\n", "keep": ["0"]},
        follow_redirects=False,
    )
    client.post(
        "/range/edit/host/alpha/dc01",
        data={"hostname": "dc01", "segment_role": "svrs", "v4": "192.0.2.5"},
        follow_redirects=False,
    )
    response = client.post("/range/delete/interface/alpha/opt1", follow_redirects=False)
    assert response.status_code == 303
    assert "dc01" in response.headers["location"], "the refusal names what is in the way"

    estate = load_estate(tmp_path / "estates" / "range.yaml")
    assert estate.firewalls[0].interfaces, "nothing was removed"


def test_an_empty_interface_is_removed(client: TestClient, tmp_path: Path) -> None:
    with_an_enclave(client)
    client.post("/range/delete/interface/alpha/opt1", follow_redirects=False)
    estate = load_estate(tmp_path / "estates" / "range.yaml")
    assert estate.firewalls[0].interfaces == ()


def test_an_enclave_can_be_amended_including_how_to_reach_it(
    client: TestClient, tmp_path: Path
) -> None:
    with_an_enclave(client)
    client.post(
        "/range/edit/enclave/alpha",
        data={
            "enclave": "alpha",
            "fqdn": "fw1.alpha.example",
            "side": "north",
            "mgmt_address": "10.0.0.9",
            "gui_url": "https://10.0.0.9/",
            "ssh_user": "analyst",
            "credential_ref": "monitor-key",
        },
        follow_redirects=False,
    )
    firewall = load_estate(tmp_path / "estates" / "range.yaml").firewalls[0]
    assert firewall.fqdn == "fw1.alpha.example"
    assert str(firewall.node.mgmt_address) == "10.0.0.9"
    assert firewall.node.ssh_user == "analyst"


def test_the_range_page_drills_down_one_level_at_a_time(client: TestClient) -> None:
    """Enclaves, then that enclave's interfaces, then that interface's hosts.

    An edit function nobody can find is not an edit function, so each level exposes
    the edit for what it is showing — and only for what it is showing.
    """
    with_an_enclave(client)

    top = client.get("/range").text
    assert "/range?enclave=alpha" in top, "an enclave tile to click"
    assert "/range/edit/interface/alpha/opt1" not in top, "interfaces are one level down"

    enclave = client.get("/range?enclave=alpha").text
    assert "/range/edit/enclave/alpha" in enclave
    assert "/range?enclave=alpha&interface=opt1" in enclave

    interface = client.get("/range?enclave=alpha&interface=opt1").text
    assert "/range/edit/interface/alpha/opt1" in interface
    assert "Add one machine" in interface, "the add form for the level being viewed"
    assert "Add many of one kind" in interface


def test_the_add_form_matches_the_level_being_viewed(client: TestClient) -> None:
    """Adding an interface is not offered while looking at hosts, and vice versa."""
    with_an_enclave(client)
    hosts_level = client.get("/range?enclave=alpha&interface=opt1").text
    assert "Add one machine" in hosts_level
    assert "Add an interface to alpha" not in hosts_level

    interfaces_level = client.get("/range?enclave=alpha&interface=__new").text
    assert "Add an interface to alpha" in interfaces_level


def test_a_machine_can_be_typed_in_without_pasting_an_annex(
    client: TestClient, tmp_path: Path
) -> None:
    """The paste accelerator is not the only way a host gets declared."""
    with_an_enclave(client)
    response = client.post(
        "/range/enclaves/alpha/hosts",
        data={
            "hostname": "dc01",
            "os": "Windows Server 2022",
            "v4": "192.0.2.5",
            "segment_role": "svrs",
            "host_type": "domain_controller",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    host = load_estate(tmp_path / "estates" / "range.yaml").firewalls[0].hosts[0]
    assert host.hostname == "dc01"
    assert host.os == "Windows Server 2022"
    assert "RPC dynamic range" in host.services, "the template's services came with it"


def test_many_machines_of_one_kind_are_one_declaration(client: TestClient, tmp_path: Path) -> None:
    with_an_enclave(client)
    client.post(
        "/range/enclaves/alpha/groups",
        data={
            "name_prefix": "ws1",
            "count": "10",
            "first_index": "1",
            "index_width": "2",
            "os": "Windows 10 22H2",
            "host_type": "windows_workstation",
            "segment_role": "svrs",
            "v4_start": "192.0.2.10",
            "v6_prefix": "2001:db8:2",
        },
        follow_redirects=False,
    )
    firewall = load_estate(tmp_path / "estates" / "range.yaml").firewalls[0]
    machines = firewall.all_hosts()
    assert [m.hostname for m in machines][:2] == ["ws101", "ws102"]
    assert len(machines) == 10
    assert str(machines[9].v4) == "192.0.2.19"
    assert str(machines[9].v6) == "2001:db8:2::19", "the v6 mirrors the v4 octet"


def test_an_implausible_group_is_refused_with_a_reason(client: TestClient) -> None:
    with_an_enclave(client)
    response = client.post(
        "/range/enclaves/alpha/groups",
        data={"name_prefix": "ws", "count": "4000", "segment_role": "svrs"},
        follow_redirects=False,
    )
    assert "typo" in response.headers["location"]


def test_a_router_is_declared_without_being_asked_its_platform(
    client: TestClient, tmp_path: Path
) -> None:
    """A router on this range is FRR on Linux. Offering a choice invites a wrong one."""
    make_estate(client)
    response = client.post(
        "/range/routers",
        data={"name": "r1", "mgmt_address": "25.42.0.1", "ssh_user": "analyst"},
        follow_redirects=False,
    )
    assert response.status_code == 303

    estate = load_estate(tmp_path / "estates" / "range.yaml")
    router = estate.nodes[0]
    assert router.name == "r1"
    assert router.platform.value == "frr"

    body = client.get("/range?routers=1").text
    assert "Add a router" in body
    assert "pfsense" not in body, "no platform to choose from"


def test_an_interface_declares_which_routers_it_peers_with(
    client: TestClient, tmp_path: Path
) -> None:
    with_an_enclave(client)
    client.post(
        "/range/routers", data={"name": "r1", "mgmt_address": "25.42.0.1"},
        follow_redirects=False,
    )
    client.post(
        "/range/edit/interface/alpha/opt1",
        data={"ifname": "opt1", "role": "svrs", "upstreams": "r1"},
        follow_redirects=False,
    )
    interface = load_estate(tmp_path / "estates" / "range.yaml").firewalls[0].interfaces[0]
    assert interface.upstreams == ("r1",)


def test_a_router_something_still_peers_with_is_not_removed(client: TestClient) -> None:
    with_an_enclave(client)
    client.post(
        "/range/routers", data={"name": "r1", "mgmt_address": "25.42.0.1"},
        follow_redirects=False,
    )
    client.post(
        "/range/edit/interface/alpha/opt1",
        data={"ifname": "opt1", "role": "svrs", "upstreams": "r1"},
        follow_redirects=False,
    )
    response = client.post("/range/routers/r1/delete", follow_redirects=False)
    assert "alpha/opt1" in response.headers["location"], "the refusal names what still peers"
