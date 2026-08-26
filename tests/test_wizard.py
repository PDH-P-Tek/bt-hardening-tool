"""Phase 2.4 — the wizard.

The spine of the interaction model. Two properties are load-bearing, and both are
about what happens when things are *not* ideal:

- every step is completable by typing, because the annex format changes between
  exercises and the paste accelerator will sometimes fail
- what the operator has not declared is never inferred, because a rule nobody
  decided on is a rule nobody can defend at three in the morning
"""

from __future__ import annotations

from collections.abc import Iterator
from ipaddress import IPv4Address, IPv4Interface
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from btht.app import data as data_module
from btht.app.main import app
from btht.app.model.estate import Estate, Firewall, Host, Interface, Node, Platform
from btht.app.model.policy import load_policy, save_estate


def an_estate() -> Estate:
    node = Node(
        name="fw1.alpha",
        platform=Platform.PFSENSE,
        mgmt_address=IPv4Address("10.9.0.1"),
        enclave="alpha",
    )
    return Estate(
        team=42,
        team_padded="42",
        role_vocabulary=("wan", "users", "servers"),
        firewalls=(
            Firewall(
                enclave="alpha",
                fqdn="fw1.alpha",
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
                        hostname="npc",
                        v4=IPv4Address("192.0.2.249"),
                        segment_role="users",
                        out_of_bounds=True,
                    ),
                ),
            ),
        ),
    )


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    store = tmp_path / "estates"
    monkeypatch.setattr(data_module, "ESTATES", store)
    monkeypatch.setattr("btht.app.web.routes.ESTATES", store)
    save_estate(an_estate(), store / "team42.yaml")
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def estate_file(tmp_path: Path) -> Path:
    return tmp_path / "estates" / "team42.yaml"


# --- walking ---------------------------------------------------------------


def test_the_wizard_walks_segments_not_ifnames(client: TestClient) -> None:
    """`SPEC.md` §12.7 — the operator works in segments; ifnames are for emission."""
    body = client.get("/estates/team42/policy/alpha?step=0").text
    assert "segment 1 of 2", "WAN is not a segment to declare services on"
    assert "users" in body
    assert "servers" in body


def test_each_segment_is_its_own_step(client: TestClient) -> None:
    first = client.get("/estates/team42/policy/alpha?step=0").text
    second = client.get("/estates/team42/policy/alpha?step=1").text
    assert "<h2>users</h2>" in first
    assert "<h2>servers</h2>" in second


def test_a_segment_with_nothing_declared_says_what_that_means(client: TestClient) -> None:
    """Silence is a decision here, and the consequence is stated rather than implied."""
    body = client.get("/estates/team42/policy/alpha?step=0").text
    assert "Nothing declared for this segment yet" in body
    assert "will be denied" in body


def test_the_segment_with_the_safety_net_is_marked(client: TestClient) -> None:
    body = client.get("/estates/team42/policy/alpha?step=0").text
    assert "anti-lockout binds here" in body


def test_an_out_of_bounds_host_is_shown_as_never_a_target(client: TestClient) -> None:
    """`BASELINE-ANALYSIS.md` F8 — it is in this segment and must not be built policy around."""
    body = client.get("/estates/team42/policy/alpha?step=0").text
    assert "npc" in body
    assert "never a policy target" in body


# --- typing it in ----------------------------------------------------------


def test_a_service_can_be_declared_entirely_by_typing(
    client: TestClient, estate_file: Path
) -> None:
    response = client.post(
        "/estates/team42/policy/alpha/services",
        data={
            "step": "1",
            "segment": "servers",
            "name": "AD / DC",
            "protocol": "tcp",
            "ports": "88, 389, 445",
            "from_segments": "users, servers",
            "from_any": "",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303

    policy = load_policy(estate_file)
    service = policy.for_enclave("alpha").services[0]  # type: ignore[union-attr]
    assert service.name == "AD / DC"
    assert service.ports == (88, 389, 445)
    assert service.source.segments == ("users", "servers")
    assert service.source.any is False


def test_a_declared_service_comes_back_in_words(client: TestClient) -> None:
    """The operator reads one line per rule, not the YAML — `CLAUDE.md`."""
    client.post(
        "/estates/team42/policy/alpha/services",
        data={
            "step": "0",
            "segment": "users",
            "name": "RDP for usersims",
            "protocol": "tcp",
            "ports": "3389",
            "from_alias": "YT_Usersim_Sources",
        },
        follow_redirects=False,
    )
    body = client.get("/estates/team42/policy/alpha?step=0").text
    assert "RDP for usersims" in body
    assert "alias YT_Usersim_Sources" in body


def test_reaching_anywhere_has_to_be_chosen(client: TestClient, estate_file: Path) -> None:
    """`any` is never arrived at by leaving fields blank."""
    client.post(
        "/estates/team42/policy/alpha/services",
        data={
            "step": "0",
            "segment": "users",
            "name": "Public web",
            "protocol": "tcp",
            "ports": "443",
            "from_any": "yes",
        },
        follow_redirects=False,
    )
    service = load_policy(estate_file).for_enclave("alpha").services[0]  # type: ignore[union-attr]
    assert service.source.any is True


def test_egress_is_a_step_of_its_own(client: TestClient, estate_file: Path) -> None:
    response = client.post(
        "/estates/team42/policy/alpha/egress",
        data={"default": "deny_and_log", "notes": "agents need the dependency above this"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    entry = load_policy(estate_file).for_enclave("alpha")
    assert entry.egress.default == "deny_and_log"  # type: ignore[union-attr]
    assert "agents need" in entry.egress.notes  # type: ignore[union-attr]


def test_the_egress_step_states_the_trap(client: TestClient) -> None:
    """A default-deny is good practice and is also what silently severs an agent."""
    body = client.get("/estates/team42/policy/alpha?step=egress").text
    assert "silently severs" in body


# --- the file underneath ---------------------------------------------------


def test_saving_policy_leaves_the_inventory_alone(client: TestClient, estate_file: Path) -> None:
    """Both halves share the document. Neither writer may tread on the other."""
    from btht.app.model.policy import load_estate

    before = load_estate(estate_file)
    client.post(
        "/estates/team42/policy/alpha/services",
        data={
            "step": "0",
            "segment": "users",
            "name": "X",
            "protocol": "tcp",
            "ports": "443",
            "from_any": "yes",
        },
        follow_redirects=False,
    )
    after = load_estate(estate_file)
    assert after.firewalls[0].interfaces == before.firewalls[0].interfaces
    assert after.firewalls[0].hosts == before.firewalls[0].hosts
    assert after.role_vocabulary == before.role_vocabulary


def test_problems_are_shown_while_the_operator_works(client: TestClient) -> None:
    """Not held back to the end. A missing alias found now costs a minute."""
    client.post(
        "/estates/team42/policy/alpha/services",
        data={
            "step": "0",
            "segment": "users",
            "name": "Kibana",
            "protocol": "tcp",
            "ports": "5601",
            "from_alias": "Never_Declared",
        },
        follow_redirects=False,
    )
    body = client.get("/estates/team42/policy/alpha?step=0").text
    assert "Not ready to generate" in body
    assert "Never_Declared" in body


# --- annex paste, Phase 2.5 -------------------------------------------------

ANNEX = """Hostname\tIPv4\tIPv6\tDescription
dc01\t192.0.2.5\t2001:db8:2::5\tDomain controller
npc-server\t192.0.2.249\t\tEXCON. Out of Bounds.
Workstations\t192.0.2.0/24\t\tUser segment
"""


def test_a_paste_is_previewed_and_not_applied(client: TestClient, estate_file: Path) -> None:
    """The rule this whole path exists for — `SPEC.md` §5.2."""
    from btht.app.model.policy import load_estate

    before = len(load_estate(estate_file).firewalls[0].hosts)
    response = client.post("/estates/team42/enclaves/alpha/paste", data={"text": ANNEX})
    assert response.status_code == 200
    assert "dc01" in response.text
    assert len(load_estate(estate_file).firewalls[0].hosts) == before, (
        "previewing must not change the estate"
    )


def test_the_preview_shows_the_line_beside_the_parse(client: TestClient) -> None:
    """A mis-parse is only visible if the operator can see what it was made from."""
    body = client.post("/estates/team42/enclaves/alpha/paste", data={"text": ANNEX}).text
    assert "the line you pasted" in body
    assert "Domain controller" in body


def test_only_ticked_rows_are_kept(client: TestClient, estate_file: Path) -> None:
    from btht.app.model.policy import load_estate

    client.post(
        "/estates/team42/enclaves/alpha/paste/confirm",
        data={"text": ANNEX, "keep": ["0"]},
        follow_redirects=False,
    )
    hosts = load_estate(estate_file).firewalls[0].hosts
    assert [h.hostname for h in hosts if h.source_of_truth.value == "annex"] == ["dc01"]


def test_an_out_of_bounds_host_is_flagged_when_kept(client: TestClient, estate_file: Path) -> None:
    """`BASELINE-ANALYSIS.md` F8 — it must never become a policy target."""
    from btht.app.model.policy import load_estate

    client.post(
        "/estates/team42/enclaves/alpha/paste/confirm",
        data={"text": ANNEX, "keep": ["0", "1"]},
        follow_redirects=False,
    )
    hosts = {h.hostname: h for h in load_estate(estate_file).firewalls[0].hosts}
    assert hosts["npc-server"].out_of_bounds is True
    assert hosts["dc01"].out_of_bounds is False


def test_kept_hosts_record_where_they_came_from(client: TestClient, estate_file: Path) -> None:
    """A host from the annex and a host the operator typed are different evidence."""
    from btht.app.model.policy import load_estate

    client.post(
        "/estates/team42/enclaves/alpha/paste/confirm",
        data={"text": ANNEX, "keep": ["0"]},
        follow_redirects=False,
    )
    kept = next(h for h in load_estate(estate_file).firewalls[0].hosts if h.hostname == "dc01")
    assert kept.source_of_truth.value == "annex"


def test_the_subnet_table_is_compared_and_never_applied(client: TestClient) -> None:
    """`V-ANNEX-CONFIG-MISMATCH` — the annex and the box disagreeing is worth knowing."""
    body = client.post("/estates/team42/enclaves/alpha/paste", data={"text": ANNEX}).text
    assert "Subnets in the paste" in body
    assert "matches users" in body, "192.0.2.0/24 is the declared users segment"


def test_a_subnet_with_no_declared_interface_is_called_out(client: TestClient) -> None:
    body = client.post(
        "/estates/team42/enclaves/alpha/paste",
        data={"text": "Storage\t10.10.10.0/24\t\tSAN segment\n"},
    ).text
    assert "no declared interface on this subnet" in body


# --- review and export gate, Phase 4.1 and 4.4 ------------------------------


def _declare_a_generatable_estate(client: TestClient) -> None:
    """Enough policy for the generator to run: it refuses without these."""
    client.post(
        "/estates/team42/policy/alpha/services",
        data={
            "step": "0",
            "segment": "users",
            "name": "RDP",
            "protocol": "tcp",
            "ports": "3389",
            "from_any": "yes",
        },
        follow_redirects=False,
    )


def test_the_review_page_refuses_rather_than_generating_something_plausible(
    client: TestClient,
) -> None:
    """No management alias declared: the generator refuses and the page says why."""
    _declare_a_generatable_estate(client)
    body = client.get("/estates/team42/review/alpha").text
    assert "Refusing to generate" in body
    assert "locks itself out" in body


def test_export_is_refused_while_the_gate_is_shut(client: TestClient) -> None:
    """Checked in the endpoint, not only hidden in the template.

    A gate that only hides a button is not a gate — it is a suggestion.
    """
    _declare_a_generatable_estate(client)
    response = client.post("/estates/team42/review/alpha/export", follow_redirects=False)
    assert response.status_code == 409, "a refusal must read as a refusal, not a crash"
    assert "Refusing to generate" in response.text
