"""Phase 2.1 — the estate document.

It is the durable artefact: the operator's day-one work, the thing that diffs in a
text editor, and the file both halves of the tool read. Two properties matter more
than the schema itself — it round-trips without losing anything, and saving it twice
produces the same bytes, so a diff shows what a person changed and nothing else.
"""

from __future__ import annotations

from ipaddress import IPv4Address, IPv4Interface, ip_network
from pathlib import Path

import pytest

from btht.app.ingest.roles import SideRule
from btht.app.model.estate import (
    Estate,
    Firewall,
    Host,
    Interface,
    Node,
    Platform,
    SourceOfTruth,
)
from btht.app.model.policy import (
    EstateFileError,
    convention_of,
    load_estate,
    save_estate,
    side_rules_of,
)


def an_estate() -> Estate:
    """A small estate an operator could plausibly have declared on day one."""
    firewall_node = Node(
        name="fw1.alpha",
        platform=Platform.PFSENSE,
        mgmt_address=IPv4Address("10.9.0.1"),
        credential_ref="monitor-key",
        enclave="alpha",
    )
    router = Node(
        name="r1",
        platform=Platform.FRR,
        mgmt_address=IPv4Address("10.9.0.254"),
        credential_ref="monitor-key",
        enclave="alpha",
        poll_seconds=120,
    )
    return Estate(
        team=7,
        team_padded="07",
        role_vocabulary=("wan", "users", "servers"),
        firewalls=(
            Firewall(
                enclave="alpha",
                fqdn="fw1.alpha.example",
                node=firewall_node,
                side="north",
                config_version="23.3",
                interfaces=(
                    Interface(
                        ifname="wan",
                        role="wan",
                        descr="uplink",
                        nic="vmx0",
                        v4=IPv4Interface("198.51.100.2/24"),
                    ),
                    Interface(
                        ifname="lan",
                        role="users",
                        descr="site_users",
                        nic="vmx1",
                        v4=IPv4Interface("192.0.2.1/24"),
                        is_lan=True,
                    ),
                ),
                hosts=(
                    Host(
                        hostname="scoring",
                        v4=IPv4Address("192.0.2.254"),
                        segment_role="users",
                        out_of_bounds=True,
                        source_of_truth=SourceOfTruth.ANNEX,
                    ),
                ),
            ),
        ),
        nodes=(router,),
    )


SIDES = (SideRule(network=ip_network("198.51.100.0/24"), label="north"),)
TOKENS = ("site_",)


def test_the_document_round_trips(tmp_path: Path) -> None:
    path = tmp_path / "team07.yaml"
    save_estate(an_estate(), path, TOKENS, SIDES)
    loaded = load_estate(path)

    original = an_estate()
    assert loaded.team == original.team
    assert loaded.team_padded == "07", "padding is stored, never re-derived (Q3 is open)"
    assert loaded.role_vocabulary == original.role_vocabulary
    assert len(loaded.firewalls) == 1
    assert loaded.firewalls[0].interfaces == original.firewalls[0].interfaces
    assert loaded.firewalls[0].hosts == original.firewalls[0].hosts
    assert loaded.firewalls[0].side == "north"


def test_saving_twice_produces_identical_bytes(tmp_path: Path) -> None:
    """A diff of the estate file must show the operator's change and nothing else."""
    first, second = tmp_path / "a.yaml", tmp_path / "b.yaml"
    save_estate(an_estate(), first, TOKENS, SIDES)
    save_estate(an_estate(), second, TOKENS, SIDES)
    assert first.read_bytes() == second.read_bytes()


def test_the_monitor_and_the_generator_read_one_inventory(tmp_path: Path) -> None:
    """`MONITORING.md` §11 — the firewall and the router come off the same list."""
    path = tmp_path / "estate.yaml"
    save_estate(an_estate(), path, TOKENS, SIDES)
    loaded = load_estate(path)

    polled = {n.name: n.platform for n in loaded.all_nodes()}
    assert polled == {"fw1.alpha": Platform.PFSENSE, "r1": Platform.FRR}


def test_a_node_carries_a_credential_name_and_never_a_credential(tmp_path: Path) -> None:
    path = tmp_path / "estate.yaml"
    save_estate(an_estate(), path, TOKENS, SIDES)
    text = path.read_text(encoding="utf-8")
    assert "credential_ref: monitor-key" in text
    assert "password" not in text.lower()
    assert "key:" not in text.lower().replace("credential_ref", "")


def test_the_declared_convention_comes_back_out(tmp_path: Path) -> None:
    """What the operator declared is what role derivation must use."""
    path = tmp_path / "estate.yaml"
    save_estate(an_estate(), path, TOKENS, SIDES)
    convention = convention_of(path)
    assert convention.vocabulary == ("wan", "users", "servers")
    assert convention.enclave_tokens == ("site_",)
    assert side_rules_of(path)[0].label == "north"


def test_an_unsupported_platform_is_refused_not_guessed(tmp_path: Path) -> None:
    """A platform with no adapter cannot be polled, so it is not silently accepted."""
    path = tmp_path / "estate.yaml"
    path.write_text(
        "version: 1\nteam: 1\nenclaves:\n"
        "  - name: a\n    nodes:\n"
        "      - {name: x, platform: cisco-ios, mgmt_address: 10.0.0.1}\n",
        encoding="utf-8",
    )
    with pytest.raises(EstateFileError, match="cisco-ios"):
        load_estate(path)


def test_a_future_schema_version_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "estate.yaml"
    path.write_text("version: 99\nteam: 1\n", encoding="utf-8")
    with pytest.raises(EstateFileError, match="schema version"):
        load_estate(path)


def test_poll_interval_below_the_floor_is_refused(tmp_path: Path) -> None:
    """`MONITORING.md` §3.5 — below 30s the poll cost on the firewall starts to matter."""
    path = tmp_path / "estate.yaml"
    path.write_text(
        "version: 1\nteam: 1\nenclaves:\n"
        "  - name: a\n    nodes:\n"
        "      - {name: x, platform: linux, mgmt_address: 10.0.0.1, poll_seconds: 5}\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="30s floor"):
        load_estate(path)


def test_group_isa_checks_survive_a_save_and_load(tmp_path: Path) -> None:
    """They were dropped by the serializer, so a scored workstation group came back
    unscored — every ICMP HOST rule for those ten machines silently gone."""
    from btht.app.model.estate import Estate, Firewall, HostGroup, Node, Platform
    from btht.app.model.policy import load_estate, save_estate

    estate = Estate(
        team=42,
        firewalls=(
            Firewall(
                enclave="do",
                fqdn="do.example",
                node=Node(
                    name="do",
                    platform=Platform.PFSENSE,
                    mgmt_address=__import__("ipaddress").ip_address("10.0.0.1"),
                ),
                host_groups=(
                    HostGroup(
                        name_prefix="ws1",
                        count=10,
                        host_type="windows_workstation",
                        segment_role="ws",
                        isa_checks=("HOST", "RDP"),
                    ),
                ),
            ),
        ),
    )
    path = tmp_path / "range.yaml"
    save_estate(estate, path)
    reloaded = load_estate(path)
    assert reloaded.firewalls[0].host_groups[0].isa_checks == ("HOST", "RDP")
