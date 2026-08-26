"""Phase 9.6 — amending what has already been declared.

Everything was add-only, which is fine until somebody types an address wrong the night
before the range opens. Then it is the difference between fixing a field and
hand-editing YAML under pressure, which is how the second mistake gets made.

Two properties carry this file, and both are about refusing to be quietly destructive:
nothing is removed while something still points at it, and a rename takes its
references with it.
"""

from __future__ import annotations

from ipaddress import IPv4Address, IPv4Interface

import pytest

from btht.app.model.edit import (
    InUse,
    alias_references,
    remove_alias,
    remove_firewall,
    remove_host,
    remove_host_group,
    remove_host_type,
    remove_interface,
    remove_policy_service,
    remove_service,
    rename_service,
    service_references,
    update_firewall,
    update_host,
    update_host_group,
    update_interface,
    update_policy_service,
)
from btht.app.model.estate import Estate, Firewall, Host, HostGroup, Interface, Node, Platform
from btht.app.model.policy import (
    Dependency,
    EgressPolicy,
    FirewallPolicy,
    Policy,
    PolicyAlias,
    Selector,
    ServiceRule,
)
from btht.app.model.services import Catalogue, HostType, Service


def an_estate() -> Estate:
    node = Node(name="fw1", platform=Platform.PFSENSE, mgmt_address=IPv4Address("10.0.0.1"))
    return Estate(
        team=42,
        team_padded="42",
        firewalls=(
            Firewall(
                enclave="alpha",
                fqdn="fw1.alpha",
                node=node,
                interfaces=(
                    Interface(ifname="wan", role="wan", v4=IPv4Interface("198.51.100.2/24")),
                    Interface(ifname="lan", role="users", v4=IPv4Interface("192.0.2.1/24")),
                ),
                hosts=(
                    Host(
                        hostname="dc01",
                        v4=IPv4Address("192.0.2.5"),
                        segment_role="users",
                        service_role="domain_controller",
                        services=("RDP", "SMB"),
                    ),
                ),
                host_groups=(
                    HostGroup(
                        name_prefix="ws1",
                        count=3,
                        segment_role="users",
                        host_type="windows_workstation",
                        v4_start=IPv4Address("192.0.2.10"),
                    ),
                ),
            ),
        ),
    )


def a_catalogue() -> Catalogue:
    return Catalogue(
        services={
            "RDP": Service(name="RDP", tcp=(3389,)),
            "SMB": Service(name="SMB", tcp=(445,)),
            "Spare": Service(name="Spare", tcp=(9999,), custom=True),
        },
        host_types={
            "windows_workstation": HostType(name="windows_workstation", services=("RDP",)),
            "domain_controller": HostType(name="domain_controller", services=("RDP", "SMB")),
            "unused": HostType(name="unused", services=()),
        },
    )


def a_policy() -> Policy:
    return Policy(
        aliases=(
            PolicyAlias(name="Mgmt_Sources", lockout_critical=True),
            PolicyAlias(name="Fleet", entries=("192.0.2.50",)),
            PolicyAlias(name="Spare_Alias"),
        ),
        dependencies=(
            Dependency(
                name="Agents",
                from_enclaves=("alpha",),
                to_enclave="beta",
                to_alias="Fleet",
                ports=(8220,),
            ),
        ),
        firewalls=(
            FirewallPolicy(
                enclave="alpha",
                services=(
                    ServiceRule(
                        name="AD",
                        segment="users",
                        protocol="tcp",
                        ports=(389,),
                        source=Selector(any=True),
                    ),
                ),
                egress=EgressPolicy(default="deny_and_log"),
            ),
        ),
    )


# --- amending ---------------------------------------------------------------


def test_a_mistyped_address_can_be_corrected() -> None:
    """The whole reason this module exists."""
    fixed = update_interface(
        an_estate(), "alpha", "lan", v4=IPv4Interface("192.0.5.1/24"), role="workstations"
    )
    interface = fixed.firewalls[0].interfaces[1]
    assert str(interface.v4) == "192.0.5.1/24"
    assert interface.role == "workstations"


def test_a_firewall_can_be_amended_including_how_to_reach_it() -> None:
    fixed = update_firewall(an_estate(), "alpha", fqdn="fw1.alpha.example", side="north")
    assert fixed.firewalls[0].fqdn == "fw1.alpha.example"
    assert fixed.firewalls[0].side == "north"


def test_a_host_can_gain_services_after_it_was_created() -> None:
    fixed = update_host(
        an_estate(), "alpha", "dc01", services=("RDP", "SMB", "Spare"), os="Server 2022"
    )
    host = fixed.firewalls[0].hosts[0]
    assert host.services == ("RDP", "SMB", "Spare")
    assert host.os == "Server 2022"


def test_a_group_can_be_resized_and_readdressed() -> None:
    fixed = update_host_group(
        an_estate(), "alpha", "ws1", count=5, v4_start=IPv4Address("192.0.2.20")
    )
    hosts = fixed.firewalls[0].all_hosts()
    workstations = [h for h in hosts if h.group == "ws1"]
    assert len(workstations) == 5
    assert str(workstations[0].v4) == "192.0.2.20"


def test_a_policy_service_can_be_corrected() -> None:
    corrected = ServiceRule(
        name="AD",
        segment="users",
        protocol="tcp",
        ports=(389, 636),
        source=Selector(segments=("users",)),
    )
    fixed = update_policy_service(a_policy(), "alpha", "AD", corrected)
    assert fixed.firewalls[0].services[0].ports == (389, 636)


# --- refusing to be quietly destructive -------------------------------------


def test_a_service_in_use_is_not_removed() -> None:
    """Removing it leaves hosts running something the tool no longer knows ports for."""
    with pytest.raises(InUse, match="host type"):
        remove_service(a_catalogue(), an_estate(), "RDP")


def test_an_unused_service_is_removed_without_argument() -> None:
    reduced = remove_service(a_catalogue(), an_estate(), "Spare")
    assert "Spare" not in reduced.services


def test_the_refusal_names_what_is_using_it() -> None:
    """ "In use" without a list is a dead end; with one it is a next step."""
    with pytest.raises(InUse) as caught:
        remove_service(a_catalogue(), an_estate(), "SMB")
    assert "domain_controller" in str(caught.value)
    assert "dc01" in str(caught.value)


def test_a_host_type_in_use_is_not_removed() -> None:
    with pytest.raises(InUse, match="ws1"):
        remove_host_type(a_catalogue(), an_estate(), "windows_workstation")
    assert "unused" not in remove_host_type(a_catalogue(), an_estate(), "unused").host_types


def test_an_interface_with_hosts_on_it_is_not_removed() -> None:
    """A host on a segment that no longer exists gets no rules and appears nowhere."""
    with pytest.raises(InUse, match="host"):
        remove_interface(an_estate(), "alpha", "lan")


def test_an_empty_interface_is_removed() -> None:
    reduced = remove_interface(an_estate(), "alpha", "wan")
    assert [i.ifname for i in reduced.firewalls[0].interfaces] == ["lan"]


def test_an_enclave_named_by_a_declared_path_is_not_removed() -> None:
    """The far end keeps a rule for traffic that can no longer arrive."""
    with pytest.raises(InUse, match="Agents"):
        remove_firewall(an_estate(), "alpha", a_policy())


def test_an_alias_with_rules_pointing_at_it_is_not_removed() -> None:
    with pytest.raises(InUse, match="dependency Agents"):
        remove_alias(a_policy(), "Fleet")


def test_a_lockout_critical_alias_is_refused_even_when_unused() -> None:
    """How a team loses access to its own firewall, from a change they made themselves."""
    with pytest.raises(InUse, match="lockout-critical"):
        remove_alias(a_policy(), "Mgmt_Sources")


def test_an_unreferenced_alias_is_removed() -> None:
    assert "Spare_Alias" not in {a.name for a in remove_alias(a_policy(), "Spare_Alias").aliases}


def test_alias_references_finds_every_kind_of_pointer() -> None:
    policy = a_policy()
    assert alias_references(policy, "Fleet") == ("dependency Agents",)


# --- renaming ---------------------------------------------------------------


def test_renaming_a_service_carries_its_references() -> None:
    """Without this a rename silently empties every host that ran it.

    The name stops resolving, the ports vanish from generation, and nothing reports an
    error because an unknown service is indistinguishable from no service.
    """
    catalogue, estate, outcome = rename_service(a_catalogue(), an_estate(), "RDP", "Remote Desktop")
    assert "RDP" not in catalogue.services
    assert catalogue.services["Remote Desktop"].tcp == (3389,)
    assert catalogue.host_types["windows_workstation"].services == ("Remote Desktop",)
    assert estate.firewalls[0].hosts[0].services == ("Remote Desktop", "SMB")
    assert service_references(catalogue, estate, "RDP") == (), (
        "nothing still points at the old name"
    )


def test_a_rename_reports_what_it_touched() -> None:
    """The blast radius, stated, rather than trusting that it worked."""
    _catalogue, _estate, outcome = rename_service(
        a_catalogue(), an_estate(), "SMB", "Windows file sharing"
    )
    assert "domain_controller" in outcome.summary
    assert "dc01" in outcome.summary
    assert outcome.old == "SMB" and outcome.new == "Windows file sharing"


def test_renaming_something_that_does_not_exist_fails_loudly() -> None:
    with pytest.raises(KeyError):
        rename_service(a_catalogue(), an_estate(), "Nope", "Something")


# --- removing what should be removable --------------------------------------


def test_a_host_and_a_group_can_be_removed() -> None:
    without_host = remove_host(an_estate(), "alpha", "dc01")
    assert without_host.firewalls[0].hosts == ()

    without_group = remove_host_group(an_estate(), "alpha", "ws1")
    assert without_group.firewalls[0].host_groups == ()
    assert [h.hostname for h in without_group.firewalls[0].all_hosts()] == ["dc01"]


def test_a_policy_service_can_be_removed() -> None:
    assert remove_policy_service(a_policy(), "alpha", "AD").firewalls[0].services == ()
