"""Phase 9.1–9.3 — services, host types and host groups.

An estate is a few kinds of machine repeated, and declaring each one by hand is how a
host gets missed. A host nobody declared is a host whose ports nobody opened, and
nothing downstream notices — which is why groups expand into real hosts rather than
staying an abstraction the rest of the tool has to understand.
"""

from __future__ import annotations

from ipaddress import IPv4Address, IPv6Address
from pathlib import Path

import pytest

from btht.app.model.estate import HostGroup
from btht.app.model.services import (
    Catalogue,
    Confidence,
    HostType,
    Service,
    load_catalogue,
    save_catalogue,
)

SHIPPED = Path(__file__).resolve().parents[1] / "service-catalogue.yaml"


def catalogue() -> Catalogue:
    return load_catalogue(SHIPPED)


# --- the catalogue ----------------------------------------------------------


def test_the_shipped_catalogue_names_services_rather_than_ports() -> None:
    """The operator picks `RDP`, not 3389. That is the whole point of the layer."""
    loaded = catalogue()
    assert loaded.services["RDP"].tcp == (3389,)
    assert loaded.services["SSH"].tcp == (22,)
    assert "DNS" in loaded.services


def test_the_traps_are_attached_to_the_service_that_carries_them() -> None:
    """A note nobody reads is worthless; a note on the thing you are picking is not."""
    rpc = catalogue().services["RPC dynamic range"]
    assert "replication" in rpc.note
    assert rpc.tcp_dynamic == "49152-65535"

    ftp = catalogue().services["FTP control"]
    assert "no FTP helper" in ftp.note, "a port forward on 21 alone does nothing"


def test_confidence_is_recorded_because_some_ports_are_guesses() -> None:
    loaded = catalogue()
    assert loaded.services["RDP"].confidence is Confidence.STANDARD
    assert loaded.services["Elastic Fleet"].confidence is Confidence.ASSUMED
    assert loaded.unverified(("RDP", "SSH")) == ()


def test_a_host_type_carries_what_that_kind_of_machine_runs() -> None:
    dc = catalogue().host_types["domain_controller"]
    assert "RPC dynamic range" in dc.services, "the one everybody forgets"
    assert "Kerberos" in dc.services
    assert dc.default_os


def test_ports_for_a_host_type_are_deduplicated_and_ordered() -> None:
    loaded = catalogue()
    ports = loaded.ports_for(loaded.host_types["domain_controller"].services)
    assert ("tcp", 445) in ports
    assert ("udp", 88) in ports
    assert ports == tuple(sorted(set(ports)))


def test_hostname_patterns_all_point_at_a_type_that_exists() -> None:
    """A suggestion resolving to nothing is worse than no suggestion.

    The operator sees a blank where they expected a proposal and cannot tell whether
    the tool looked or had nothing to say.
    """
    assert catalogue().dangling_patterns() == ()


def test_a_hostname_only_suggests_a_type_and_never_assigns_one() -> None:
    loaded = catalogue()
    assert loaded.suggest_type("dc01") == "domain_controller"
    assert loaded.suggest_type("ws101") == "windows_workstation"
    assert loaded.suggest_type("something-bespoke") == "", "no guess"


# --- defining new ones ------------------------------------------------------


def test_a_non_standard_service_is_first_class(tmp_path: Path) -> None:
    """Every estate has something bespoke on an odd port.

    A catalogue that only knows well-known ports forces the operator to lie about
    what they are running.
    """
    path = tmp_path / "catalogue.yaml"
    extended = catalogue().with_service(
        Service(
            name="Range scoring agent",
            tcp=(8443, 9999),
            descr="Bespoke, exercise-specific",
            confidence=Confidence.UNVERIFIED,
            custom=True,
        )
    )
    save_catalogue(extended, path)

    reloaded = load_catalogue(path)
    service = reloaded.services["Range scoring agent"]
    assert service.tcp == (8443, 9999)
    assert service.custom is True
    assert reloaded.unverified(("Range scoring agent",)) == ("Range scoring agent",), (
        "an unverified service keeps a rule open until somebody closes it"
    )


def test_a_new_host_type_can_be_defined_and_reloaded(tmp_path: Path) -> None:
    path = tmp_path / "catalogue.yaml"
    extended = catalogue().with_host_type(
        HostType(
            name="uav_ground_station",
            services=("SSH", "HTTPS"),
            default_os="Windows 11 23H2",
            custom=True,
        )
    )
    save_catalogue(extended, path)
    reloaded = load_catalogue(path)
    assert reloaded.host_types["uav_ground_station"].services == ("SSH", "HTTPS")
    assert reloaded.host_types["uav_ground_station"].custom is True


def test_saving_preserves_what_the_tool_does_not_model(tmp_path: Path) -> None:
    """The shipped file carries prose and role sets this layer does not read."""
    path = tmp_path / "catalogue.yaml"
    path.write_text(SHIPPED.read_text(encoding="utf-8"), encoding="utf-8")
    save_catalogue(load_catalogue(path), path)
    text = path.read_text(encoding="utf-8")
    assert "port_aliases" in text
    assert "naming_rules" in text


# --- host groups ------------------------------------------------------------


def test_a_group_expands_into_real_hosts() -> None:
    """`ws101` to `ws110`, addressed consecutively, exactly as the diagram reads."""
    group = HostGroup(
        name_prefix="ws1",
        count=10,
        first_index=1,
        segment_role="ws",
        host_type="windows_workstation",
        os="Windows 10 22H2",
        v4_start=IPv4Address("25.42.9.2"),
        v6_start=IPv6Address("fd81:25:42:9::2"),
    )
    hosts = group.expand(("RDP", "SMB"))
    assert len(hosts) == 10
    assert hosts[0].hostname == "ws101"
    assert hosts[-1].hostname == "ws110"
    assert str(hosts[0].v4) == "25.42.9.2"
    assert str(hosts[-1].v4) == "25.42.9.11"
    assert str(hosts[-1].v6) == "fd81:25:42:9::b"
    assert hosts[0].os == "Windows 10 22H2"
    assert hosts[0].services == ("RDP", "SMB")
    assert hosts[0].group == "ws1", "a host remembers the group it came from"


def test_a_group_can_override_the_type_default() -> None:
    group = HostGroup(name_prefix="ws2", count=2, services=("SSH",))
    assert group.expand(("RDP",))[0].services == ("SSH",)


def test_a_group_with_no_addresses_still_expands() -> None:
    """The machines exist and are visible with nothing to address yet.

    Dropping them silently would hide hosts the operator has said they have.
    """
    hosts = HostGroup(name_prefix="tbc", count=3).expand()
    assert [h.hostname for h in hosts] == ["tbc01", "tbc02", "tbc03"]
    assert all(h.v4 is None for h in hosts)


def test_an_implausible_group_is_refused() -> None:
    """Almost certainly a typo in the count or the range, and 4000 hosts either way."""
    with pytest.raises(ValueError, match="typo"):
        HostGroup(name_prefix="ws", count=4000)
    with pytest.raises(ValueError, match="not a group"):
        HostGroup(name_prefix="ws", count=0)


def test_index_width_follows_how_the_operator_writes_it() -> None:
    assert HostGroup(name_prefix="ws", count=1, first_index=1, index_width=3).names() == ("ws001",)
    assert HostGroup(name_prefix="srv", count=1, first_index=7, index_width=1).names() == ("srv7",)


def test_groups_and_individual_hosts_are_read_as_one_list() -> None:
    """Everything downstream reads `all_hosts()`, so a host in a group of ten is as
    real as one typed in alone — it gets rules, scoring assertions and a topology node."""
    from ipaddress import IPv4Address as V4

    from btht.app.model.estate import Firewall, Host, Node, Platform

    firewall = Firewall(
        enclave="alpha",
        fqdn="fw1",
        node=Node(name="fw1", platform=Platform.PFSENSE, mgmt_address=V4("10.0.0.1")),
        hosts=(Host(hostname="npc-server", v4=V4("25.42.9.249"), out_of_bounds=True),),
        host_groups=(
            HostGroup(name_prefix="ws1", count=3, v4_start=V4("25.42.9.2"), segment_role="ws"),
        ),
    )
    everything = firewall.all_hosts(catalogue())
    assert [h.hostname for h in everything] == ["npc-server", "ws101", "ws102", "ws103"]


def test_a_group_can_mirror_the_v4_octet_into_the_v6_address() -> None:
    """The observed range writes `25.X.17.13` as `fd81:25:X:17::13`.

    The last v6 group is the v4 octet written out, not the thirteenth address in the
    block. Counting from a start address gives `::d` for the thirteenth host — a
    different machine, addressed plausibly, which nothing downstream would question.
    """
    group = HostGroup(
        name_prefix="ws2",
        count=5,
        first_index=1,
        segment_role="ws",
        v4_start=IPv4Address("25.42.17.13"),
        v6_prefix="fd81:25:42:17",
    )
    hosts = group.expand()
    assert [str(h.v4) for h in hosts][:2] == ["25.42.17.13", "25.42.17.14"]
    assert [str(h.v6) for h in hosts][:2] == ["fd81:25:42:17::13", "fd81:25:42:17::14"]
    assert str(hosts[-1].v6) == "fd81:25:42:17::17"


def test_counting_and_mirroring_genuinely_differ() -> None:
    """Stated as its own test because the two look identical for the first nine hosts."""
    counted = HostGroup(
        name_prefix="ws",
        count=12,
        v4_start=IPv4Address("25.42.9.2"),
        v6_start=IPv6Address("fd81:25:42:9::2"),
    ).expand()
    mirrored = HostGroup(
        name_prefix="ws",
        count=12,
        v4_start=IPv4Address("25.42.9.2"),
        v6_prefix="fd81:25:42:9",
    ).expand()
    assert str(counted[9].v6) == "fd81:25:42:9::b"
    assert str(mirrored[9].v6) == "fd81:25:42:9::11"


# --- the guard that should have existed from the start ----------------------


def test_no_host_type_opens_a_port_the_evidence_does_not_support() -> None:
    """Seeded host types must match the shipped role-keyed port sets exactly.

    This test exists because the first seeding invented ports. `windows_workstation`
    gained SMB, which the source does not list — it says workstations are 3389 and 22,
    "Windows hosts scored on RDP, Linux on SSH". A generated ruleset would have opened
    file sharing inbound to every workstation in the estate, for no reason anybody
    could have traced, and every layer downstream would have treated it as declared
    intent.

    Inventing a port is the exact failure this tool exists to prevent, so it is
    asserted rather than reviewed.
    """
    import yaml

    data = yaml.safe_load(SHIPPED.read_text(encoding="utf-8"))
    role_sets = data["services"]
    named = data["named_services"]

    def implied(service_names: list[str]) -> tuple[set[int], set[int]]:
        tcp: set[int] = set()
        udp: set[int] = set()
        for name in service_names:
            spec = named.get(name, {})
            tcp |= set(spec.get("tcp") or [])
            udp |= set(spec.get("udp") or [])
        return tcp, udp

    problems = []
    for type_name, spec in sorted(data["host_types"].items()):
        role = role_sets.get(type_name)
        if role is None:
            continue  # a type with no shipped equivalent, such as the workstation split
        tcp, udp = implied(spec["services"])
        invented = sorted(tcp - set(role.get("tcp") or [])) + sorted(
            f"udp/{p}" for p in udp - set(role.get("udp") or [])
        )
        missing = sorted(set(role.get("tcp") or []) - tcp) + sorted(
            f"udp/{p}" for p in set(role.get("udp") or []) - udp
        )
        if invented:
            problems.append(f"{type_name} opens {invented}, which the evidence does not list")
        if missing:
            problems.append(f"{type_name} omits {missing}, which the evidence does list")
    assert problems == [], "\n  " + "\n  ".join(problems)


def test_a_named_service_does_not_silently_widen() -> None:
    """Picking file sharing must not also open name services.

    The first version bundled 445, 139, 137 and 138 into `SMB`, so every host that ran
    it opened four ports when the operator asked for one.
    """
    loaded = catalogue()
    assert loaded.services["SMB"].tcp == (445,)
    assert loaded.services["SMB"].udp == ()
    assert loaded.services["NetBIOS"].tcp == (139,)
    assert "not open name services" in loaded.services["NetBIOS"].note


def test_the_workstation_split_follows_what_the_note_says() -> None:
    """ "Windows hosts scored on RDP, Linux on SSH" — so neither runs the other's."""
    loaded = catalogue()
    assert loaded.host_types["windows_workstation"].services == ("RDP",)
    assert loaded.host_types["linux_workstation"].services == ("SSH",)


# --- templates doing their job ----------------------------------------------


def test_choosing_a_host_template_fills_in_the_rest_of_the_form() -> None:
    """The whole reason templates exist. Without this a template is a label.

    Carried as data on the select so one listener serves every form; the values are
    asserted here because a broken map fails silently in the browser.
    """
    from pathlib import Path

    from btht.app.model.services import load_catalogue
    from btht.app.web.forms import host_fields

    catalogue = load_catalogue(Path(__file__).resolve().parents[1] / "service-catalogue.yaml")
    field = next(f for f in host_fields(catalogue) if f["name"] == "host_type")

    assert "fills" in field, "picking a template must populate the form"
    for name, kind in catalogue.host_types.items():
        assert field["fills"][name]["os"] == kind.default_os
        assert field["fills"][name]["services"] == list(kind.services)


def test_host_groups_get_the_same_treatment() -> None:
    from pathlib import Path

    from btht.app.model.services import load_catalogue
    from btht.app.web.forms import group_fields

    catalogue = load_catalogue(Path(__file__).resolve().parents[1] / "service-catalogue.yaml")
    field = next(f for f in group_fields(catalogue) if f["name"] == "host_type")
    assert "fills" in field


def test_the_template_list_names_the_operating_system() -> None:
    """An estate has several kinds of workstation differing only by version.

    `windows_workstation` alone does not say which one you are about to create, so the
    option is labelled with its OS while still submitting the bare name.
    """
    from pathlib import Path

    from btht.app.model.services import load_catalogue
    from btht.app.web.forms import host_fields

    catalogue = load_catalogue(Path(__file__).resolve().parents[1] / "service-catalogue.yaml")
    field = next(f for f in host_fields(catalogue) if f["name"] == "host_type")
    labelled = [o for o in field["options"] if isinstance(o, dict)]
    assert labelled, "options must carry a label distinct from the submitted value"
    for option in labelled:
        kind = catalogue.host_types[option["value"]]
        if kind.default_os:
            assert kind.default_os in option["label"]
        assert option["value"] == kind.name, "the name is still what gets submitted"


def test_the_template_question_comes_before_what_it_answers() -> None:
    """Asking it last means typing the answers first, then having them overwritten."""
    from pathlib import Path

    from btht.app.model.services import load_catalogue
    from btht.app.web.forms import host_fields

    catalogue = load_catalogue(Path(__file__).resolve().parents[1] / "service-catalogue.yaml")
    order = [f["name"] for f in host_fields(catalogue)]
    assert order.index("host_type") == 1
    assert order.index("host_type") < order.index("os")
    assert order.index("host_type") < order.index("services")


def test_adding_a_machine_does_not_ask_which_segment() -> None:
    """You got here by opening a segment. It is still submitted, just not asked."""
    from pathlib import Path

    from btht.app.model.estate import Host
    from btht.app.model.services import load_catalogue
    from btht.app.web.forms import host_fields

    catalogue = load_catalogue(Path(__file__).resolve().parents[1] / "service-catalogue.yaml")
    adding = next(f for f in host_fields(catalogue, segment="svrs") if f["name"] == "segment_role")
    assert adding["hidden"] is True
    assert adding["value"] == "svrs"

    existing = Host(hostname="dc01", segment_role="svrs")
    editing = next(
        f for f in host_fields(catalogue, existing) if f["name"] == "segment_role"
    )
    assert not editing.get("hidden"), "moving a host between segments is a real edit"
