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
    editing = next(f for f in host_fields(catalogue, existing) if f["name"] == "segment_role")
    assert not editing.get("hidden"), "moving a host between segments is a real edit"


def test_a_machine_shows_what_it_runs_even_when_it_came_from_a_template() -> None:
    """The table, the edit form and the generated rules must agree.

    A group created from a template stored no services of its own, so the services
    column was blank and the edit form opened with nothing ticked — while the rules
    generated for those same machines used the template's set. The tool was showing one
    thing and doing another.
    """
    from btht.app.model.services import Catalogue, HostType, Service, services_for

    catalogue = Catalogue(
        services={"RDP": Service(name="RDP", tcp=(3389,))},
        host_types={"windows_workstation": HostType(name="windows_workstation", services=("RDP",))},
    )
    assert services_for(catalogue, "windows_workstation", ()) == ("RDP",)


def test_what_was_declared_always_wins_over_the_template() -> None:
    """The template is a starting point. An override must not be quietly re-expanded."""
    from btht.app.model.services import Catalogue, HostType, Service, services_for

    catalogue = Catalogue(
        services={"RDP": Service(name="RDP"), "SSH": Service(name="SSH")},
        host_types={"windows_workstation": HostType(name="windows_workstation", services=("RDP",))},
    )
    assert services_for(catalogue, "windows_workstation", ("SSH",)) == ("SSH",)


def test_an_unknown_template_resolves_to_nothing_rather_than_raising() -> None:
    from btht.app.model.services import Catalogue, services_for

    assert services_for(Catalogue(), "no_such_type", ()) == ()


def test_editing_a_templated_group_opens_with_its_services_ticked() -> None:
    from pathlib import Path

    from btht.app.model.estate import HostGroup
    from btht.app.model.services import load_catalogue
    from btht.app.web.forms import group_fields

    catalogue = load_catalogue(Path(__file__).resolve().parents[1] / "service-catalogue.yaml")
    kind = next(iter(catalogue.host_types.values()))
    group = HostGroup(name_prefix="ws1", count=10, host_type=kind.name, segment_role="ws")
    field = next(f for f in group_fields(catalogue, group) if f["name"] == "services")
    assert field["value"] == list(kind.services)


def test_what_the_screen_shows_is_what_the_rules_use() -> None:
    """The invariant this kept failing on, asserted directly.

    Groups resolved an empty service list to their template and single hosts did not,
    so `dc01` — a declared domain controller with no services of its own — displayed
    nine services on every screen and generated rules for none of them. A tool that
    shows one thing and does another is worse than one that does neither.

    Whichever way the ambiguity is settled, both paths have to settle it identically.
    Empty means "whatever the template says"; to say a machine runs nothing, clear its
    template too.
    """
    from ipaddress import IPv4Address

    from btht.app.model.estate import Firewall, Host, HostGroup, Node, Platform
    from btht.app.model.services import Catalogue, HostType, Service, services_for

    catalogue = Catalogue(
        services={n: Service(name=n) for n in ("RDP", "SSH", "SMB")},
        host_types={
            "workstation": HostType(name="workstation", services=("RDP",)),
            "server": HostType(name="server", services=("SSH", "SMB")),
        },
    )
    firewall = Firewall(
        enclave="do",
        fqdn="do.example",
        node=Node(name="do", platform=Platform.PFSENSE, mgmt_address=IPv4Address("10.0.0.1")),
        hosts=(
            # follows its template
            Host(hostname="a", service_role="server", segment_role="svrs"),
            # overridden away from it
            Host(hostname="b", service_role="server", services=("RDP",), segment_role="svrs"),
            # no template at all
            Host(hostname="c", segment_role="svrs"),
        ),
        host_groups=(
            HostGroup(name_prefix="ws", count=2, host_type="workstation", segment_role="ws"),
            HostGroup(
                name_prefix="kiosk",
                count=1,
                host_type="workstation",
                services=("SSH",),
                segment_role="ws",
            ),
        ),
    )

    for host in firewall.all_hosts(catalogue):
        declared = next(
            (h for h in firewall.hosts if h.hostname == host.hostname),
            None,
        )
        group = next((g for g in firewall.host_groups if g.name_prefix == host.group), None)
        shown = (
            services_for(catalogue, declared.service_role, declared.services)
            if declared is not None
            else services_for(catalogue, group.host_type, group.services)  # type: ignore[union-attr]
        )
        assert tuple(shown) == tuple(host.services), f"{host.hostname} disagrees"

    resolved = {h.hostname: h.services for h in firewall.all_hosts(catalogue)}
    assert resolved["a"] == ("SSH", "SMB"), "follows the template"
    assert resolved["b"] == ("RDP",), "a manual change wins over the template"
    assert resolved["c"] == (), "no template, nothing assumed"
    assert resolved["ws01"] == ("RDP",)
    assert resolved["kiosk01"] == ("SSH",), "an override on a group wins too"


def test_clearing_the_template_is_how_you_say_it_runs_nothing() -> None:
    from ipaddress import IPv4Address

    from btht.app.model.estate import Firewall, Host, Node, Platform
    from btht.app.model.services import Catalogue, HostType, Service

    catalogue = Catalogue(
        services={"SSH": Service(name="SSH")},
        host_types={"server": HostType(name="server", services=("SSH",))},
    )
    firewall = Firewall(
        enclave="do",
        fqdn="do.example",
        node=Node(name="do", platform=Platform.PFSENSE, mgmt_address=IPv4Address("10.0.0.1")),
        hosts=(Host(hostname="bare", segment_role="svrs"),),
    )
    assert firewall.all_hosts(catalogue)[0].services == ()


# --- ISA scoring checks, including ICMP -------------------------------------


def test_icmp_reachability_comes_from_the_host_isa_check_not_a_service() -> None:
    """The answer to 'do I add ICMP to every host?' — no. It is the HOST scoring check.

    A host is pinged by the scoring bot because it carries `HOST`, which the catalogue
    maps to proto icmp. Ticking it emits the echo rule; ICMP is never a per-host service.
    """
    from pathlib import Path

    from btht.app.ingest.isa import load_catalogue, required_ports

    isa = load_catalogue(Path(__file__).resolve().parents[1] / "isa-checks.yaml")
    pairs = required_ports(("HOST",), isa)
    assert ("icmp", 0) in pairs or any(proto == "icmp" for proto, _ in pairs)


def test_a_role_proposes_host_so_every_scored_machine_is_pingable() -> None:
    """Every role the demo uses carries HOST, so nothing is silently unreachable."""
    from pathlib import Path

    from btht.app.ingest.isa import load_catalogue

    isa = load_catalogue(Path(__file__).resolve().parents[1] / "isa-checks.yaml")
    for role in ("windows_workstation", "domain_controller", "linux_workstation"):
        assert "HOST" in isa.propose(role), f"{role} would not be pinged"


def test_a_group_carries_isa_checks_onto_every_expanded_host() -> None:
    """Ten pinged workstations are one HOST tick on the group, not ten on the hosts."""
    from btht.app.model.estate import HostGroup

    group = HostGroup(
        name_prefix="ws1",
        count=3,
        host_type="windows_workstation",
        segment_role="ws",
        isa_checks=("HOST", "RDP"),
    )
    for expanded in group.expand():
        assert expanded.isa_checks == ("HOST", "RDP")


def test_the_host_form_offers_the_isa_checks() -> None:
    """The gap this closes: isa_checks had no way in through the UI at all."""
    from pathlib import Path

    from btht.app.ingest.isa import load_catalogue as load_isa
    from btht.app.model.services import load_catalogue
    from btht.app.web.forms import host_fields

    services = load_catalogue(Path(__file__).resolve().parents[1] / "service-catalogue.yaml")
    isa = load_isa(Path(__file__).resolve().parents[1] / "isa-checks.yaml")
    field = next(f for f in host_fields(services, isa=isa) if f["name"] == "isa_checks")
    assert "HOST" in field["checkboxes"]


def test_picking_a_template_proposes_its_scoring_checks() -> None:
    """So a workstation is pingable the moment its template is chosen."""
    from pathlib import Path

    from btht.app.ingest.isa import load_catalogue as load_isa
    from btht.app.model.services import load_catalogue
    from btht.app.web.forms import host_fields

    services = load_catalogue(Path(__file__).resolve().parents[1] / "service-catalogue.yaml")
    isa = load_isa(Path(__file__).resolve().parents[1] / "isa-checks.yaml")
    field = next(f for f in host_fields(services, isa=isa) if f["name"] == "host_type")
    assert "HOST" in field["fills"]["windows_workstation"]["isa_checks"]
