"""Build a demo range so the tool can be looked at without a real one.

Modelled on the **Deployed Official** and **Deployed Secret** enclaves as the range
diagram draws them, on team 42, so the mapping can be checked against something real:
the same segments, the same machine names, the same operating systems, and the same
addressing convention — including the one where the IPv6 host part mirrors the IPv4
octet rather than counting (`25.42.17.13` is `fd81:25:42:17::13`, not `::d`).

Run with `make demo`. Writes to the gitignored estates directory.
"""

from __future__ import annotations

from ipaddress import IPv4Address, IPv4Interface, IPv6Interface, ip_network

from btht.app.data import ESTATES, ISA_CHECKS, SERVICE_CATALOGUE
from btht.app.ingest.isa import load_catalogue as load_isa
from btht.app.ingest.roles import SideRule
from btht.app.model.estate import (
    Estate,
    Firewall,
    Host,
    HostGroup,
    Interface,
    Node,
    Platform,
    SourceOfTruth,
)
from btht.app.model.policy import (
    Dependency,
    EgressPolicy,
    FirewallPolicy,
    Policy,
    PolicyAlias,
    Selector,
    ServiceRule,
    save_estate,
    save_policy,
)
from btht.app.model.services import load_catalogue

TEAM = 42
V6 = f"fd81:25:{TEAM}"


def interface(ifname: str, role: str, third: int, host: int, *, is_lan: bool = False) -> Interface:
    return Interface(
        ifname=ifname,
        role=role,
        descr=f"{role}",
        v4=IPv4Interface(f"25.{TEAM}.{third}.{host}/24"),
        v6=IPv6Interface(f"{V6}:{third}::{host}/64"),
        is_lan=is_lan,
    )


#: The ISA board proposes a check set per role — HOST (the ICMP ping) among them for
#: everything the scoring bot must see as up. Assigning it here is what makes the demo
#: actually generate scoring rules, which is the whole point of the exercise.
ISA = load_isa(ISA_CHECKS)


def host(name: str, os_name: str, third: int, last: int, segment: str, host_type: str) -> Host:
    """One named machine, addressed the way the diagram addresses it."""
    from ipaddress import IPv6Address

    return Host(
        hostname=name,
        os=os_name,
        v4=IPv4Address(f"25.{TEAM}.{third}.{last}"),
        v6=IPv6Address(f"{V6}:{third}::{last}"),
        segment_role=segment,
        service_role=host_type,
        isa_checks=ISA.propose(host_type),
        source_of_truth=SourceOfTruth.ANNEX,
    )


def workstations(
    prefix: str, count: int, first: int, os_name: str, third: int, start: int, host_type: str
) -> HostGroup:
    return HostGroup(
        name_prefix=prefix,
        count=count,
        first_index=first,
        index_width=2,
        segment_role="ws",
        host_type=host_type,
        os=os_name,
        isa_checks=ISA.propose(host_type),
        v4_start=IPv4Address(f"25.{TEAM}.{third}.{start}"),
        v6_prefix=f"{V6}:{third}",
    )


def deployed_official() -> Firewall:
    """`do.XX.dcm.ex` — WAN .0.10, workstations .9, servers .10, DMZ .11."""
    node = Node(
        name="fw1.do",
        platform=Platform.PFSENSE,
        mgmt_address=IPv4Address(f"25.{TEAM}.0.10"),
        credential_ref="monitor-key",
        enclave="do",
        gui_url=f"https://25.{TEAM}.0.10/",
        ssh_user="analyst",
    )
    return Firewall(
        enclave="do",
        fqdn=f"fw1.do.{TEAM}.dcm.ex",
        node=node,
        side="deployed",
        config_version="23.3",
        interfaces=(
            Interface(
                ifname="wan",
                role="wan",
                descr="bt_wan_do",
                v4=IPv4Interface(f"25.{TEAM}.0.10/24"),
                v6=IPv6Interface(f"{V6}::10/64"),
                upstreams=("r1", "r2"),
            ),
            interface("lan", "ws", 9, 1, is_lan=True),
            interface("opt1", "svrs", 10, 1),
            interface("opt2", "dmz", 11, 1),
        ),
        hosts=(
            host("ftp", "Ubuntu 24.04", 11, 22, "dmz", "ftp_server"),
            host("proxy", "Ubuntu 24.04", 11, 53, "dmz", "proxy"),
            host("dc01", "Windows Server 22 GUI", 10, 11, "svrs", "domain_controller"),
            host("dc02", "Windows Server 22 GUI", 10, 12, "svrs", "domain_controller"),
            host("mail", "Windows Server 22 GUI", 10, 25, "svrs", "mail_server"),
            host("fs", "Windows Server 22 GUI", 10, 139, "svrs", "file_server"),
            host("apj", "Ubuntu 24.04", 10, 6, "svrs", "web_server"),
            host("nextcloud", "Ubuntu 24.04", 10, 7, "svrs", "nextcloud"),
            host("modgpt", "Ubuntu 24.04", 10, 8, "svrs", "web_server"),
            Host(
                hostname="npc-server-do",
                os="Ubuntu 24.04",
                v4=IPv4Address(f"25.{TEAM}.9.249"),
                segment_role="ws",
                service_role="npc_server",
                out_of_bounds=True,
                source_of_truth=SourceOfTruth.ANNEX,
                services=("SSH",),
            ),
        ),
        host_groups=(
            workstations("ws1", 10, 1, "Windows 10 22H2", 9, 2, "windows_workstation"),
            workstations("ws2", 10, 1, "Windows 11 23H2", 9, 31, "windows_workstation"),
            workstations("ws3", 5, 1, "Ubuntu Desktop 24.04", 9, 60, "linux_workstation"),
            workstations("ws4", 5, 1, "Ubuntu Desktop 24.04", 9, 80, "linux_workstation"),
        ),
    )


def deployed_secret() -> Firewall:
    """`ds.XX.dcm.ex` — WAN .0.12, workstations .17, servers .18, UAV .19, DMZ .21."""
    node = Node(
        name="fw1.ds",
        platform=Platform.PFSENSE,
        mgmt_address=IPv4Address(f"25.{TEAM}.0.12"),
        credential_ref="monitor-key",
        enclave="ds",
        gui_url=f"https://25.{TEAM}.0.12/",
        ssh_user="analyst",
    )
    return Firewall(
        enclave="ds",
        fqdn=f"fw1.ds.{TEAM}.dcm.ex",
        node=node,
        side="deployed",
        config_version="23.3",
        interfaces=(
            Interface(
                ifname="wan",
                role="wan",
                descr="bt_wan_ds",
                v4=IPv4Interface(f"25.{TEAM}.0.12/24"),
                v6=IPv6Interface(f"{V6}::12/64"),
                upstreams=("r1", "r2"),
            ),
            interface("lan", "ws", 17, 1, is_lan=True),
            interface("opt1", "svrs", 18, 1),
            interface("opt2", "uav", 19, 1),
            interface("opt3", "dmz", 21, 1),
        ),
        hosts=(
            host("sftp", "Ubuntu 24.04", 21, 22, "dmz", "ftp_server"),
            host("proxy", "Ubuntu 24.04", 21, 53, "dmz", "proxy"),
            host("pilot", "Windows 11 23H2", 19, 11, "uav", "windows_workstation"),
            host("camera", "Windows 11 23H2", 19, 12, "uav", "windows_workstation"),
            host("dc01", "Windows Server 22 GUI", 18, 11, "svrs", "domain_controller"),
            host("dc02", "Windows Server 22 GUI", 18, 12, "svrs", "domain_controller"),
            host("mail", "Windows Server 22 GUI", 18, 25, "svrs", "mail_server"),
            host("fs", "Windows Server 22 GUI", 18, 139, "svrs", "file_server"),
            host("tak", "Ubuntu 24.04", 18, 6, "svrs", "web_server"),
            host("nextcloud", "Ubuntu 24.04", 18, 7, "svrs", "nextcloud"),
            host("aistracks", "Ubuntu 24.04", 18, 9, "svrs", "web_server"),
            host("video", "Linux", 18, 13, "svrs", "web_server"),
            Host(
                hostname="npc-server-ds",
                os="Ubuntu 24.04",
                v4=IPv4Address(f"25.{TEAM}.17.41"),
                segment_role="ws",
                service_role="npc_server",
                out_of_bounds=True,
                source_of_truth=SourceOfTruth.ANNEX,
                services=("SSH",),
            ),
        ),
        host_groups=(
            workstations("ws1", 5, 1, "Windows 10 22H2", 17, 2, "windows_workstation"),
            workstations("ws2", 5, 1, "Windows 11 23H2", 17, 13, "windows_workstation"),
            workstations("ws3", 5, 1, "Ubuntu Desktop 24.04", 17, 21, "linux_workstation"),
            workstations("ws4", 5, 1, "Ubuntu Desktop 24.04", 17, 32, "linux_workstation"),
        ),
    )


def build() -> tuple[Estate, Policy]:
    routers = tuple(
        Node(
            name=name,
            platform=Platform.FRR,
            mgmt_address=IPv4Address(f"25.{TEAM}.0.{last}"),
            credential_ref="monitor-key",
            enclave="",
            ssh_user="analyst",
            poll_seconds=120,
        )
        for name, last in (("r1", 1), ("r2", 2))
    )
    estate = Estate(
        team=TEAM,
        team_name=f"BT{TEAM}",
        role_vocabulary=("wan", "ws", "svrs", "dmz", "uav"),
        firewalls=(deployed_official(), deployed_secret()),
        nodes=routers,
    )

    def enclave_policy(enclave: str, svrs: int, dmz: int) -> FirewallPolicy:
        return FirewallPolicy(
            enclave=enclave,
            services=(
                ServiceRule(
                    name="Domain services",
                    segment="svrs",
                    host=f"25.{TEAM}.{svrs}.11",
                    protocol="tcp",
                    ports=(53, 88, 135, 389, 445, 464, 636, 3268, 3269),
                    source=Selector(segments=("ws", "svrs")),
                    notes="Scored target. The RPC dynamic range is not in this list and "
                    "replication needs it — restrict it by source rather than omitting it.",
                ),
                ServiceRule(
                    name="Mail and webmail",
                    segment="svrs",
                    host=f"25.{TEAM}.{svrs}.25",
                    protocol="tcp",
                    ports=(25, 143, 443, 993),
                    source=Selector(segments=("ws",)),
                ),
                ServiceRule(
                    name="Web proxy out of the DMZ",
                    segment="dmz",
                    host=f"25.{TEAM}.{dmz}.53",
                    protocol="tcp",
                    ports=(3128, 8080),
                    source=Selector(segments=("ws", "svrs")),
                    notes="Ports assumed. Confirm before relying on them.",
                ),
                ServiceRule(
                    name="RDP for the user simulators",
                    segment="ws",
                    protocol="tcp",
                    ports=(3389,),
                    source=Selector(alias="Remote_Access"),
                    notes="A technical obligation, and their complaints are scored.",
                ),
            ),
            egress=EgressPolicy(
                default="deny_and_log",
                notes="Declared dependencies are emitted above this deny automatically.",
            ),
        )

    policy = Policy(
        aliases=(
            PolicyAlias(
                name="Mgmt_Sources",
                lockout_critical=True,
                nested_aliases=("Remote_Access",),
                segments=("ws",),
                descr="Where firewall administration may originate",
            ),
            PolicyAlias(
                name="Remote_Access",
                entries=(
                    "172.21.31.0/24",
                    "198.18.128.0/24",
                    f"198.19.{TEAM}.0/24",
                    "172.21.28.0/24",
                    "172.21.29.0/24",
                ),
                lockout_critical=True,
                descr="Shipped VPN ranges. Narrowing this loses access to your own firewalls",
            ),
            PolicyAlias(name="DNS_Servers", type="host", entries=("10.181.0.11", "10.181.0.12")),
            PolicyAlias(name="NTP_Servers", type="host", entries=(f"25.{TEAM}.10.11",)),
            PolicyAlias(
                name="Scoring_Sources",
                entries=(f"25.{TEAM}.9.254/32", f"25.{TEAM}.17.254/32"),
                descr="Local scoring bots, one per deployed enclave",
            ),
        ),
        dependencies=(
            Dependency(
                name="DO agents to the DS collector",
                from_enclaves=("do",),
                from_segments=("svrs",),
                to_enclave="ds",
                to_host=f"25.{TEAM}.18.9",
                protocol="tcp",
                ports=(8220, 9200),
                notes="Agents initiate outbound; an egress deny severs them silently.",
            ),
        ),
        firewalls=(enclave_policy("do", 10, 11), enclave_policy("ds", 18, 21)),
    )
    return estate, policy


def main() -> int:
    estate, policy = build()
    path = ESTATES / "range.yaml"
    save_estate(
        estate,
        path,
        enclave_tokens=("bt_wan_", "do_", "ds_"),
        sides=(SideRule(network=ip_network("25.0.0.0/8"), label="deployed"),),
    )
    save_policy(policy, path)

    catalogue = load_catalogue(SERVICE_CATALOGUE)
    for firewall in estate.firewalls:
        hosts = firewall.all_hosts(catalogue)
        groups = sum(g.count for g in firewall.host_groups)
        print(
            f"  {firewall.enclave:4} {len(firewall.interfaces)} interfaces, "
            f"{len(hosts)} hosts ({groups} from groups)"
        )
    print(f"wrote {path}")
    print("open http://127.0.0.1:8000/range/topology")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
