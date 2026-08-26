"""Build a demo estate so the tool can be looked at without a range.

Everything here is invented and obviously so — RFC 5737 documentation addresses, and
segment names that are this operator's to choose. It exists to make the flow reviewable
end to end: declare an estate, see it drawn, declare policy, hit the diff gate.

Run with `make demo`. Writes to the gitignored estates directory.
"""

from __future__ import annotations

from ipaddress import IPv4Address, IPv4Interface, IPv6Address, IPv6Interface, ip_network

from btht.app.data import ESTATES
from btht.app.ingest.roles import SideRule
from btht.app.model.estate import Estate, Firewall, Host, Interface, Node, Platform, SourceOfTruth
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


def firewall(enclave: str, third: int, *, invert_lan: bool = False) -> Firewall:
    """One enclave. `invert_lan` reproduces the case that breaks naive tooling."""
    users = Interface(
        ifname="opt1" if invert_lan else "lan",
        role="users",
        descr=f"{enclave}_users",
        v4=IPv4Interface(f"192.0.{third}.1/24"),
        v6=IPv6Interface(f"2001:db8:{third}::1/64"),
        is_lan=invert_lan is False,
    )
    servers = Interface(
        ifname="lan" if invert_lan else "opt1",
        role="servers",
        descr=f"{enclave}_servers",
        v4=IPv4Interface(f"192.0.{third + 1}.1/24"),
        v6=IPv6Interface(f"2001:db8:{third + 1}::1/64"),
        is_lan=invert_lan,
    )
    return Firewall(
        enclave=enclave,
        fqdn=f"fw1.{enclave}.example",
        node=Node(
            name=f"fw1.{enclave}",
            platform=Platform.PFSENSE,
            mgmt_address=IPv4Address(f"198.51.100.{third}"),
            credential_ref="monitor-key",
            enclave=enclave,
            gui_url=f"https://198.51.100.{third}/",
            ssh_user="analyst",
        ),
        side="north",
        config_version="23.3",
        interfaces=(
            Interface(
                ifname="wan",
                role="wan",
                descr=f"wan_{enclave}",
                v4=IPv4Interface(f"198.51.100.{third}/24"),
            ),
            users,
            servers,
        ),
        hosts=(
            Host(
                hostname=f"dc01.{enclave}",
                v4=IPv4Address(f"192.0.{third + 1}.5"),
                v6=IPv6Address(f"2001:db8:{third + 1}::5"),
                segment_role="servers",
                service_role="domain_controller",
                isa_checks=("HOST", "DNS", "LDAP", "SMB", "RDP"),
                source_of_truth=SourceOfTruth.ANNEX,
            ),
            Host(
                hostname=f"web01.{enclave}",
                v4=IPv4Address(f"192.0.{third + 1}.10"),
                v6=IPv6Address(f"2001:db8:{third + 1}::10"),
                segment_role="servers",
                service_role="web_server",
                isa_checks=("HOST", "HTTP", "HTTPS"),
                source_of_truth=SourceOfTruth.ANNEX,
            ),
            Host(
                hostname="scoringbot",
                v4=IPv4Address(f"192.0.{third}.254"),
                v6=IPv6Address(f"2001:db8:{third}::254"),
                segment_role="users",
                out_of_bounds=True,
                source_of_truth=SourceOfTruth.ANNEX,
            ),
        ),
    )


def build() -> tuple[Estate, Policy]:
    alpha = firewall("alpha", 2)
    # The second enclave inverts LAN, because that is the case worth being able to see
    # on the topology and in the checklist.
    bravo = firewall("bravo", 20, invert_lan=True)

    estate = Estate(
        team=42,
        team_padded="42",
        role_vocabulary=("wan", "users", "servers"),
        firewalls=(alpha, bravo),
        nodes=(
            Node(
                name="r1",
                platform=Platform.FRR,
                mgmt_address=IPv4Address("198.51.100.254"),
                credential_ref="monitor-key",
                enclave="alpha",
                ssh_user="analyst",
                poll_seconds=120,
            ),
        ),
    )

    def enclave_policy(name: str, third: int) -> FirewallPolicy:
        return FirewallPolicy(
            enclave=name,
            services=(
                ServiceRule(
                    name="Domain services",
                    segment="servers",
                    host=f"192.0.{third + 1}.5",
                    protocol="tcp",
                    ports=(53, 88, 389, 445),
                    source=Selector(segments=("users", "servers")),
                    notes="Scored target. Breaking any of these costs availability.",
                ),
                ServiceRule(
                    name="Web to the DMZ host",
                    segment="servers",
                    host=f"192.0.{third + 1}.10",
                    protocol="tcp",
                    ports=(80, 443),
                    source=Selector(any=True),
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
                segments=("users",),
                descr="Where firewall administration may originate",
            ),
            PolicyAlias(name="DNS_Servers", type="host", entries=("198.51.100.11",)),
            PolicyAlias(name="NTP_Servers", type="host", entries=("198.51.100.12",)),
            PolicyAlias(
                name="Bravo_Collector",
                type="host",
                entries=("192.0.21.10", "2001:db8:21::10"),
                descr="Collector in bravo, both families — a dependency named by "
                "address would be IPv4-only and silently half-covered",
            ),
            PolicyAlias(
                name="Scoring_Sources",
                entries=("192.0.2.254/32",),
                descr="Availability probe sources",
            ),
        ),
        dependencies=(
            Dependency(
                name="Alpha agents to Bravo collector",
                from_enclaves=("alpha",),
                from_segments=("servers",),
                to_enclave="bravo",
                to_alias="Bravo_Collector",
                protocol="tcp",
                ports=(8220,),
                notes="Agents initiate outbound; an egress deny severs them silently.",
            ),
        ),
        firewalls=(enclave_policy("alpha", 2), enclave_policy("bravo", 20)),
    )
    return estate, policy


def main() -> int:
    estate, policy = build()
    path = ESTATES / "demo.yaml"
    save_estate(
        estate,
        path,
        enclave_tokens=("alpha_", "bravo_", "wan_"),
        sides=(SideRule(network=ip_network("198.51.100.0/24"), label="north"),),
    )
    save_policy(policy, path)
    print(f"wrote {path}")
    print("open http://127.0.0.1:8000/estates/demo")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
