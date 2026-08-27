"""Router control-plane hardening.

The load-bearing assertion in this file is `test_it_never_filters_transit_traffic`.
The whole proposition is that this ruleset protects the router without touching what
the router is for, and a promise in a docstring is not a property. If a forward or
output chain ever appears in the generated text, that test fails.

The second theme is refusing to produce a lockout. A default-drop input chain with no
management source is not a hardening measure, it is an outage, and the generator
refuses rather than emitting it — the same stance the firewall generator takes.
"""

from __future__ import annotations

import pytest

from btht.app.generate.emit_router import (
    DROP_IN_PATH,
    RefusedToGenerate,
    RouterPolicy,
    checklist,
    control_plane_nft,
    sshd_drop_in,
)


def a_router(**overrides: object) -> RouterPolicy:
    base: dict[str, object] = {
        "name": "r1",
        "mgmt_sources": ("10.20.0.0/24",),
        "peers": ("10.1.1.2",),
        "ospf": True,
    }
    base.update(overrides)
    return RouterPolicy(**base)  # type: ignore[arg-type]


# --- the guarantee ----------------------------------------------------------


def test_it_never_filters_transit_traffic() -> None:
    """The whole proposition: protect the box, do not touch what it forwards.

    Asserted against the generated text rather than trusted, because "it only hooks
    input" is exactly the kind of claim that survives a refactor in a comment while
    ceasing to be true in the code.
    """
    for policy in (
        a_router(),
        a_router(bgp=True),
        a_router(peers=(), ospf=False, bgp=False),
        a_router(mgmt_sources=("10.20.0.0/24", "fd00:20::/64"), peers=("10.1.1.2", "fd00:1::2")),
        a_router(extra_services=(("snmp from the NMS", 161),)),
    ):
        ruleset = control_plane_nft(policy)
        assert "hook forward" not in ruleset
        assert "hook output" not in ruleset
        assert "chain forward" not in ruleset
        assert "chain output" not in ruleset
        assert ruleset.count("hook input") == 1, "exactly one base chain, and it is input"


def test_it_says_in_the_file_that_throughput_is_untouched() -> None:
    """The operator applying this at 0300 needs to know that from the file itself."""
    assert "throughput is unaffected" in control_plane_nft(a_router())


# --- refusing to lock anybody out -------------------------------------------


def test_it_refuses_to_generate_without_a_management_source() -> None:
    with pytest.raises(RefusedToGenerate, match="lockout"):
        control_plane_nft(a_router(mgmt_sources=()))


def test_established_sessions_and_loopback_survive() -> None:
    ruleset = control_plane_nft(a_router())
    assert "ct state established,related accept" in ruleset
    assert "iif lo accept" in ruleset


def test_icmp_and_icmpv6_are_permitted() -> None:
    """Dropping ICMPv6 kills OSPFv3 adjacency, and dropping ICMP breaks path MTU."""
    ruleset = control_plane_nft(a_router())
    assert "ip6 nexthdr icmpv6 accept" in ruleset
    assert "icmp type" in ruleset


def test_the_checklist_makes_you_prove_access_in_a_new_session() -> None:
    """An open session survives on conntrack whether or not the rule is right."""
    assert "*new* session" in checklist(a_router())
    assert "proves nothing on its own" in checklist(a_router())


# --- what it permits --------------------------------------------------------


def test_management_reaches_ssh_and_nothing_else_does() -> None:
    ruleset = control_plane_nft(a_router())
    assert "ip saddr { 10.20.0.0/24 } tcp dport 22 accept" in ruleset
    assert "policy drop" in ruleset


def test_only_declared_neighbours_may_form_an_adjacency() -> None:
    """`H-FRR-06` — a neighbour you did not name is a neighbour somebody else chose."""
    ruleset = control_plane_nft(a_router(peers=("10.1.1.2",), ospf=True, bgp=True))
    assert "ip saddr { 10.1.1.2 } ip protocol ospf accept" in ruleset
    assert "ip saddr { 10.1.1.2 } tcp dport 179 accept" in ruleset


def test_no_declared_neighbour_means_no_adjacency_is_permitted() -> None:
    """Said out loud in the file, because a silent absence reads as an accident."""
    ruleset = control_plane_nft(a_router(peers=()))
    assert "no adjacency is permitted to form" in ruleset


def test_a_v4_only_management_source_says_so_about_ipv6() -> None:
    """The IPv4-only habit is exactly what EVIDENCE.md E2 is about."""
    assert "IPv6 SSH is not permitted" in control_plane_nft(a_router())


def test_both_families_are_emitted_when_both_are_declared() -> None:
    ruleset = control_plane_nft(
        a_router(mgmt_sources=("10.20.0.0/24", "fd00:20::/64"), peers=("10.1.1.2", "fd00:1::2"))
    )
    assert "ip6 saddr { fd00:20::/64 } tcp dport 22 accept" in ruleset
    assert "ip6 saddr { fd00:1::2 } meta l4proto 89 accept" in ruleset


def test_the_drop_log_is_rate_limited() -> None:
    """An unlimited log line here fills the disk of the box you were protecting."""
    assert "limit rate 5/minute log" in control_plane_nft(a_router())


# --- sshd -------------------------------------------------------------------


def test_the_sshd_output_is_a_drop_in_not_an_edit() -> None:
    """A rewritten sshd_config is indistinguishable from somebody else's rewrite."""
    text = sshd_drop_in(a_router())
    assert DROP_IN_PATH in text
    assert "sshd_config.d" in DROP_IN_PATH


def test_it_warns_that_a_drop_in_below_the_include_does_nothing() -> None:
    """sshd takes the first value it obtains, so placement decides whether this works."""
    assert "FIRST value it obtains" in sshd_drop_in(a_router())


def test_the_anti_pivot_settings_are_all_present() -> None:
    """`HARDENING.md` §5 — these matter far more on a router than on a general host."""
    text = sshd_drop_in(a_router())
    for setting in (
        "PermitTunnel no",
        "AllowTcpForwarding no",
        "AllowAgentForwarding no",
        "PermitRootLogin no",
        "PasswordAuthentication no",
        "KbdInteractiveAuthentication no",
    ):
        assert setting in text


def test_verbose_logging_is_set_because_it_names_the_key() -> None:
    """`H-SSH-19` is what makes session correlation able to say which key was used."""
    text = sshd_drop_in(a_router())
    assert "LogLevel VERBOSE" in text
    assert "key fingerprint" in text


def test_an_allow_list_is_emitted_when_groups_are_declared() -> None:
    text = sshd_drop_in(a_router(allow_groups=("wheel", "netops")))
    assert "AllowGroups wheel netops" in text


def test_every_setting_carries_the_reason_for_it() -> None:
    """The operator is deciding whether to accept an outage; a keyword alone will not do."""
    text = sshd_drop_in(a_router())
    assert text.count("# H-SSH-") >= 10


def test_the_checklist_says_what_this_does_not_cover() -> None:
    """`H-FRR-04` and `H-FRR-05` are the two that actually stop a pivot."""
    text = checklist(a_router())
    assert "H-FRR-04" in text and "H-FRR-05" in text
    assert "does not replace them" in text


def test_output_is_deterministic() -> None:
    assert control_plane_nft(a_router()) == control_plane_nft(a_router())
    assert sshd_drop_in(a_router()) == sshd_drop_in(a_router())
