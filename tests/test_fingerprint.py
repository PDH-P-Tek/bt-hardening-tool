"""Phase 1.3 — normalisation and the two-tier fingerprint. The gate on Phase 2.

`SPEC.md` §11 forbids building UI before these pass, and the reason is specific: a
brittle fingerprint fires the triage modal on everything, people learn to click
through it, and the classification silently stops meaning anything. That failure is
invisible through a UI — it looks like the tool working.

So the invariants are asserted as properties over generated input rather than over a
handful of examples that happen to hold.
"""

from __future__ import annotations

import os
import subprocess
import sys
from ipaddress import ip_address, ip_network

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from btht.app.ingest.fingerprint import canonical_json, strict_fingerprint, structural_fingerprint
from btht.app.ingest.normalise import (
    ALL_INTERFACES,
    Template,
    canonical_address,
    canonical_rule,
)
from btht.app.model.rules import (
    Action,
    Alias,
    AliasRef,
    AliasType,
    AnyEndpoint,
    Family,
    HostAddress,
    Network,
    PortSpec,
    Rule,
)

pytestmark = pytest.mark.property


def rule(**kwargs: object) -> Rule:
    base: dict[str, object] = {"action": Action.PASS, "interfaces": ("wan",)}
    base.update(kwargs)
    return Rule(**base)  # type: ignore[arg-type]


# --- the §6.1 equivalences -------------------------------------------------


@pytest.mark.parametrize("spelling", ["0.0.0.0/0", "::/0"])
def test_any_and_the_all_networks_spellings_are_the_same_rule(spelling: str) -> None:
    """A firewall treats these identically, so the tool must too."""
    explicit = rule(source=Network(ip_network(spelling)))
    implicit = rule(source=AnyEndpoint())
    assert strict_fingerprint(explicit) == strict_fingerprint(implicit)


def test_a_single_port_and_its_degenerate_range_are_the_same_port() -> None:
    assert strict_fingerprint(rule(destination_ports=(PortSpec(53, 53),))) == strict_fingerprint(
        rule(destination_ports=(PortSpec(53, 53),))
    )
    single = rule(destination_ports=(PortSpec(53, 53),))
    ranged = rule(destination_ports=(PortSpec(53, 53), PortSpec(53, 53)))
    assert strict_fingerprint(single) == strict_fingerprint(ranged), "repetition is not information"


def test_the_dual_stack_family_expands_to_both() -> None:
    """`inet46` is the `{inet, inet6}` pair — `SPEC.md` §6.1."""
    from btht.app.ingest.normalise import canonical_families

    assert canonical_families(Family.INET46) == ["inet", "inet6"]
    assert canonical_families(Family.INET) == ["inet"]
    assert strict_fingerprint(rule(family=Family.INET46)) != strict_fingerprint(
        rule(family=Family.INET)
    )


@given(st.lists(st.integers(min_value=1, max_value=65535), min_size=1, max_size=8, unique=True))
@settings(max_examples=50)
def test_port_order_and_repetition_never_change_the_fingerprint(ports: list[int]) -> None:
    forward = tuple(PortSpec(p, p) for p in ports)
    backward = tuple(reversed(forward))
    doubled = forward + forward
    assert (
        strict_fingerprint(rule(destination_ports=forward))
        == strict_fingerprint(rule(destination_ports=backward))
        == strict_fingerprint(rule(destination_ports=doubled))
    )


@given(st.lists(st.sampled_from(["wan", "lan", "opt1", "opt2", "opt3"]), min_size=1, max_size=5))
@settings(max_examples=50)
def test_interface_order_and_repetition_never_change_the_fingerprint(names: list[str]) -> None:
    """A floating rule names several interfaces and the file's order is arbitrary."""
    assert strict_fingerprint(rule(interfaces=tuple(names))) == strict_fingerprint(
        rule(interfaces=tuple(reversed(names)) + tuple(names))
    )


@given(
    st.lists(
        st.integers(min_value=1, max_value=254).map(lambda n: f"192.0.2.{n}"),
        min_size=1,
        max_size=6,
        unique=True,
    )
)
@settings(max_examples=50)
def test_alias_entry_order_and_repetition_never_change_the_fingerprint(entries: list[str]) -> None:
    """`SPEC.md` §6.1 — address lists are sorted and deduplicated before hashing."""
    forward = Alias(name="A", type=AliasType.HOST, entries=tuple(entries))
    shuffled = Alias(name="A", type=AliasType.HOST, entries=tuple(reversed(entries)) * 2)
    ref = rule(source=AliasRef("A"))
    assert strict_fingerprint(ref, {"A": forward}) == strict_fingerprint(ref, {"A": shuffled})


@pytest.mark.parametrize(
    ("written", "equivalent"),
    [
        ("FD81:25:42::1", "fd81:25:42:0:0:0:0:1"),
        ("FD81:0025:0042::0001", "fd81:25:42::1"),
        ("2001:DB8::", "2001:db8:0:0:0:0:0:0"),
    ],
)
def test_ipv6_spelling_never_changes_the_fingerprint(written: str, equivalent: str) -> None:
    """Lowercase, RFC 5952. The same address written two ways is one address."""
    assert canonical_address(written) == canonical_address(equivalent)
    assert strict_fingerprint(rule(source=HostAddress(ip_address(written)))) == strict_fingerprint(
        rule(source=HostAddress(ip_address(equivalent)))
    )


# --- descriptions are never identity ---------------------------------------


@given(st.text(max_size=60), st.text(max_size=20))
@settings(max_examples=50)
def test_labels_never_affect_identity(descr: str, tracker: str) -> None:
    """`SPEC.md` §12.6 and `EVIDENCE.md` E3.

    Three rules in the observed estate said BLOCK and did `pass`. A tool that let the
    label into the fingerprint would have agreed with them.
    """
    assert strict_fingerprint(rule(descr=descr, tracker=tracker, log=True)) == strict_fingerprint(
        rule(descr="", tracker=None, log=False)
    )


def test_action_is_identity() -> None:
    """The converse: what a rule *does* is exactly what identity is made of."""
    assert strict_fingerprint(rule(action=Action.PASS)) != strict_fingerprint(
        rule(action=Action.BLOCK)
    )


# --- the two tiers ---------------------------------------------------------


def test_a_widened_alias_fails_strict_and_matches_structurally() -> None:
    """`EVIDENCE.md` E7, the case both tiers exist for.

    A baseline rule whose source was widened while keeping its description. Strict
    must reject it — it is not the rule any more. Structural must recognise it, so
    triage can say *what* changed rather than presenting an unfamiliar rule.
    """
    expected = Alias(name="Remote_Access", type=AliasType.NETWORK, entries=("198.19.14.0/24",))
    widened = Alias(name="Remote_Access", type=AliasType.NETWORK, entries=("198.19.0.0/16",))
    ref = rule(source=AliasRef("Remote_Access"), descr="VPN access for exercise participants")

    assert strict_fingerprint(ref, {"Remote_Access": expected}) != strict_fingerprint(
        ref, {"Remote_Access": widened}
    )
    assert structural_fingerprint(ref, {"Remote_Access": expected}) == structural_fingerprint(
        ref, {"Remote_Access": widened}
    )


def test_structural_still_separates_genuinely_different_shapes() -> None:
    """The looser tier must not collapse everything, or it recognises nothing."""
    from_alias = rule(source=AliasRef("A"))
    from_any = rule(source=AnyEndpoint())
    assert structural_fingerprint(from_alias) != structural_fingerprint(from_any)


# --- team templating -------------------------------------------------------


def test_the_team_number_templates_so_one_profile_matches_every_team() -> None:
    """A shipped profile reads `25.{X}.0.1`; a real config reads `25.14.0.1`."""
    template = Template(number=14, padded="14")
    for_team_14 = rule(source=Network(ip_network("25.14.0.0/24")))
    assert "{X}" in canonical_json(canonical_rule(for_team_14, {}, template))


def test_templating_matches_whole_tokens_only() -> None:
    """Team 4 must not template the 4 inside 143 or inside fd81."""
    template = Template(number=4, padded="04")
    assert template.apply("192.0.143.4") == "192.0.143.{X}"
    assert template.apply("fd81:4::1") == "fd81:{X}::1"
    assert "{X}" not in template.apply("192.0.143.40")


def test_no_template_declared_changes_nothing() -> None:
    assert Template().apply("25.14.0.1") == "25.14.0.1"


# --- determinism -----------------------------------------------------------


def test_fingerprints_are_stable_across_processes_and_hash_seeds() -> None:
    """`SPEC.md` §12.9 — byte-identical across runs *and processes*.

    Python randomises string hashing per process, so anything that leaked dict or set
    iteration order into the digest would pass in one process and fail in the next.
    Running it twice in-process would never catch that.
    """
    script = (
        "from ipaddress import ip_network;"
        "from btht.app.ingest.fingerprint import strict_fingerprint;"
        "from btht.app.model.rules import Action, Network, PortSpec, Rule;"
        "r = Rule(action=Action.PASS, interfaces=('opt2','wan','lan'),"
        " source=Network(ip_network('192.0.2.0/24')),"
        " destination_ports=(PortSpec(443,443), PortSpec(53,53)));"
        "print(strict_fingerprint(r))"
    )
    digests = set()
    for seed in ("0", "1", "12345"):
        env = dict(os.environ, PYTHONHASHSEED=seed)
        result = subprocess.run(
            [sys.executable, "-c", script], capture_output=True, text=True, env=env, check=True
        )
        digests.add(result.stdout.strip())
    assert len(digests) == 1, f"fingerprint varies by process: {digests}"


# --- against the real fixtures ---------------------------------------------
#
# The properties above are necessary and were not sufficient. Both defects below
# survived them and only appeared when the same protected rule was fingerprinted
# on three different enclaves.


def _enclave(name: str):  # type: ignore[no-untyped-def]
    """Parse, derive roles, and remap — the order the pipeline must use."""
    from pathlib import Path

    from btht.app.ingest.normalise import alias_table
    from btht.app.ingest.pfsense import parse_file
    from btht.app.ingest.roles import RoleConvention, apply_roles, derive_interfaces

    declared = RoleConvention(
        vocabulary=("wan", "ws", "svrs", "dmz", "uav", "port1", "port2", "stbd1", "stbd2"),
        enclave_tokens=("bt_wan_", "hn_wan_", "dsoc_", "do_", "ds_", "mcu_"),
    )
    base = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "baseline"
    parsed = parse_file(base / f"{name}-baseline.xml")
    interfaces = derive_interfaces(parsed.interfaces, declared)
    mapping = {i.ifname: i.role for i in interfaces}
    return (
        apply_roles(parsed.rules, mapping),
        alias_table(parsed.aliases),
        frozenset(i.role for i in interfaces),
    )


def test_one_protected_rule_fingerprints_identically_across_every_enclave() -> None:
    """The whole point of a shipped profile.

    The same Green Team floating rule appears on every enclave. The enclaves have
    three, four and six interfaces, and one of them inverts LAN. If those produce
    three different fingerprints, the profile matches on at most one of them and the
    operator triages the identical baseline by hand on every firewall.
    """
    template = Template(number=42, padded="42")
    digests = set()
    for name in ("do", "dsoc", "mcu"):
        rules, aliases, all_roles = _enclave(name)
        dns = next(r for r in rules if r.floating and r.protocol == "tcp/udp")
        digests.add(strict_fingerprint(dns, aliases, template, all_roles))
    assert len(digests) == 1, "the same shipped rule must be one identity everywhere"


def test_rules_are_fingerprinted_on_roles_not_ifnames() -> None:
    """`BASELINE-ANALYSIS.md` F2, as an identity bug rather than a config one.

    The permissive default on the inverted enclave's `lan` is a rule over *servers*.
    On a conventional enclave the `lan` rule is over *workstations*. Fingerprinting
    the raw ifname makes those one identity, which would let a profile classify one
    as the other — the specific mistake that makes applying the wrong ruleset
    destructive.
    """
    from dataclasses import replace

    inverted_rules, inverted_aliases, _ = _enclave("dsoc")
    normal_rules, normal_aliases, _ = _enclave("do")

    inverted_lan = next(r for r in inverted_rules if r.interfaces == ("svrs",))
    normal_lan = next(r for r in normal_rules if r.interfaces == ("ws",))

    assert strict_fingerprint(inverted_lan, inverted_aliases) != strict_fingerprint(
        normal_lan, normal_aliases
    ), "different segments must be different identities"

    # And the trap itself: had the remap not happened, both would read `lan`.
    as_ifnames_a = replace(inverted_lan, interfaces=("lan",))
    as_ifnames_b = replace(normal_lan, interfaces=("lan",))
    assert strict_fingerprint(as_ifnames_a, inverted_aliases) == strict_fingerprint(
        as_ifnames_b, normal_aliases
    ), "this is what the tool would have concluded without the role layer"


def test_all_interfaces_collapses_but_a_subset_does_not() -> None:
    every = frozenset({"wan", "ws", "svrs"})
    on_all = rule(interfaces=("ws", "wan", "svrs"))
    on_some = rule(interfaces=("ws", "wan"))

    assert canonical_rule(on_all, {}, Template(), all_roles=every)["interfaces"] == [ALL_INTERFACES]
    assert canonical_rule(on_some, {}, Template(), all_roles=every)["interfaces"] == ["wan", "ws"]
    assert strict_fingerprint(on_all, all_roles=every) != strict_fingerprint(
        on_some, all_roles=every
    )
