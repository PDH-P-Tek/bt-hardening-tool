"""Knowing what to do next.

The tool spans three days of work in a fixed order — declare the range from the
documents, generate and check a ruleset, then watch the estate — and nobody sitting
down in front of it for the first time can infer that from a navigation bar. Worse, the
order is load-bearing: declaring policy before the hosts exist writes rules against
segments with nothing on them, and taking a baseline before hardening throws away the
only clean record of what Green Team shipped.

Each step reports itself done from the estate's own state. There is no stored progress
to get out of step with reality, and no wizard to be trapped halfway through — which
also means these tests can drive it purely by building estates.
"""

from __future__ import annotations

from ipaddress import IPv4Address, IPv4Interface

from btht.app.model.estate import Estate, Firewall, Host, Interface, Node, Platform
from btht.app.model.policy import FirewallPolicy, Policy
from btht.app.web.guide import Step, next_step, plan


def a_firewall(
    *, interfaces: tuple[Interface, ...] = (), hosts: tuple[Host, ...] = ()
) -> Firewall:
    return Firewall(
        enclave="do",
        fqdn="do.example",
        node=Node(name="do", platform=Platform.PFSENSE, mgmt_address=IPv4Address("10.0.0.1")),
        interfaces=interfaces,
        hosts=hosts,
    )


WAN = Interface(ifname="wan", role="wan", v4=IPv4Interface("10.0.0.1/24"))
SVRS = Interface(ifname="opt1", role="svrs", v4=IPv4Interface("192.0.2.1/24"))
DC = Host(hostname="dc01", v4=IPv4Address("192.0.2.5"), segment_role="svrs")


def step(steps: tuple[Step, ...], key: str) -> Step:
    return next(s for s in steps if s.key == key)


def test_an_empty_install_is_told_to_declare_the_range() -> None:
    assert next_step(plan(None)).key == "range"


def test_a_declared_range_with_no_enclaves_asks_for_one() -> None:
    assert next_step(plan(Estate(team=42))).key == "enclaves"


def test_a_firewall_with_no_internal_segments_asks_for_interfaces() -> None:
    """A WAN-only firewall has nothing behind it to protect yet."""
    estate = Estate(team=42, firewalls=(a_firewall(interfaces=(WAN,)),))
    nxt = next_step(plan(estate))
    assert nxt.key == "interfaces"
    assert "enclave=do" in nxt.href, "and it says which enclave"


def test_segments_with_nothing_on_them_ask_for_machines() -> None:
    """Rules are written against what is on a segment, not against the subnet."""
    estate = Estate(team=42, firewalls=(a_firewall(interfaces=(WAN, SVRS)),))
    assert next_step(plan(estate)).key == "hosts"


def test_machines_but_no_policy_asks_for_policy() -> None:
    estate = Estate(team=42, firewalls=(a_firewall(interfaces=(WAN, SVRS), hosts=(DC,)),))
    nxt = next_step(plan(estate))
    assert nxt.key == "policy"
    assert nxt.href == "/range/policy/do"


def test_policy_but_nothing_signed_off_asks_for_a_read() -> None:
    """Nothing exports until a person has read the rules and said they are right."""
    estate = Estate(team=42, firewalls=(a_firewall(interfaces=(WAN, SVRS), hosts=(DC,)),))
    policy = Policy(firewalls=(FirewallPolicy(enclave="do"),))
    nxt = next_step(plan(estate, policy))
    assert nxt.key == "review"
    assert nxt.href == "/rules/do"


def test_signed_off_rules_lead_to_taking_a_baseline() -> None:
    estate = Estate(team=42, firewalls=(a_firewall(interfaces=(WAN, SVRS), hosts=(DC,)),))
    policy = Policy(firewalls=(FirewallPolicy(enclave="do"),))
    nxt = next_step(plan(estate, policy, reviewed=frozenset({"do"})))
    assert nxt.key == "baseline"
    assert "before you harden" in nxt.why


def test_a_fully_set_up_estate_settles_on_watching() -> None:
    """Watching is the steady state, not a task — it never reports itself done."""
    estate = Estate(team=42, firewalls=(a_firewall(interfaces=(WAN, SVRS), hosts=(DC,)),))
    policy = Policy(firewalls=(FirewallPolicy(enclave="do"),))
    steps = plan(estate, policy, reviewed=frozenset({"do"}), baselined=frozenset({"do"}))
    assert next_step(steps).key == "watch"
    assert step(steps, "watch").done is False


def test_every_step_says_why_it_matters_not_just_what_it_is() -> None:
    """The reason is what stops someone skipping a step that looks like paperwork."""
    for entry in plan(Estate(team=42)):
        assert entry.why and entry.action and entry.href


def test_a_broken_estate_never_takes_the_page_down() -> None:
    """This decorates every page, so it degrades to 'you are near the start'."""
    assert next_step(plan(None)).key == "range"
