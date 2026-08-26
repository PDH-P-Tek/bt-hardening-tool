"""Phase 4.2 and 4.3 — the validator catalogue.

Every ID gets two assertions, per `SPEC.md` §8: it **fires on its case**, and it
**stays silent on a clean baseline**. Both halves matter. A validator that never fires
was never a control, and one that fires on everything gets turned off by lunchtime —
at which point the ones that mattered go with it.

The IDs carrying an evidence reference are not hypothetical. They are things a real
team shipped, under time pressure, while believing the opposite.
"""

from __future__ import annotations

from dataclasses import replace

from conftest import ESSENTIAL, a_firewall, a_policy

from btht.app.generate.order import generate
from btht.app.ingest.classify import RuleMatch, Tier
from btht.app.ingest.isa import Catalogue, load_catalogue
from btht.app.model.policy import EgressPolicy, FirewallPolicy, Selector, ServiceRule
from btht.app.model.rules import (
    Action,
    Alias,
    AliasType,
    Rule,
)
from btht.app.validate.rules import (
    REGISTRY,
    Context,
    Severity,
    blocking,
    run_all,
)

CATALOGUE = load_catalogue(None)


def clean_context(**overrides: object) -> Context:
    """A ruleset with nothing wrong with it. Every validator must be quiet here."""
    firewall = a_firewall()
    ruleset = generate(
        firewall,
        a_policy(),
        CATALOGUE,
        scoring_source=Selector(alias="Scoring_Sources"),
        essential=ESSENTIAL,
    )
    base: dict[str, object] = {
        "firewall": firewall,
        "ruleset": ruleset,
        "policy": a_policy(),
        "catalogue": CATALOGUE,
    }
    base.update(overrides)
    return Context(**base)  # type: ignore[arg-type]


def fired(context: Context, check_id: str) -> list[str]:
    _severity, function = REGISTRY[check_id]
    return [f.message for f in function(context)]


# --- the silence half, for every ID at once --------------------------------


def test_the_whole_catalogue_is_silent_on_a_clean_baseline() -> None:
    """The half that gets forgotten. Noise is how a control stops being one."""
    findings = run_all(clean_context())
    noisy = [f"{f.id}: {f.message}" for f in findings]
    assert noisy == [], "validators fired on a clean ruleset"


def test_every_registered_id_has_a_severity() -> None:
    assert len(REGISTRY) == 31, "the catalogue in SPEC.md §8 has 31 IDs"
    for check_id, (severity, _fn) in REGISTRY.items():
        assert isinstance(severity, Severity), check_id


# --- blocking --------------------------------------------------------------


def test_unknown_unresolved_fires_on_an_unclassified_item() -> None:
    match = RuleMatch(rule=Rule(action=Action.PASS, descr="something new"), tier=Tier.NONE)
    assert fired(clean_context(matches=(match,)), "V-UNKNOWN-UNRESOLVED")


def test_lockout_drop_fires_and_typed_confirmation_clears_it() -> None:
    """Not a checkbox. Losing this means losing your own firewall."""
    context = clean_context(dropped_lockout_critical=("Remote_Access",))
    assert fired(context, "V-LOCKOUT-DROP")
    confirmed = replace(context, typed_confirmations=frozenset({"Remote_Access"}))
    assert not fired(confirmed, "V-LOCKOUT-DROP")


def test_alias_missing_fires_when_a_rule_points_at_nothing() -> None:
    policy = a_policy()
    entry = FirewallPolicy(
        enclave="alpha",
        services=(
            ServiceRule(
                name="Kibana",
                segment="servers",
                alias="Never_Declared",
                protocol="tcp",
                ports=(5601,),
                source=Selector(any=True),
            ),
        ),
        egress=EgressPolicy(default="deny_and_log"),
    )
    ruleset = generate(
        a_firewall(),
        replace(policy, firewalls=(entry,)),
        CATALOGUE,
        essential=ESSENTIAL,
    )
    assert fired(clean_context(ruleset=ruleset), "V-ALIAS-MISSING")


def test_alias_orphan_drop_fires_when_a_used_alias_is_removed() -> None:
    baseline = (Alias(name="Mgmt_Sources", type=AliasType.NETWORK, entries=("192.0.2.0/24",)),)
    assert fired(clean_context(baseline_aliases=baseline, output_aliases=()), "V-ALIAS-ORPHAN-DROP")


def test_mgmt_absent_fires_when_a_segment_has_no_way_in() -> None:
    context = clean_context()
    stripped = replace(
        context.ruleset,
        floating=tuple(g for g in context.ruleset.floating if g.block != "MGMT ACCESS"),
    )
    assert fired(replace(context, ruleset=stripped), "V-MGMT-ABSENT")


def test_deny_without_essential_fires() -> None:
    """`EVIDENCE.md` E6 — the team who added the deny and lost DNS silently."""
    context = clean_context()
    stripped = replace(
        context.ruleset,
        floating=tuple(g for g in context.ruleset.floating if g.block != "ESSENTIAL SERVICES"),
    )
    assert fired(replace(context, ruleset=stripped), "V-DENY-WITHOUT-ESSENTIAL")


def test_identity_mismatch_refuses_a_ruleset_meant_for_another_firewall() -> None:
    assert fired(clean_context(target_identity="somewhere-else"), "V-IF-MISMATCH")


def test_config_version_fires_on_an_unexpected_format() -> None:
    assert fired(clean_context(config_version="21.7"), "V-CONFIG-VERSION")


def test_permissive_retained_fires_on_a_catch_all() -> None:
    """`EVIDENCE.md` E1 — six of six enclaves finished with one of these live."""
    context = clean_context()
    from btht.app.generate.order import GeneratedRule

    catch_all = GeneratedRule(
        rule=Rule(action=Action.PASS, interfaces=("users",), descr="temporary, honestly"),
        block="POLICY",
        intent="a catch-all somebody added",
    )
    widened = replace(context.ruleset, floating=(*context.ruleset.floating, catch_all))
    assert fired(replace(context, ruleset=widened), "V-PERMISSIVE-RETAINED")


def test_dualstack_asymmetry_fires_on_a_narrowed_rule() -> None:
    """`EVIDENCE.md` E2 — 74 of these across the estate, all bypassed on IPv6."""
    context = clean_context()
    narrowed = replace(
        context.ruleset,
        warnings=("1 rule(s) emitted inet only, because the address 192.0.2.1 is IPv4.",),
    )
    assert fired(replace(context, ruleset=narrowed), "V-DUALSTACK-ASYMMETRY")


def test_nat_mode_changed_fires() -> None:
    assert fired(clean_context(nat_mode="hybrid"), "V-NAT-MODE-CHANGED")


def test_scoring_absent_fires_only_when_a_catalogue_says_there_is_scoring() -> None:
    """`EVIDENCE.md` E9. With no catalogue there is nothing to be absent."""
    from pathlib import Path

    loaded = load_catalogue(Path(__file__).resolve().parents[1] / "isa-checks.yaml")
    bare = replace(a_firewall(), hosts=())
    ruleset = generate(
        bare, a_policy(), loaded, scoring_source=Selector(alias="S"), essential=ESSENTIAL
    )
    assert fired(
        clean_context(firewall=bare, ruleset=ruleset, catalogue=loaded), "V-SCORING-ABSENT"
    )
    assert not fired(clean_context(ruleset=ruleset), "V-SCORING-ABSENT")


def test_egress_check_fires_when_a_deny_would_fail_an_outbound_check(
    catalogue: Catalogue,
) -> None:
    """`EVIDENCE.md` E6 and F9 — two enclaves shipped exactly this."""
    outbound = next(c.name for c in catalogue.checks.values() if not c.satisfiable_by_ingress)
    firewall = a_firewall()
    hosts = tuple(
        replace(h, isa_checks=(outbound,)) if h.hostname == "dc01" else h for h in firewall.hosts
    )
    context = clean_context(firewall=replace(firewall, hosts=hosts), catalogue=catalogue)
    assert fired(context, "V-EGRESS-CHECK")


def test_out_of_bounds_blocked_fires_when_the_protected_host_has_no_pass() -> None:
    """`BASELINE-ANALYSIS.md` F8 — inside the segment, on no diagram."""
    context = clean_context()
    stripped = replace(
        context.ruleset,
        floating=tuple(g for g in context.ruleset.floating if g.block != "OUT OF BOUNDS"),
    )
    assert fired(replace(context, ruleset=stripped), "V-OOB-BLOCKED")


# --- warnings --------------------------------------------------------------


def test_alias_family_fires_on_the_shipped_ipv6_defect() -> None:
    """`BASELINE-ANALYSIS.md` F1 — the alias lists another estate's v6 prefix."""
    from ipaddress import IPv6Interface

    from btht.app.model.estate import Interface

    firewall = a_firewall()
    with_v6 = replace(
        firewall,
        interfaces=(
            *firewall.interfaces,
            Interface(ifname="opt9", role="extra", v6=IPv6Interface("fd81:25:42::1/64")),
        ),
    )
    wrong = (Alias(name="Routers", type=AliasType.HOST, entries=("fd81:10:42::1",)),)
    assert fired(clean_context(firewall=with_v6, baseline_aliases=wrong), "V-ALIAS-FAMILY")


def test_routing_peers_fires_when_a_peer_is_in_no_alias() -> None:
    assert fired(clean_context(frr_peers=("198.51.100.9",)), "V-ROUTING-PEERS")


def test_shadow_floating_fires_when_a_preserved_pass_falls_below_a_quick_block() -> None:
    """`BASELINE-ANALYSIS.md` F3 — the trap that kills DNS silently."""
    from btht.app.generate.order import GeneratedRule

    context = clean_context()
    preserved = GeneratedRule(
        rule=Rule(action=Action.PASS, interfaces=("wan",), descr="baseline DNS"),
        block="PRESERVED",
        intent="preserved",
        preserved=True,
    )
    shadowed = replace(context.ruleset, floating=(*context.ruleset.floating, preserved))
    assert fired(replace(context, ruleset=shadowed), "V-SHADOW-FLOATING")


def test_shadowed_rule_fires_on_an_unreachable_rule() -> None:
    """`EVIDENCE.md` E8."""
    from btht.app.generate.order import GeneratedRule

    context = clean_context()
    role, rules = context.ruleset.per_interface[0]
    extra = GeneratedRule(
        rule=Rule(action=Action.PASS, interfaces=(role,), quick=True, descr="added later"),
        block="POLICY",
        intent="added after the deny",
    )
    reordered = replace(context.ruleset, per_interface=((role, (*rules, extra)),))
    assert fired(replace(context, ruleset=reordered), "V-SHADOWED-RULE")


def test_label_action_mismatch_fires_both_ways() -> None:
    """`EVIDENCE.md` E3 — three rules said BLOCK and did pass."""
    liar = Rule(action=Action.PASS, descr="BLOCK inbound from greynet")
    assert fired(clean_context(baseline_rules=(liar,)), "V-LABEL-ACTION-MISMATCH")
    other = Rule(action=Action.BLOCK, descr="allow analyst access")
    assert fired(clean_context(baseline_rules=(other,)), "V-LABEL-ACTION-MISMATCH")


def test_alias_name_hygiene_fires_on_a_temporary_name() -> None:
    """`EVIDENCE.md` E4 — an alias named `Temp` still exposing a database at the end."""
    temp = (Alias(name="Temp", type=AliasType.PORT, entries=("3306",)),)
    assert fired(clean_context(output_aliases=temp), "V-ALIAS-NAME-HYGIENE")


def test_overbroad_scoring_source_fires(catalogue: Catalogue) -> None:
    """`EVIDENCE.md` E10 — sourcing from any opens the scored port to everyone."""
    firewall = a_firewall()
    ruleset = generate(
        firewall,
        a_policy(),
        catalogue,
        scoring_source=Selector(any=True),
        essential=ESSENTIAL,
    )
    assert fired(clean_context(ruleset=ruleset, catalogue=catalogue), "V-OVERBROAD-SCORING-SOURCE")


def test_icmp6_minimum_fires_when_the_set_is_narrowed() -> None:
    """`BASELINE-ANALYSIS.md` F5 — IPv6 then fails slowly and looks like something else."""
    from btht.app.model.policy import Options

    policy = replace(a_policy(), options=Options(icmp6_minimum=(128,)))
    ruleset = generate(a_firewall(), policy, CATALOGUE, essential=ESSENTIAL)
    assert fired(clean_context(ruleset=ruleset, policy=policy), "V-ICMP6-MINIMUM")


def test_unverified_service_fires_on_a_service_with_no_ports() -> None:
    entry = FirewallPolicy(
        enclave="alpha",
        services=(ServiceRule(name="modgpt", segment="servers", source=Selector(any=True)),),
    )
    assert fired(
        clean_context(policy=replace(a_policy(), firewalls=(entry,))), "V-UNVERIFIED-SERVICE"
    )


def test_antilockout_disabled_fires_and_says_what_to_do_first() -> None:
    messages = fired(clean_context(antilockout_enabled=False), "V-ANTILOCKOUT-DISABLED")
    assert messages
    assert "second session" in messages[0]


def test_annex_config_mismatch_fires() -> None:
    assert fired(
        clean_context(annex_subnets=(("Storage", "10.10.10.0/24"),)),
        "V-ANNEX-CONFIG-MISMATCH",
    )


def test_scoring_uncovered_fires_when_a_scored_host_has_no_rule(
    catalogue: Catalogue,
) -> None:
    firewall = a_firewall()
    hosts = tuple(replace(h, v4=None, v6=None) for h in firewall.hosts)
    stripped = replace(firewall, hosts=hosts)
    ruleset = generate(
        stripped, a_policy(), catalogue, scoring_source=Selector(alias="S"), essential=ESSENTIAL
    )
    assert fired(
        clean_context(firewall=stripped, ruleset=ruleset, catalogue=catalogue),
        "V-SCORING-UNCOVERED",
    )


def test_cross_enclave_orphan_fires_on_one_sided_paths() -> None:
    from btht.app.model.policy import Dependency

    policy = replace(
        a_policy(),
        dependencies=(
            Dependency(name="Agents to Fleet", from_enclaves=("alpha",), to_enclave="beta"),
        ),
    )
    assert fired(clean_context(policy=policy), "V-CROSS-ENCLAVE-ORPHAN")


# --- info ------------------------------------------------------------------


def test_baseline_drift_reports_structural_matches() -> None:
    match = RuleMatch(rule=Rule(action=Action.PASS, descr="x"), tier=Tier.STRUCTURAL)
    assert fired(clean_context(matches=(match,)), "V-BASELINE-DRIFT")


def test_unexpected_host_reports_something_the_documents_do_not_mention() -> None:
    assert fired(clean_context(nmap_hosts=("192.0.3.77",)), "V-UNEXPECTED-HOST")


def test_scoring_unchecked_asks_rather_than_assumes(catalogue: Catalogue) -> None:
    firewall = a_firewall()
    hosts = tuple(replace(h, isa_checks=()) for h in firewall.hosts)
    assert fired(
        clean_context(firewall=replace(firewall, hosts=hosts), catalogue=catalogue),
        "V-SCORING-UNCHECKED",
    )


def test_no_separators_is_information_not_a_problem() -> None:
    assert fired(clean_context(separators_emitted=False), "V-NO-SEPARATORS")


# --- severity behaviour ----------------------------------------------------


def test_blocking_findings_are_separable_from_the_rest() -> None:
    findings = run_all(clean_context(config_version="21.7", nmap_hosts=("192.0.3.77",)))
    assert any(f.id == "V-CONFIG-VERSION" for f in blocking(findings))
    assert not any(f.id == "V-UNEXPECTED-HOST" for f in blocking(findings))


def test_findings_come_out_in_a_stable_order() -> None:
    context = clean_context(config_version="21.7", nat_mode="hybrid")
    assert [f.id for f in run_all(context)] == [f.id for f in run_all(context)]
