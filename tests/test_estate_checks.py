"""Phase 8.3 — estate-level checks.

The findings that only exist when the whole estate is looked at once. Each firewall's
own validators see nothing wrong in these cases, because from where they stand nothing
is — which is exactly why the tool models a team's estate rather than an enclave.
"""

from __future__ import annotations

from dataclasses import replace

from conftest import ESSENTIAL, a_firewall, a_policy

from btht.app.generate.order import Ruleset, generate
from btht.app.ingest.isa import load_catalogue
from btht.app.model.estate import Estate
from btht.app.model.policy import Dependency, Policy, Selector
from btht.app.validate.estate import run_estate_checks

CATALOGUE = load_catalogue(None)


def two_enclaves() -> Estate:
    alpha = a_firewall()
    beta = replace(a_firewall(), enclave="beta", fqdn="fw1.beta")
    return Estate(team=42, team_padded="42", firewalls=(alpha, beta))


def rulesets_for(policy: Policy) -> dict[str, Ruleset]:
    return {
        firewall.enclave: generate(
            firewall,
            policy,
            CATALOGUE,
            scoring_source=Selector(alias="Scoring_Sources"),
            essential=ESSENTIAL,
        )
        for firewall in two_enclaves().firewalls
    }


def test_a_declared_path_is_emitted_on_both_firewalls() -> None:
    """Declared once, generated twice. The source's egress and the destination's ingress."""
    policy = replace(
        a_policy(),
        dependencies=(
            Dependency(
                name="Agents to Fleet",
                from_enclaves=("alpha",),
                to_enclave="beta",
                protocol="tcp",
                ports=(8220,),
            ),
        ),
    )
    rulesets = rulesets_for(policy)
    for enclave in ("alpha", "beta"):
        assert any("Agents to Fleet" in g.intent for g in rulesets[enclave].all_rules()), (
            f"{enclave} has no rule for the declared path"
        )
    assert [
        f
        for f in run_estate_checks(two_enclaves(), policy, rulesets)
        if f.id == "V-CROSS-ENCLAVE-ORPHAN"
    ] == []


def test_a_path_with_only_one_end_is_reported() -> None:
    """The source shows traffic as permitted while the destination drops it.

    Neither firewall's own checks can see that, which is the whole point of this file.
    Simulated by generating the source's ruleset and not the destination's — which is
    what happens when someone regenerates one firewall and not the other.
    """
    policy = replace(
        a_policy(),
        dependencies=(
            Dependency(
                name="Agents to Fleet",
                from_enclaves=("alpha",),
                to_enclave="beta",
                protocol="tcp",
                ports=(8220,),
            ),
        ),
    )
    only_source = {"alpha": rulesets_for(policy)["alpha"]}
    findings = run_estate_checks(two_enclaves(), policy, only_source)
    assert any("Half a path is worse than none" in f.message for f in findings)


def test_a_dependency_pointing_at_an_enclave_with_no_ruleset_is_reported() -> None:
    policy = replace(
        a_policy(),
        dependencies=(Dependency(name="X", from_enclaves=("alpha",), to_enclave="nowhere"),),
    )
    findings = run_estate_checks(two_enclaves(), policy, rulesets_for(policy))
    assert any("Half a path is worse than none" in f.message for f in findings)


def test_no_dependencies_means_no_findings() -> None:
    policy = a_policy()
    findings = run_estate_checks(two_enclaves(), policy, rulesets_for(policy))
    assert [f for f in findings if f.id == "V-CROSS-ENCLAVE-ORPHAN"] == []


def test_an_enclave_with_hosts_and_no_checks_is_flagged_for_confirmation() -> None:
    from ipaddress import IPv4Address

    from btht.app.model.estate import Host

    firewall = replace(
        a_firewall(),
        hosts=(Host(hostname="unwatched", v4=IPv4Address("192.0.3.9"), segment_role="servers"),),
    )
    estate = Estate(team=42, team_padded="42", firewalls=(firewall,))
    findings = run_estate_checks(estate, a_policy(), {})
    assert any(f.id == "V-ESTATE-UNSCORED-ENCLAVE" for f in findings)
