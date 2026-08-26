"""Estate-level checks — `BUILD-PLAN.md` 8.3, `SPEC.md` §8.

Everything up to here validates one firewall. These are the findings that only exist
when you look at the whole estate at once, which is why the tool models a team's estate
rather than an enclave at a time.

The one that matters: a declared path between two enclaves has two ends. Generate the
egress on one firewall and forget the ingress on the other and the traffic is dropped
silently by the second box, while the first shows a rule that says it is allowed. Each
firewall's own validators see nothing wrong, because from where they stand nothing is.
"""

from __future__ import annotations

from btht.app.generate.order import Ruleset
from btht.app.model.estate import Estate
from btht.app.model.policy import Policy
from btht.app.validate.rules import Finding, Severity


def cross_enclave_paths(
    estate: Estate, policy: Policy, rulesets: dict[str, Ruleset]
) -> list[Finding]:
    """Both ends of every declared dependency, or neither."""
    findings: list[Finding] = []
    for dependency in policy.dependencies:
        sources = [e for e in dependency.from_enclaves if e in rulesets]
        destination = dependency.to_enclave

        for enclave in sources:
            emitted = any(
                dependency.name in generated.intent for generated in rulesets[enclave].all_rules()
            )
            if not emitted:
                findings.append(
                    Finding(
                        "V-CROSS-ENCLAVE-ORPHAN",
                        Severity.WARNING,
                        f"'{dependency.name}': {enclave} is a source but has no egress "
                        "rule for it. The path is declared and does not exist.",
                        dependency.name,
                    )
                )

        if destination and destination in rulesets:
            ingress = any(
                dependency.name in generated.intent
                for generated in rulesets[destination].all_rules()
            )
            if not ingress:
                findings.append(
                    Finding(
                        "V-CROSS-ENCLAVE-ORPHAN",
                        Severity.WARNING,
                        f"'{dependency.name}': {destination} is the destination and has "
                        "no ingress rule. The source will show traffic as permitted "
                        "while the destination drops it, and neither firewall's own "
                        "checks can see that.",
                        dependency.name,
                    )
                )
        elif destination and destination not in rulesets:
            findings.append(
                Finding(
                    "V-CROSS-ENCLAVE-ORPHAN",
                    Severity.WARNING,
                    f"'{dependency.name}' points at {destination}, which has no "
                    "generated ruleset. Half a path is worse than none: it looks "
                    "configured.",
                    dependency.name,
                )
            )
    return findings


def shared_alias_consistency(estate: Estate, policy: Policy) -> list[Finding]:
    """An alias meaning two different things on two firewalls.

    `Mgmt_Sources` holding one set of addresses on one enclave and another elsewhere is
    how a management restriction ends up with a hole nobody planned — and reading
    either firewall alone shows a tidy, consistent rule.
    """
    findings = []
    declared = {alias.name for alias in policy.aliases}
    for firewall in estate.firewalls:
        present = {alias.name for alias in firewall.aliases}
        missing = sorted(declared - present - {"BLOCKED_IPs"})
        if missing and firewall.aliases:
            findings.append(
                Finding(
                    "V-SHARED-ALIAS-ABSENT",
                    Severity.WARNING,
                    f"{firewall.enclave} does not carry: {', '.join(missing)}. Rules "
                    "referring to them will match nothing on this firewall only.",
                    firewall.enclave,
                )
            )
    return findings


def scoring_coverage(estate: Estate) -> list[Finding]:
    """A whole enclave with nothing scored. Worth one look before it is believed."""
    findings = []
    for firewall in estate.firewalls:
        if firewall.hosts and not any(host.isa_checks for host in firewall.hosts):
            findings.append(
                Finding(
                    "V-ESTATE-UNSCORED-ENCLAVE",
                    Severity.INFO,
                    f"{firewall.enclave} has hosts declared and no checks assigned to "
                    "any of them. Confirm the board really shows nothing for it.",
                    firewall.enclave,
                )
            )
    return findings


def run_estate_checks(
    estate: Estate, policy: Policy, rulesets: dict[str, Ruleset]
) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    findings += cross_enclave_paths(estate, policy, rulesets)
    findings += shared_alias_consistency(estate, policy)
    findings += scoring_coverage(estate)
    return tuple(findings)
