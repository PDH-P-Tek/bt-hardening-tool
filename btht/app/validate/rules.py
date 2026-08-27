"""The validator catalogue — `SPEC.md` §8.

Pure functions with stable IDs. Each one has a golden test asserting it fires on its
case *and* stays silent on a clean baseline, because a validator that cries wolf gets
turned off and a validator that never fires was never a control.

Severity is not a style choice. **Blocking** findings stop export outright; there is no
override, because every one of them is a way to produce a ruleset that looks correct
and is not. **Warnings** must be acknowledged individually — acknowledging in bulk is
how thirty findings become one click. **Info** is context.

Most of these are not hypothetical. The IDs carrying an `EVIDENCE.md` reference are
things a real team shipped, under time pressure, while believing the opposite.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum

from btht.app.generate.order import BLOCK_ALL, ESSENTIAL_SERVICES, MGMT_ACCESS, SCORING, Ruleset
from btht.app.ingest.classify import RuleMatch, Tier
from btht.app.ingest.isa import Catalogue
from btht.app.model.estate import Firewall
from btht.app.model.policy import Policy
from btht.app.model.rules import (
    Action,
    Alias,
    AliasRef,
    AnyEndpoint,
    Endpoint,
    HostAddress,
    Negated,
    Role,
    Rule,
)


class Severity(StrEnum):
    BLOCKING = "blocking"
    WARNING = "warning"
    INFO = "info"


@dataclass(frozen=True, slots=True)
class Finding:
    id: str
    severity: Severity
    message: str
    """Written for the operator, not for a log. It says what is wrong and what it costs."""

    item: str = ""


@dataclass(frozen=True, slots=True)
class Context:
    """Everything a validator may look at. Nothing reaches outside it."""

    firewall: Firewall
    ruleset: Ruleset
    policy: Policy
    catalogue: Catalogue = field(default_factory=lambda: Catalogue({}, {}, {}))
    baseline_rules: tuple[Rule, ...] = ()
    baseline_aliases: tuple[Alias, ...] = ()
    output_aliases: tuple[Alias, ...] = ()
    matches: tuple[RuleMatch, ...] = ()
    config_version: str = "23.3"
    antilockout_enabled: bool = True
    nat_mode: str = "disabled"
    baseline_nat_mode: str = "disabled"
    target_identity: str = ""
    dropped_lockout_critical: tuple[str, ...] = ()
    annex_subnets: tuple[tuple[str, str], ...] = ()
    frr_peers: tuple[str, ...] = ()
    nmap_hosts: tuple[str, ...] = ()
    separators_emitted: bool = True
    typed_confirmations: frozenset[str] = frozenset()


Validator = Callable[[Context], list[Finding]]
REGISTRY: dict[str, tuple[Severity, Validator]] = {}


def validator(check_id: str, severity: Severity) -> Callable[[Validator], Validator]:
    def register(function: Validator) -> Validator:
        REGISTRY[check_id] = (severity, function)
        return function

    return register


def _endpoint_is_any(endpoint: Endpoint) -> bool:
    return isinstance(endpoint, AnyEndpoint)


def _alias_names(endpoint: Endpoint) -> list[str]:
    match endpoint:
        case AliasRef(name):
            return [name]
        case Negated(inner):
            return _alias_names(inner)
    return []


def _generated(context: Context) -> tuple[Rule, ...]:
    return tuple(g.rule for g in context.ruleset.all_rules() if not g.preserved)


# ===========================================================================
#  Blocking — no export, no override
# ===========================================================================


@validator("V-UNKNOWN-UNRESOLVED", Severity.BLOCKING)
def unknown_unresolved(context: Context) -> list[Finding]:
    """An item nobody classified. Guessing is the one thing the tool must not do."""
    out = []
    for match in context.matches:
        if match.role is Role.UNKNOWN:
            label = match.rule.descr or "(no description)"
            out.append(
                Finding(
                    "V-UNKNOWN-UNRESOLVED",
                    Severity.BLOCKING,
                    f"{label} has not been classified. Every item needs a role before "
                    "anything is generated from it.",
                    label,
                )
            )
    return out


@validator("V-LOCKOUT-DROP", Severity.BLOCKING)
def lockout_drop(context: Context) -> list[Finding]:
    """Dropping the way back in. Requires typed confirmation, not a checkbox."""
    return [
        Finding(
            "V-LOCKOUT-DROP",
            Severity.BLOCKING,
            f"{name} is lockout-critical and is being dropped. Losing it means losing "
            "access to your own firewall, from a rule you wrote yourself.",
            name,
        )
        for name in context.dropped_lockout_critical
        if name not in context.typed_confirmations
    ]


@validator("V-ALIAS-MISSING", Severity.BLOCKING)
def alias_missing(context: Context) -> list[Finding]:
    """A rule pointing at an alias that will not exist. pfSense matches nothing."""
    known = {a.name for a in context.output_aliases} | {a.name for a in context.policy.aliases}
    known |= {"BLOCKED_IPs", "Remote_Access", "Routers"}
    out = []
    for rule in _generated(context):
        for name in _alias_names(rule.source) + _alias_names(rule.destination):
            if name not in known:
                out.append(
                    Finding(
                        "V-ALIAS-MISSING",
                        Severity.BLOCKING,
                        f"Rule '{rule.descr}' refers to alias {name}, which is not in the "
                        "output. The rule will match nothing.",
                        name,
                    )
                )
    return out


@validator("V-ALIAS-ORPHAN-DROP", Severity.BLOCKING)
def alias_orphan_drop(context: Context) -> list[Finding]:
    """An alias removed while rules still point at it."""
    referenced: set[str] = set()
    for rule in _generated(context):
        referenced.update(_alias_names(rule.source) + _alias_names(rule.destination))
    present = {a.name for a in context.output_aliases}
    baseline = {a.name for a in context.baseline_aliases}
    return [
        Finding(
            "V-ALIAS-ORPHAN-DROP",
            Severity.BLOCKING,
            f"Alias {name} is referenced by a rule but is being dropped from the output.",
            name,
        )
        for name in sorted(referenced & baseline - present)
    ]


@validator("V-MGMT-ABSENT", Severity.BLOCKING)
def mgmt_absent(context: Context) -> list[Finding]:
    """No management path on some segment. The rule that saves you at 3am."""
    internal = {i.role for i in context.firewall.interfaces if i.role != "wan"}
    covered: set[str] = set()
    for generated in context.ruleset.all_rules():
        if generated.block == MGMT_ACCESS:
            covered.update(generated.rule.interfaces)
    missing = sorted(internal - covered)
    if not missing:
        return []
    return [
        Finding(
            "V-MGMT-ABSENT",
            Severity.BLOCKING,
            "No management rule reaches: " + ", ".join(missing) + ". If you are on one "
            "of those segments when the deny goes in, you have locked yourself out.",
            ", ".join(missing),
        )
    ]


@validator("V-DENY-WITHOUT-ESSENTIAL", Severity.BLOCKING)
def deny_without_essential(context: Context) -> list[Finding]:
    """`SPEC.md` §12.4. `EVIDENCE.md` E6 is a team who did this and lost DNS silently."""
    has_deny = any(g.block == BLOCK_ALL for g in context.ruleset.all_rules())
    has_essential = any(g.block == ESSENTIAL_SERVICES for g in context.ruleset.all_rules())
    if has_deny and not has_essential:
        return [
            Finding(
                "V-DENY-WITHOUT-ESSENTIAL",
                Severity.BLOCKING,
                "A deny is emitted with no essential-services pass above it. DNS, NTP "
                "and IPv6 neighbour discovery will stop, and nothing in the ruleset "
                "will look wrong.",
            )
        ]
    return []


@validator("V-IF-MISMATCH", Severity.BLOCKING)
def identity_mismatch(context: Context) -> list[Finding]:
    """Output is bound to one firewall. Applying it elsewhere is destructive.

    On an estate where one enclave inverts LAN, applying another's ruleset means
    the workstation rules land on the servers.
    """
    if context.target_identity and context.target_identity != context.firewall.enclave:
        return [
            Finding(
                "V-IF-MISMATCH",
                Severity.BLOCKING,
                f"This ruleset was generated for {context.firewall.enclave} and is being "
                f"applied to {context.target_identity}. Refused: segment roles differ "
                "between firewalls, so the rules would land on the wrong segments.",
            )
        ]
    return []


@validator("V-CONFIG-VERSION", Severity.BLOCKING)
def config_version(context: Context) -> list[Finding]:
    if context.config_version and context.config_version != "23.3":
        return [
            Finding(
                "V-CONFIG-VERSION",
                Severity.BLOCKING,
                f"Baseline is config format {context.config_version}, not 23.3. The "
                "element layout may differ from what this tool writes.",
            )
        ]
    return []


@validator("V-PERMISSIVE-RETAINED", Severity.BLOCKING)
def permissive_retained(context: Context) -> list[Finding]:
    """`EVIDENCE.md` E1 — six of six enclaves finished with one of these live."""
    out = []
    for generated in context.ruleset.all_rules():
        rule = generated.rule
        if (
            rule.action is Action.PASS
            and _endpoint_is_any(rule.source)
            and _endpoint_is_any(rule.destination)
            and not rule.destination_ports
            and not rule.protocol
            and generated.block != ESSENTIAL_SERVICES
        ):
            label = rule.descr or "(no description)"
            out.append(
                Finding(
                    "V-PERMISSIVE-RETAINED",
                    Severity.BLOCKING,
                    f"{label} passes everything from anywhere to anywhere. Every rule "
                    "above it is decoration.",
                    label,
                )
            )
    return out


@validator("V-DUALSTACK-ASYMMETRY", Severity.BLOCKING)
def dualstack_asymmetry(context: Context) -> list[Finding]:
    """`EVIDENCE.md` E2 — 74 IPv4-only rules across the estate, all bypassed on IPv6."""
    return [
        Finding("V-DUALSTACK-ASYMMETRY", Severity.BLOCKING, warning)
        for warning in context.ruleset.warnings
        if "emitted inet only" in warning or "emitted inet6 only" in warning
    ]


@validator("V-NAT-MODE-CHANGED", Severity.BLOCKING)
def nat_mode_changed(context: Context) -> list[Finding]:
    if context.nat_mode != context.baseline_nat_mode:
        return [
            Finding(
                "V-NAT-MODE-CHANGED",
                Severity.BLOCKING,
                f"Outbound NAT mode changed from {context.baseline_nat_mode} to "
                f"{context.nat_mode}. The range is routed; changing this breaks "
                "return paths in ways that look like a firewall rule problem.",
            )
        ]
    return []


@validator("V-SCORING-ABSENT", Severity.BLOCKING)
def scoring_absent(context: Context) -> list[Finding]:
    """`EVIDENCE.md` E9. Only fires where a catalogue says there is scoring to do."""
    if context.catalogue.is_empty:
        return []
    if any(g.block == SCORING for g in context.ruleset.all_rules()):
        return []
    return [
        Finding(
            "V-SCORING-ABSENT",
            Severity.BLOCKING,
            "No rule carries the scoring role, but a scoring catalogue is loaded. "
            "Availability points are being lost silently.",
        )
    ]


@validator("V-EGRESS-CHECK", Severity.BLOCKING)
def egress_check(context: Context) -> list[Finding]:
    """`EVIDENCE.md` E6 and F9 — an egress block fails an outbound-measured check."""
    entry = context.policy.for_enclave(context.firewall.enclave)
    if entry is None or entry.egress.default == "allow":
        return []
    outbound_checks = [
        check.name
        for check in context.catalogue.checks.values()
        if not check.satisfiable_by_ingress
    ]
    scored_hosts = [h for h in context.firewall.hosts if set(h.isa_checks) & set(outbound_checks)]
    if not scored_hosts:
        return []
    return [
        Finding(
            "V-EGRESS-CHECK",
            Severity.BLOCKING,
            f"{host.hostname} carries a check measured on its outbound path, and this "
            f"enclave's egress default is {entry.egress.default}. The check fails "
            "outright unless its path is allowed above the deny.",
            host.hostname,
        )
        for host in scored_hosts
    ]


@validator("V-OOB-BLOCKED", Severity.BLOCKING)
def out_of_bounds_blocked(context: Context) -> list[Finding]:
    """`BASELINE-ANALYSIS.md` F8 — they are inside a segment and on no diagram."""
    protected = {h.hostname: h for h in context.firewall.hosts if h.out_of_bounds}
    if not protected:
        return []
    allowed: set[str] = set()
    for generated in context.ruleset.all_rules():
        rule = generated.rule
        if rule.action is not Action.PASS:
            continue
        for endpoint in (rule.source, rule.destination):
            if isinstance(endpoint, HostAddress):
                for name, host in protected.items():
                    if endpoint.address in (host.v4, host.v6):
                        allowed.add(name)
    return [
        Finding(
            "V-OOB-BLOCKED",
            Severity.BLOCKING,
            f"{name} is out of bounds and has no pass rule. It sits inside a segment "
            "you are tightening, appears on no diagram, and breaking it costs scoring "
            "or the user simulation.",
            name,
        )
        for name in sorted(set(protected) - allowed)
    ]


# ===========================================================================
#  Warnings — acknowledged individually, never in bulk
# ===========================================================================


@validator("V-ALIAS-FAMILY", Severity.WARNING)
def alias_family(context: Context) -> list[Finding]:
    """`BASELINE-ANALYSIS.md` F1 — the shipped alias lists the wrong v6 prefix.

    It is masked by the catch-all until someone closes it, which is the first thing
    a competent team does. Then IPv6 routing adjacency goes with it.
    """
    from ipaddress import ip_address, ip_network

    out = []
    own_v6 = [str(i.v6.network) for i in context.firewall.interfaces if i.v6]
    for alias in context.baseline_aliases:
        v6_entries = []
        for entry in alias.entries:
            try:
                address = ip_network(entry, strict=False) if "/" in entry else ip_address(entry)
            except ValueError:
                continue
            if address.version == 6:
                v6_entries.append(str(address))
        if not v6_entries or not own_v6:
            continue
        # Compare two hextets: everything in an estate may share the first, and the
        # defect this exists for is exactly a right-looking prefix with the wrong
        # second group.
        prefix = ":".join(own_v6[0].split(":")[:2])
        if all(not entry.startswith(prefix) for entry in v6_entries):
            out.append(
                Finding(
                    "V-ALIAS-FAMILY",
                    Severity.WARNING,
                    f"Alias {alias.name} holds IPv6 entries ({', '.join(v6_entries)}) that "
                    f"are not on this firewall's own IPv6 prefix. Rules using it will not "
                    "match the real IPv6 peers.",
                    alias.name,
                )
            )
    return out


@validator("V-ROUTING-PEERS", Severity.WARNING)
def routing_peers(context: Context) -> list[Finding]:
    """A routing peer with no rule covering it. Adjacency drops when the catch-all goes."""
    if not context.frr_peers:
        return []
    covered: set[str] = set()
    for alias in context.output_aliases + context.baseline_aliases:
        covered.update(alias.entries)
    missing = [peer for peer in context.frr_peers if peer not in covered]
    return (
        [
            Finding(
                "V-ROUTING-PEERS",
                Severity.WARNING,
                "Routing peers not covered by any alias: "
                + ", ".join(sorted(missing))
                + ". Adjacency will drop when the permissive rule is removed.",
                ", ".join(sorted(missing)),
            )
        ]
        if missing
        else []
    )


@validator("V-SHADOW-FLOATING", Severity.WARNING)
def shadow_floating(context: Context) -> list[Finding]:
    """A quick block above a preserved non-quick pass — `BASELINE-ANALYSIS.md` F3."""
    seen_block = False
    out = []
    for generated in context.ruleset.floating:
        if generated.rule.action is Action.BLOCK and generated.rule.quick:
            seen_block = True
        elif seen_block and generated.preserved and generated.rule.action is Action.PASS:
            out.append(
                Finding(
                    "V-SHADOW-FLOATING",
                    Severity.WARNING,
                    f"Preserved rule '{generated.rule.descr or '(no description)'}' sits "
                    "below a quick block and can no longer take effect.",
                    generated.rule.descr,
                )
            )
    return out


@validator("V-SHADOWED-RULE", Severity.WARNING)
def shadowed_rule(context: Context) -> list[Finding]:
    """`EVIDENCE.md` E8 — a rule below an earlier quick rule that already matched."""
    out = []
    for _role, rules in context.ruleset.per_interface:
        blocked_at = None
        for index, generated in enumerate(rules):
            rule = generated.rule
            if blocked_at is not None and rule.action is Action.PASS and index > blocked_at:
                out.append(
                    Finding(
                        "V-SHADOWED-RULE",
                        Severity.WARNING,
                        f"'{rule.descr or '(no description)'}' is below a quick block-all "
                        "on the same interface and is unreachable.",
                        rule.descr,
                    )
                )
            if (
                rule.action is Action.BLOCK
                and rule.quick
                and _endpoint_is_any(rule.source)
                and _endpoint_is_any(rule.destination)
            ):
                blocked_at = index
    return out


@validator("V-LABEL-ACTION-MISMATCH", Severity.WARNING)
def label_action_mismatch(context: Context) -> list[Finding]:
    """`EVIDENCE.md` E3 — three rules said BLOCK and did `pass`."""
    import re

    negation = re.compile(r"\b(?:not|never|no)\s+(?:permitted|allowed|passed)\b")
    blockish = re.compile(r"\b(?:block(?:ed|s)?|deny|denied|drop(?:ped|s)?)\b")
    passish = re.compile(r"\b(?:allow(?:ed|s)?|permit(?:ted|s)?|pass(?:es)?)\b")

    out = []
    for rule in context.baseline_rules:
        # Generated rules are excluded on purpose: their description is written from
        # their action, so the two cannot disagree, and checking them only produces
        # noise. This validator is about labels a human wrote.
        label = negation.sub("", rule.descr.lower())
        says_block = bool(blockish.search(label))
        says_pass = bool(passish.search(label))
        if says_block and rule.action is Action.PASS:
            out.append(
                Finding(
                    "V-LABEL-ACTION-MISMATCH",
                    Severity.WARNING,
                    f"'{rule.descr}' is labelled as a block and its action is pass. "
                    "The label is what someone will read in a hurry.",
                    rule.descr,
                )
            )
        elif says_pass and rule.action is Action.BLOCK:
            out.append(
                Finding(
                    "V-LABEL-ACTION-MISMATCH",
                    Severity.WARNING,
                    f"'{rule.descr}' is labelled as an allow and its action is block.",
                    rule.descr,
                )
            )
    return out


@validator("V-ALIAS-NAME-HYGIENE", Severity.WARNING)
def alias_name_hygiene(context: Context) -> list[Finding]:
    """`EVIDENCE.md` E4 — an alias named `Temp` exposing a database to the greynet."""
    smells = ("temp", "tmp", "test", "todo", "xxx")
    return [
        Finding(
            "V-ALIAS-NAME-HYGIENE",
            Severity.WARNING,
            f"Alias {alias.name} is named like something temporary. In the observed "
            "estate an alias named this way was still exposing a database at the end "
            "of the exercise.",
            alias.name,
        )
        for alias in (*context.output_aliases, *context.baseline_aliases)
        if any(smell in alias.name.lower() for smell in smells)
    ]


@validator("V-OVERBROAD-SCORING-SOURCE", Severity.WARNING)
def overbroad_scoring_source(context: Context) -> list[Finding]:
    """`EVIDENCE.md` E10 — a scoring rule sourced from `any` opens the port to everyone."""
    return [
        Finding(
            "V-OVERBROAD-SCORING-SOURCE",
            Severity.WARNING,
            f"Scoring rule '{g.rule.descr}' accepts from anywhere rather than from the "
            "scoring source. It opens the scored port to the whole network.",
            g.rule.descr,
        )
        for g in context.ruleset.all_rules()
        if g.block == SCORING and _endpoint_is_any(g.rule.source)
    ]


@validator("V-ICMP6-MINIMUM", Severity.WARNING)
def icmp6_minimum(context: Context) -> list[Finding]:
    """`BASELINE-ANALYSIS.md` F5 — narrowing ICMPv6 breaks IPv6 in ways that fail slowly."""
    required = {"2", "128", "129", "133", "134", "135", "136"}
    passed: set[str] = set()
    for generated in context.ruleset.all_rules():
        if generated.rule.action is Action.PASS and generated.rule.icmp_types:
            passed.update(generated.rule.icmp_types)
    missing = sorted(required - passed, key=int)
    if not missing:
        return []
    return [
        Finding(
            "V-ICMP6-MINIMUM",
            Severity.WARNING,
            "ICMPv6 types not passed: " + ", ".join(missing) + ". Neighbour discovery, "
            "router advertisement and path-MTU all live here; without them IPv6 fails "
            "slowly and looks like something else.",
        )
    ]


#: IPv4 ICMP types with no business crossing a segment boundary inbound. Echo is the
#: exception and is handled separately, because the scoring bot needs it.
ICMP_UNNEEDED = ("timestamp", "timereq", "maskreq", "inforeq", "redir", "routeradv")


@validator("V-ICMP-EXPOSURE", Severity.WARNING)
def icmp_exposure(context: Context) -> list[Finding]:
    """ICMP echo passed from an unrestricted source.

    Availability scoring is decided by ICMP, so blocking echo outright loses points and
    is never the advice. The exposure is passing it *from anywhere*: an implant on a
    firewall can be woken by a crafted echo — a particular payload size is enough — and
    the reply path out is a shell. Restricting echo to the scoring sources and the
    management range keeps every point and removes the trigger from everybody else.

    Warning rather than blocking, because a range may legitimately want echo working
    between segments for diagnosis, and that is the operator's call to make knowingly.
    """
    findings = []
    for generated in context.ruleset.all_rules():
        rule = generated.rule
        if rule.action is not Action.PASS:
            continue
        # IPv4 echo specifically, or ICMP passed wholesale with no types named. The
        # ICMPv6 minimum set is neither: it names its types and *must* come from any,
        # because neighbour discovery and router advertisement originate from
        # link-local addresses this ruleset never enumerates. Flagging it would train
        # the operator to ignore this check, and F5 is emphatic that narrowing ICMPv6
        # breaks IPv6 in ways that fail slowly.
        wholesale = rule.protocol == "icmp" and not rule.icmp_types
        if "echoreq" not in rule.icmp_types and not wholesale:
            continue
        if not _endpoint_is_any(rule.source):
            continue
        if generated.block == SCORING:
            continue
        findings.append(
            Finding(
                "V-ICMP-EXPOSURE",
                Severity.WARNING,
                "ICMP echo is passed from any source by "
                f"'{rule.descr or generated.intent}'. Scoring only needs it from the "
                "scoring sources, and echo reachable from everywhere is a wake-up "
                "signal for anything already implanted on the box. Narrow the source "
                "to the scoring and management ranges — the availability points are "
                "unaffected.",
                item=generated.intent,
            )
        )
    return findings


@validator("V-ICMP-EXTRA-TYPES", Severity.WARNING)
def icmp_extra_types(context: Context) -> list[Finding]:
    """ICMP types beyond what anything needs.

    Timestamp and address-mask requests leak host information for nothing in return,
    and redirects accepted inbound let somebody else edit the routing table. None is
    needed by any scored check.
    """
    findings = []
    for generated in context.ruleset.all_rules():
        rule = generated.rule
        if rule.action is not Action.PASS:
            continue
        unneeded = sorted(set(rule.icmp_types) & set(ICMP_UNNEEDED))
        if not unneeded:
            continue
        findings.append(
            Finding(
                "V-ICMP-EXTRA-TYPES",
                Severity.WARNING,
                f"'{rule.descr or generated.intent}' passes ICMP {', '.join(unneeded)}. "
                "Nothing scored needs these; timestamp and mask requests give away host "
                "detail, and an accepted redirect lets somebody else steer your traffic. "
                "Echo request is the only IPv4 type availability scoring needs.",
                item=generated.intent,
            )
        )
    return findings


@validator("V-UNVERIFIED-SERVICE", Severity.WARNING)
def unverified_service(context: Context) -> list[Finding]:
    """A service permitted broadly because its ports are not known yet."""
    entry = context.policy.for_enclave(context.firewall.enclave)
    if entry is None:
        return []
    return [
        Finding(
            "V-UNVERIFIED-SERVICE",
            Severity.WARNING,
            f"Service '{service.name}' is permitted with no port list. It stays open "
            "until someone finds out what it actually needs.",
            service.name,
        )
        for service in entry.services
        if not service.ports
    ]


@validator("V-ANTILOCKOUT-DISABLED", Severity.WARNING)
def antilockout_disabled(context: Context) -> list[Finding]:
    if context.antilockout_enabled:
        return []
    return [
        Finding(
            "V-ANTILOCKOUT-DISABLED",
            Severity.WARNING,
            "Anti-lockout is disabled. That is a legitimate hardening step and it is "
            "also the single highest-risk change here: verify your management rule "
            "works from a second session before you rely on it.",
        )
    ]


@validator("V-ANNEX-CONFIG-MISMATCH", Severity.WARNING)
def annex_config_mismatch(context: Context) -> list[Finding]:
    """The documents and the box disagreeing is worth knowing before generating."""
    declared = {str(i.v4.network) for i in context.firewall.interfaces if i.v4}
    return [
        Finding(
            "V-ANNEX-CONFIG-MISMATCH",
            Severity.WARNING,
            f"The annex lists {name} on {subnet}, which is not on any declared "
            "interface. One of the two is out of date.",
            name,
        )
        for name, subnet in context.annex_subnets
        if subnet not in declared
    ]


@validator("V-SCORING-UNCOVERED", Severity.WARNING)
def scoring_uncovered(context: Context) -> list[Finding]:
    """A confirmed check with no rule permitting it. Points lost, quietly."""
    if context.catalogue.is_empty:
        return []
    scored = {h.hostname for h in context.firewall.hosts if h.isa_checks}
    covered = {g.intent.split()[0] for g in context.ruleset.all_rules() if g.block == SCORING}
    return [
        Finding(
            "V-SCORING-UNCOVERED",
            Severity.WARNING,
            f"{name} has confirmed checks but no scoring rule was generated for it.",
            name,
        )
        for name in sorted(scored - covered)
    ]


@validator("V-CROSS-ENCLAVE-ORPHAN", Severity.WARNING)
def cross_enclave_orphan(context: Context) -> list[Finding]:
    """One side of a declared path. The other end silently drops the traffic."""
    out = []
    for dependency in context.policy.dependencies:
        names_this_enclave = context.firewall.enclave in dependency.from_enclaves
        has_rule = any(
            g.block == "POLICY" and dependency.name in g.intent for g in context.ruleset.all_rules()
        )
        if names_this_enclave and not has_rule:
            out.append(
                Finding(
                    "V-CROSS-ENCLAVE-ORPHAN",
                    Severity.WARNING,
                    f"Dependency '{dependency.name}' names this enclave as a source "
                    "but no rule was generated for it here.",
                    dependency.name,
                )
            )
    return out


# ===========================================================================
#  Info — context, not a problem
# ===========================================================================


@validator("V-BASELINE-DRIFT", Severity.INFO)
def baseline_drift(context: Context) -> list[Finding]:
    """The shipped baseline is not what the profile expected. Expected on a new exercise."""
    drifted = [m for m in context.matches if m.tier is Tier.STRUCTURAL]
    if not drifted:
        return []
    return [
        Finding(
            "V-BASELINE-DRIFT",
            Severity.INFO,
            f"{len(drifted)} baseline item(s) match the profile structurally but not "
            "exactly. Expected if the shipped baseline changed this year.",
        )
    ]


@validator("V-UNEXPECTED-HOST", Severity.INFO)
def unexpected_host(context: Context) -> list[Finding]:
    """Something answering that the documents do not mention."""
    declared = {str(h.v4) for h in context.firewall.hosts if h.v4}
    return [
        Finding(
            "V-UNEXPECTED-HOST",
            Severity.INFO,
            f"{address} answered a scan but is not in the declared inventory.",
            address,
        )
        for address in context.nmap_hosts
        if address not in declared
    ]


@validator("V-SCORING-UNCHECKED", Severity.INFO)
def scoring_unchecked(context: Context) -> list[Finding]:
    """A host with no checks. Probably unscored — worth one look at the board."""
    if context.catalogue.is_empty:
        return []
    return [
        Finding(
            "V-SCORING-UNCHECKED",
            Severity.INFO,
            f"{host.hostname} has no checks assigned. Confirm on the board that it "
            "really is unscored.",
            host.hostname,
        )
        for host in context.firewall.hosts
        if not host.isa_checks and not host.out_of_bounds
    ]


@validator("V-NO-SEPARATORS", Severity.INFO)
def no_separators(context: Context) -> list[Finding]:
    if context.separators_emitted:
        return []
    return [
        Finding(
            "V-NO-SEPARATORS",
            Severity.INFO,
            "No separators emitted. The rule list will be one undifferentiated block "
            "on screen, which is harder to work with under pressure.",
        )
    ]


def run_all(context: Context) -> tuple[Finding, ...]:
    """Every validator, in ID order so output is stable."""
    findings: list[Finding] = []
    for check_id in sorted(REGISTRY):
        _severity, function = REGISTRY[check_id]
        findings.extend(function(context))
    return tuple(findings)


def blocking(findings: tuple[Finding, ...]) -> tuple[Finding, ...]:
    return tuple(f for f in findings if f.severity is Severity.BLOCKING)


def warnings(findings: tuple[Finding, ...]) -> tuple[Finding, ...]:
    return tuple(f for f in findings if f.severity is Severity.WARNING)
