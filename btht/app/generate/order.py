"""The ordering contract — `SPEC.md` §7.1.

Generated output **never depends on non-quick evaluation semantics**. Every intended
pass is an explicit quick rule, in a known position. Preserved baseline floating rules
stay underneath as a backstop and are never load-bearing.

That rule exists because of a specific, silent failure. On pfSense the shipped floating
passes for DNS, NTP and ICMP are *not* quick, so they act as a last-match backstop. Add
a quick block at the end of an interface tab — the obvious hardening step — and it
matches first and terminates. DNS, NTP and ICMP die, nothing in the configuration looks
wrong, and the enclave fails checks it appears to permit. `BASELINE-ANALYSIS.md` F3, and
`EVIDENCE.md` E6 is a team who lived it.

So the generator refuses to emit a deny unless an essential-services pass sits above it.
That refusal is `SPEC.md` §12.4, and it is not overridable.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from ipaddress import ip_address

from btht.app.ingest.fingerprint import strict_fingerprint
from btht.app.ingest.isa import Catalogue, required_ports
from btht.app.model.estate import Firewall
from btht.app.model.policy import EgressPolicy, FirewallPolicy, Policy, Selector
from btht.app.model.rules import (
    Action,
    AliasRef,
    AnyEndpoint,
    Direction,
    Endpoint,
    Family,
    HostAddress,
    InterfaceNet,
    PortSpec,
    Role,
    Rule,
    SelfEndpoint,
)

#: Floating block order. Position is the contract — `SPEC.md` §7.1.
THREAT_BLOCK = "THREAT BLOCK"
MGMT_ACCESS = "MGMT ACCESS"
SCORING = "SCORING"
OUT_OF_BOUNDS = "OUT OF BOUNDS"
ESSENTIAL_SERVICES = "ESSENTIAL SERVICES"
PRESERVED = "PRESERVED"
POLICY = "POLICY"
BLOCK_ALL = "BLOCK ALL"

FLOATING_ORDER = (
    THREAT_BLOCK,
    MGMT_ACCESS,
    SCORING,
    OUT_OF_BOUNDS,
    ESSENTIAL_SERVICES,
    PRESERVED,
)

#: Every generated rule carries this prefix. With filter descriptions on, the string
#: appears in the firewall log against every match, which is how a team debugs at speed.
TAG = "BTHT"


class GenerationRefused(Exception):
    """Refusing to generate beats generating something plausible — `SPEC.md` §2."""


@dataclass(frozen=True, slots=True)
class GeneratedRule:
    rule: Rule
    block: str
    intent: str
    """One line of plain English. The operator reads this, not the XML."""

    preserved: bool = False

    @property
    def description(self) -> str:
        if self.preserved:
            return self.rule.descr
        return f"{TAG} | {self.block} | {self.intent}"


@dataclass(frozen=True, slots=True)
class Ruleset:
    firewall: str
    floating: tuple[GeneratedRule, ...] = ()
    per_interface: tuple[tuple[str, tuple[GeneratedRule, ...]], ...] = ()
    wan: tuple[GeneratedRule, ...] = ()
    warnings: tuple[str, ...] = ()

    def all_rules(self) -> tuple[GeneratedRule, ...]:
        out = list(self.floating)
        out.extend(self.wan)
        for _role, rules in self.per_interface:
            out.extend(rules)
        return tuple(out)


def tracker_for(rule: Rule) -> str:
    """A stable tracker derived from the rule's own fingerprint.

    Deterministic on purpose: `SPEC.md` §12.9 requires byte-identical output across
    runs, and a timestamp or a counter would break that on the second run.
    """
    return str(int(strict_fingerprint(rule)[:12], 16))


def _endpoint_of(selector: Selector) -> Endpoint:
    """A declared selector as an endpoint. Nothing is inferred from an empty one."""
    if selector.any:
        return AnyEndpoint()
    if selector.alias:
        return AliasRef(selector.alias)
    if selector.host:
        return HostAddress(ip_address(selector.host))
    if selector.segments:
        return InterfaceNet(selector.segments[0])
    return AnyEndpoint()


def _ports(ports: tuple[int, ...]) -> tuple[PortSpec, ...]:
    return tuple(PortSpec(p, p) for p in sorted(set(ports)))


def _quick(
    action: Action,
    interfaces: tuple[str, ...],
    *,
    floating: bool = True,
    direction: Direction = Direction.IN,
    protocol: str | None = None,
    source: Endpoint | None = None,
    destination: Endpoint | None = None,
    destination_ports: tuple[PortSpec, ...] = (),
    icmp_types: tuple[str, ...] = (),
    role: Role = Role.UNKNOWN,
    log: bool = False,
) -> Rule:
    """Every generated rule is quick. That is the contract, not a preference."""
    return Rule(
        action=action,
        interfaces=interfaces,
        family=Family.INET46,
        direction=direction,
        quick=True,
        floating=floating,
        protocol=protocol,
        icmp_types=icmp_types,
        state_type="keep state",
        source=source or AnyEndpoint(),
        destination=destination or AnyEndpoint(),
        destination_ports=destination_ports,
        role=role,
        log=log,
    )


def _internal_roles(firewall: Firewall) -> tuple[str, ...]:
    return tuple(i.role for i in firewall.interfaces if i.role != "wan")


def build_floating(
    firewall: Firewall,
    policy: Policy,
    entry: FirewallPolicy,
    preserved: tuple[Rule, ...],
    catalogue: Catalogue,
    scoring_source: Selector,
    essential: dict[str, Selector],
) -> tuple[tuple[GeneratedRule, ...], tuple[str, ...]]:
    """The floating tab, in the order of `SPEC.md` §7.1."""
    every = tuple(i.role for i in firewall.interfaces)
    internal = _internal_roles(firewall)
    warnings: list[str] = []
    out: list[GeneratedRule] = []

    # 1 — threat block. Empty on day one; the alias exists so there is somewhere to
    # put an indicator at three in the morning without redesigning the ruleset.
    out.append(
        GeneratedRule(
            rule=_quick(
                Action.BLOCK,
                every,
                direction=Direction.ANY,
                source=AliasRef("BLOCKED_IPs"),
                role=Role.THREAT_BLOCK,
                log=True,
            ),
            block=THREAT_BLOCK,
            intent="Drop anything from BLOCKED_IPs, in or out, before any other rule",
        )
    )

    # 2 — management access, uniform across every internal segment regardless of
    # which pfSense interface happens to be `lan`.
    mgmt = next((a for a in policy.aliases if a.name == "Mgmt_Sources"), None)
    if mgmt is None:
        raise GenerationRefused(
            "No Mgmt_Sources alias declared. Generating a ruleset with no management "
            "path is how a team locks itself out of its own firewall."
        )
    out.append(
        GeneratedRule(
            rule=_quick(
                Action.PASS,
                internal or every,
                protocol="tcp",
                source=AliasRef("Mgmt_Sources"),
                destination=SelfEndpoint(),
                destination_ports=_ports((443, 22)),
                role=Role.MANAGEMENT,
            ),
            block=MGMT_ACCESS,
            intent="Administration of this firewall from Mgmt_Sources, on every internal "
            "segment — DO NOT REMOVE",
        )
    )

    # 3 — scoring. The firewall is itself a scored target (F9), so it is included.
    scored = 0
    if not catalogue.is_empty and scoring_source.declared:
        for host in firewall.hosts:
            pairs = required_ports(host.isa_checks, catalogue)
            if not pairs:
                continue
            scored += 1
            for proto, port in pairs:
                out.append(
                    GeneratedRule(
                        rule=_quick(
                            Action.PASS,
                            every,
                            protocol=None if proto == "icmp" else proto,
                            icmp_types=("echoreq",) if proto == "icmp" else (),
                            source=_endpoint_of(scoring_source),
                            destination=HostAddress(host.v4) if host.v4 else AnyEndpoint(),
                            destination_ports=_ports((port,)) if port else (),
                            role=Role.SCORING,
                        ),
                        block=SCORING,
                        intent=f"{host.hostname} {proto}"
                        + (f"/{port}" if port else "")
                        + " is scored — DO NOT REMOVE",
                    )
                )
    elif catalogue.is_empty:
        warnings.append(
            "No scoring catalogue loaded, so no scoring rules were generated. If this "
            "estate is scored, that is the highest-value thing still missing."
        )
    elif not scoring_source.declared:
        warnings.append("No scoring source declared, so no scoring rules were generated.")

    # 4 — out of bounds. Ingress and egress both, because their outbound path is a
    # scored obligation and they sit inside a segment somebody is about to tighten.
    for host in firewall.hosts:
        if not host.out_of_bounds or host.v4 is None:
            continue
        for direction, source, destination in (
            (Direction.IN, AnyEndpoint(), HostAddress(host.v4)),
            (Direction.OUT, HostAddress(host.v4), AnyEndpoint()),
        ):
            out.append(
                GeneratedRule(
                    rule=_quick(
                        Action.PASS,
                        every,
                        direction=direction,
                        source=source,
                        destination=destination,
                        role=Role.OUT_OF_BOUNDS,
                    ),
                    block=OUT_OF_BOUNDS,
                    intent=f"{host.hostname} is out of bounds and must keep working "
                    f"{'inbound' if direction is Direction.IN else 'outbound'} — DO NOT REMOVE",
                )
            )

    # 5 — essential services. Without these above a deny, DNS, NTP and IPv6
    # neighbour discovery die silently and nothing in the ruleset looks wrong.
    for name, ports, protocol in (("dns", (53,), "tcp/udp"), ("ntp", (123,), "udp")):
        selector = essential.get(name)
        if selector is None or not selector.declared:
            raise GenerationRefused(
                f"No {name.upper()} destination declared. A deny is generated beneath "
                f"these rules, so emitting one without a {name.upper()} pass above it "
                "breaks the enclave in a way the configuration does not show."
            )
        out.append(
            GeneratedRule(
                rule=_quick(
                    Action.PASS,
                    every,
                    protocol=protocol,
                    destination=_endpoint_of(selector),
                    destination_ports=_ports(ports),
                    role=Role.ESSENTIAL_SERVICES,
                ),
                block=ESSENTIAL_SERVICES,
                intent=f"{name.upper()} to its declared destination, from every segment",
            )
        )

    icmp6 = policy.options.icmp6_minimum
    out.append(
        GeneratedRule(
            rule=_quick(
                Action.PASS,
                every,
                direction=Direction.ANY,
                protocol="icmp",
                icmp_types=tuple(str(t) for t in sorted(icmp6)),
                role=Role.ESSENTIAL_SERVICES,
            ),
            block=ESSENTIAL_SERVICES,
            intent="ICMP and ICMPv6 minimum set — neighbour discovery, router "
            "advertisement, packet-too-big and echo. Narrowing this breaks IPv6 slowly",
        )
    )

    # 6+ — preserved baseline floating rules, verbatim, in their original order.
    for rule in preserved:
        out.append(
            GeneratedRule(
                rule=rule,
                block=PRESERVED,
                intent="Preserved from the shipped baseline, unchanged",
                preserved=True,
            )
        )

    return tuple(out), tuple(warnings)


def build_interface(
    role: str,
    entry: FirewallPolicy,
    policy: Policy,
    egress: EgressPolicy,
) -> tuple[GeneratedRule, ...]:
    """One internal segment: declared policy in declared order, then the deny."""
    out: list[GeneratedRule] = []

    for service in entry.services:
        if service.segment != role:
            continue
        out.append(
            GeneratedRule(
                rule=_quick(
                    Action.PASS,
                    (role,),
                    floating=False,
                    protocol=service.protocol,
                    source=_endpoint_of(service.source),
                    destination=(
                        HostAddress(ip_address(service.host))
                        if service.host
                        else (AliasRef(service.alias) if service.alias else AnyEndpoint())
                    ),
                    destination_ports=_ports(service.ports),
                    role=Role.ENCLAVE_POLICY,
                ),
                block=POLICY,
                intent=service.name,
            )
        )

    for index, allow in enumerate(egress.allow, start=1):
        if role not in allow.source.segments and not allow.source.any:
            continue
        out.append(
            GeneratedRule(
                rule=_quick(
                    Action.PASS,
                    (role,),
                    floating=False,
                    protocol=allow.protocol,
                    destination=_endpoint_of(allow.destination),
                    destination_ports=_ports(allow.ports),
                    role=Role.ENCLAVE_POLICY,
                ),
                block=POLICY,
                intent=f"Declared egress allow {index}",
            )
        )

    if egress.default in ("deny_and_log", "deny"):
        out.append(
            GeneratedRule(
                rule=_quick(
                    Action.BLOCK,
                    (role,),
                    floating=False,
                    role=Role.ENCLAVE_POLICY,
                    log=egress.default == "deny_and_log",
                ),
                block=BLOCK_ALL,
                intent="Everything not permitted above is denied"
                + (" and logged" if egress.default == "deny_and_log" else ""),
            )
        )
    return tuple(out)


def build_wan(
    entry: FirewallPolicy,
    policy: Policy,
    preserved_wan: tuple[Rule, ...],
    egress: EgressPolicy,
) -> tuple[GeneratedRule, ...]:
    """WAN: preserved baseline access rules, then declared ingress, then the deny.

    The shipped `any → any` on WAN is dropped. Every enclave in the evidence finished
    the exercise with it still live, beneath thirty carefully written rules.
    """
    out: list[GeneratedRule] = [
        GeneratedRule(
            rule=rule,
            block=PRESERVED,
            intent="Preserved from the shipped baseline, unchanged",
            preserved=True,
        )
        for rule in preserved_wan
    ]
    out.extend(build_interface("wan", entry, policy, EgressPolicy(default="none")))
    if egress.default in ("deny_and_log", "deny"):
        out.append(
            GeneratedRule(
                rule=_quick(
                    Action.BLOCK,
                    ("wan",),
                    floating=False,
                    role=Role.ENCLAVE_POLICY,
                    log=egress.default == "deny_and_log",
                ),
                block=BLOCK_ALL,
                intent="Everything not permitted above is denied and logged",
            )
        )
    return tuple(out)


def generate(
    firewall: Firewall,
    policy: Policy,
    catalogue: Catalogue,
    preserved_floating: tuple[Rule, ...] = (),
    preserved_wan: tuple[Rule, ...] = (),
    scoring_source: Selector = Selector(),
    essential: dict[str, Selector] | None = None,
) -> Ruleset:
    """A pure function of its inputs — `SPEC.md` §3. Same inputs, same ruleset."""
    entry = policy.for_enclave(firewall.enclave) or FirewallPolicy(enclave=firewall.enclave)
    floating, warnings = build_floating(
        firewall,
        policy,
        entry,
        preserved_floating,
        catalogue,
        scoring_source,
        essential or {},
    )

    per_interface = tuple(
        (role, build_interface(role, entry, policy, entry.egress))
        for role in _internal_roles(firewall)
    )
    wan = build_wan(entry, policy, preserved_wan, entry.egress)

    ruleset = Ruleset(
        firewall=firewall.enclave,
        floating=floating,
        per_interface=per_interface,
        wan=wan,
        warnings=warnings,
    )
    return replace(
        ruleset,
        floating=tuple(
            replace(g, rule=replace(g.rule, tracker=tracker_for(g.rule), descr=g.description))
            if not g.preserved
            else g
            for g in ruleset.floating
        ),
        per_interface=tuple(
            (
                role,
                tuple(
                    replace(
                        g, rule=replace(g.rule, tracker=tracker_for(g.rule), descr=g.description)
                    )
                    for g in rules
                ),
            )
            for role, rules in ruleset.per_interface
        ),
        wan=tuple(
            replace(g, rule=replace(g.rule, tracker=tracker_for(g.rule), descr=g.description))
            if not g.preserved
            else g
            for g in ruleset.wan
        ),
    )
