"""What to do next.

The tool spans three days of work — declare the range from the documents, generate and
check a ruleset, then watch the estate for the rest of the exercise — and someone
sitting down in front of it for the first time cannot be expected to infer that order
from a navigation bar. Worse, the order matters: declaring policy before the hosts
exist produces rules against segments with nothing on them, and taking a baseline
before hardening throws away the only clean picture of what Green Team shipped.

So the tool works out where the operator actually is and says what to do next, on every
page. Each step reports itself done or not from the estate's own state — nothing is
stored, nothing to get out of step with reality, and no wizard to be trapped halfway
through. The operator can always ignore it and go straight to any page.
"""

from __future__ import annotations

from dataclasses import dataclass

from btht.app.model.estate import Estate
from btht.app.model.policy import Policy


@dataclass(frozen=True, slots=True)
class Step:
    """One stage of the job, and the single action that advances it."""

    key: str
    title: str
    #: Why this step exists, in the operator's terms. Shown only when it is the next
    #: thing to do, because explaining five steps at once explains nothing.
    why: str
    action: str
    href: str
    done: bool = False
    #: Set when the step is done but not *finished* — reviewed rules with findings
    #: still outstanding, hosts declared but no services on them.
    caution: str = ""


def plan(
    estate: Estate | None,
    policy: Policy | None = None,
    *,
    reviewed: frozenset[str] = frozenset(),
    baselined: frozenset[str] = frozenset(),
    unreviewed_items: int = 0,
) -> tuple[Step, ...]:
    """The whole journey, each step reporting whether it is done.

    `reviewed` is the set of enclaves whose rules a person has actually read and
    exported; `baselined` those the monitor holds a baseline for.
    """
    firewalls = estate.firewalls if estate else ()
    # A WAN-only firewall has nothing behind it to protect yet, so interfaces counts
    # internal segments rather than every port.
    internal = {f.enclave: [i for i in f.interfaces if i.role != "wan"] for f in firewalls}
    with_hosts = {f.enclave for f in firewalls if f.hosts or f.host_groups}
    with_policy = {f.enclave for f in (policy.firewalls if policy else ())}

    needs_interfaces = [f.enclave for f in firewalls if not internal[f.enclave]]
    needs_hosts = [
        f.enclave for f in firewalls if internal[f.enclave] and f.enclave not in with_hosts
    ]
    needs_policy = [f.enclave for f in firewalls if f.enclave not in with_policy]
    needs_review = [f.enclave for f in firewalls if f.enclave not in reviewed]
    nodes = estate.all_nodes() if estate else ()
    needs_baseline = [n.name for n in nodes if n.name not in baselined]

    steps = [
        Step(
            key="range",
            title="Declare the range",
            why="Your team number shapes every address in the exercise, so it comes first.",
            action="Declare it",
            href="/",
            done=estate is not None,
        ),
        Step(
            key="enclaves",
            title="Add the enclaves",
            why="One per firewall you are responsible for. Take them from the annexes.",
            action="Add an enclave",
            href="/range",
            done=bool(firewalls),
        ),
        Step(
            key="interfaces",
            title="Add each firewall's interfaces",
            why="A firewall with no segments behind it has nothing to protect yet.",
            action="Add interfaces",
            href=f"/range?enclave={needs_interfaces[0]}" if needs_interfaces else "/range",
            done=bool(firewalls) and not needs_interfaces,
        ),
        Step(
            key="hosts",
            title="Add the machines",
            why="Rules are written against what is actually on a segment, not the subnet.",
            action="Add machines",
            href=f"/range?enclave={needs_hosts[0]}" if needs_hosts else "/range",
            done=bool(firewalls) and not needs_hosts,
        ),
        Step(
            key="policy",
            title="Declare what each enclave permits",
            why="What must work, and what must not. Everything else is generated from it.",
            action="Declare policy",
            href=f"/range/policy/{needs_policy[0]}" if needs_policy else "/rules",
            done=bool(firewalls) and not needs_policy,
        ),
        Step(
            key="review",
            title="Read the rules and agree they are right",
            why="A person signs this off, in order, one line per rule. "
            "Nothing exports until they do.",
            action="Review the rules",
            href=f"/rules/{needs_review[0]}" if needs_review else "/rules",
            done=bool(firewalls) and not needs_review,
        ),
        Step(
            key="baseline",
            title="Connect to the boxes and take a baseline",
            why="Take it as received, before you harden — it is the only clean "
            "record of what Green Team shipped.",
            action="Test and baseline",
            href="/monitor/setup",
            done=bool(nodes) and not needs_baseline,
        ),
        Step(
            key="watch",
            title="Watch for change",
            why="From here the tool runs itself. Keep the unreviewed count at zero.",
            action="Open the monitor",
            href="/monitor",
            # Never "done" — it is the steady state, not a task.
            done=False,
        ),
    ]
    return tuple(steps)


def next_step(steps: tuple[Step, ...]) -> Step:
    """The first thing not yet done. The steady state when everything is."""
    for step in steps:
        if not step.done:
            return step
    return steps[-1]
