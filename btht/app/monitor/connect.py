"""Proving the monitor can reach a box — `MONITORING.md` §7, step S6.

The requirement is precise and worth restating: this must name the **specific** failure.
"Connection failed" sends an operator to check the network when the real problem was a
key in the wrong place, and on a range day that costs an hour of the one thing nobody
has. So every outcome below maps to a different thing to go and do.

It is also the honest moment to discover that the read-only account cannot read what
the adapter needs. Better here, deliberately, than as a silently empty collection that
reads on the dashboard as "nothing has changed".
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from btht.app.model.estate import Node
from btht.app.monitor.scheduler import Credentials, transport_for
from btht.app.monitor.transport import Transport, TransportError


class Outcome(StrEnum):
    OK = "ok"
    UNRESOLVED = "unresolved"
    REFUSED = "refused"
    TIMEOUT = "timeout"
    HOST_KEY = "host_key"
    AUTH = "auth"
    PERMISSION = "permission"
    MISSING_COMMAND = "missing_command"
    UNKNOWN = "unknown"


#: What each outcome means and what to do about it. The remedy is the point — an
#: operator reading this at 0300 needs the next action, not a diagnosis to interpret.
ADVICE: dict[Outcome, tuple[str, str]] = {
    Outcome.OK: ("Reachable, and the read-only account can read what the collector needs.", ""),
    Outcome.UNRESOLVED: (
        "The name or address did not resolve.",
        "Check the management address on the Range page — this is not a credentials problem.",
    ),
    Outcome.REFUSED: (
        "The box answered and refused the connection.",
        "SSH is not listening, or a firewall rule on the box is dropping the management "
        "path. Check the box's own rules before touching the key.",
    ),
    Outcome.TIMEOUT: (
        "No answer before the timeout.",
        "The box is down, or nothing routes to the management address from here.",
    ),
    Outcome.HOST_KEY: (
        "The host key did not match what is in known_hosts.",
        "Treat this as suspicious until proved otherwise — a changed host key on a "
        "managed box during an exercise is exactly what a rebuild or an interception "
        "looks like. Verify out of band before accepting it.",
    ),
    Outcome.AUTH: (
        "The box answered but rejected the key.",
        "The monitor's public key is not in the read-only account's authorized_keys, "
        "or the account does not exist on this box.",
    ),
    Outcome.PERMISSION: (
        "Logged in, but the account cannot read what the collector needs.",
        "Grant the read-only account read access to the configuration it collects. Do "
        "not grant it write access — the monitor never needs it.",
    ),
    Outcome.MISSING_COMMAND: (
        "Logged in, but a command the collector depends on is not on this box.",
        "Check the platform is set correctly on the Range page. A Linux adapter pointed "
        "at a pfSense box fails exactly like this.",
    ),
    Outcome.UNKNOWN: ("The connection failed for a reason the tool did not recognise.", ""),
}


@dataclass(frozen=True, slots=True)
class Probe:
    """One box, tested."""

    node: str
    outcome: Outcome
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.outcome is Outcome.OK

    @property
    def meaning(self) -> str:
        return ADVICE[self.outcome][0]

    @property
    def remedy(self) -> str:
        return ADVICE[self.outcome][1]


def classify(text: str, exit_code: int) -> Outcome:
    """Read the specific failure out of what SSH actually said."""
    low = text.lower()
    if "host key verification failed" in low or "remote host identification has changed" in low:
        return Outcome.HOST_KEY
    if "permission denied" in low and "publickey" in low:
        return Outcome.AUTH
    if "could not resolve" in low or "name or service not known" in low:
        return Outcome.UNRESOLVED
    if "connection refused" in low:
        return Outcome.REFUSED
    if "timed out" in low or "timeout" in low or "no route to host" in low:
        return Outcome.TIMEOUT
    if "command not found" in low or "not found" in low and exit_code == 127:
        return Outcome.MISSING_COMMAND
    if "permission denied" in low or "operation not permitted" in low:
        return Outcome.PERMISSION
    if exit_code == 0:
        return Outcome.OK
    return Outcome.UNKNOWN


#: Harmless, read-only, and present on every platform the tool manages.
PROBE_COMMAND = "uname -a"


def probe(node: Node, credentials: Credentials, transport: Transport | None = None) -> Probe:
    """Test one box. Never raises — an operator running this wants a verdict, not a stack."""
    link = transport_for(node, credentials) if transport is None else transport
    try:
        result = link.run(PROBE_COMMAND)
    except TransportError as exc:
        return Probe(node=node.name, outcome=classify(str(exc), 255), detail=str(exc))
    except Exception as exc:  # noqa: BLE001 - a probe reports, it does not propagate
        return Probe(node=node.name, outcome=Outcome.UNKNOWN, detail=str(exc))
    text = f"{result.stderr}\n{result.stdout}".strip()
    outcome = classify(text, result.exit_code)
    return Probe(node=node.name, outcome=outcome, detail=text[:400])
