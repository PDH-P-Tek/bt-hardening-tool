"""What the monitor watches — `MONITORING.md` §3.3, §3.4, §4.

Two ideas carry this module, and getting either wrong makes the tool worse than not
having one.

**Config is diffed; state is never diffed.** Rules, accounts, keys, sudoers, cron, units
and routing *definitions* are config: baseline them, alert on any change, deletions
included. Connection tables, counters, routing tables, neighbour up/down, leases and
uptime are state: display them, never alert. Get it backwards and it cries wolf every
sixty seconds, the operator learns to dismiss it, and the alarm that mattered goes with
the rest.

**Nothing secret is retained.** The monitor deliberately reads accounts and
authentication material, which makes it a liability if it stores what it sees. So a
password hash becomes a keyed digest that can only answer "did this change", an
authorised key becomes its fingerprint and options, and a private key is never read at
all. A monitoring tool holding the estate's credentials is a worse problem than the one
it solves.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from enum import StrEnum


class Kind(StrEnum):
    CONFIG = "config"
    """Intended to be stable. Diffed strictly; any change is a finding."""

    STATE = "state"
    """Expected to churn. Displayed, thresholded if useful, never diffed."""


class ReviewState(StrEnum):
    UNREVIEWED = "unreviewed"
    ACCEPTED = "accepted"
    """That was us. Promotes current to baseline."""

    FLAGGED = "flagged"
    """That was not us, and I am dealing with it. Stays on the worklist and stops
    re-alerting every cycle."""

    SUPPRESSED = "suppressed"
    """Accept with prejudice, for a known-noisy item. Requires a note."""


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True, slots=True)
class Item:
    """One monitored thing, with an identity stable across polls.

    The identity key is what makes triage work at item level rather than host level.
    If accepting one change re-surfaces the other nine, the operator stops using
    accept and the whole model collapses — `MONITORING.md` §3.4.
    """

    key: str
    collector: str
    """The `M-*` ID this came from, so a finding can be traced to its definition."""

    kind: Kind
    value: str
    severity: Severity = Severity.MEDIUM
    label: str = ""

    def __post_init__(self) -> None:
        if not self.key:
            raise ValueError("an item without a stable key cannot be triaged")


def digest(secret: str, value: str) -> str:
    """A keyed digest of something that must never be stored.

    Answers "did this change" and nothing else. Keyed rather than plain so the stored
    values are not a rainbow-table exercise if the database is taken — the monitor is
    read-only, but its database still describes the estate.
    """
    return hmac.new(secret.encode(), value.encode(), hashlib.sha256).hexdigest()[:32]


def key_fingerprint(key_body: str) -> str:
    """The SHA256 fingerprint OpenSSH shows, from the base64 body. Never the body."""
    import base64

    try:
        raw = base64.b64decode(key_body, validate=True)
    except Exception:  # noqa: BLE001 - malformed key material is data, not an error
        return "unreadable"
    return "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")


@dataclass(frozen=True, slots=True)
class Collection:
    """One poll of one host."""

    host: str
    items: tuple[Item, ...] = ()
    reachable: bool = True
    error: str = ""

    def config_items(self) -> tuple[Item, ...]:
        return tuple(i for i in self.items if i.kind is Kind.CONFIG)

    def state_items(self) -> tuple[Item, ...]:
        return tuple(i for i in self.items if i.kind is Kind.STATE)
