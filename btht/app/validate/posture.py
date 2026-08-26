"""Posture checks — `HARDENING.md`. Phase 7.

Different question from drift. The monitor asks *has this changed*; these ask *is this
right*, whether or not anybody touched it. Same collected item set, two evaluations —
one collection, and the adapters are written once.

**They show remediation and never apply it.** Same rule as the monitor, for the same
reason: a tool that can fix a firewall is a tool that holds a credential which can
break one.

Ordering is not by ID. `HARDENING.md` §4 orders the *operator's* day by risk of doing
things in the wrong order, and steps 0–4 are the ones that go wrong — console access
confirmed, management rules in place and *verified*, and only then anti-lockout
disabled. That sequence belongs to the operator; this module reports state.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum

from btht.app.monitor.items import Item


class Result(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    NOT_APPLICABLE = "not_applicable"
    UNKNOWN = "unknown"
    """The collection did not include what this check needs. Not a pass."""


@dataclass(frozen=True, slots=True)
class Check:
    id: str
    title: str
    result: Result
    detail: str = ""
    remediation: str = ""
    """What a human would do. Shown, never run."""

    scoring_risk: str = ""
    """Whether doing this could cost points. `HARDENING.md` orders by it."""


def _by_collector(items: Iterable[Item], collector: str) -> list[Item]:
    return [i for i in items if i.collector == collector]


def _sshd(items: Iterable[Item]) -> dict[str, str]:
    settings: dict[str, str] = {}
    for item in items:
        if item.collector != "H-SSH-CONFIG":
            continue
        name, _, value = item.value.partition(" ")
        settings[name.lower()] = value.strip()
    return settings


def check_ssh(items: Iterable[Item]) -> list[Check]:
    """`H-SSH-*`. Read from `sshd -T`, so `Include` and `Match` resolve.

    Hashing `sshd_config` alone misses anything in an included file — which is both a
    correctness point and where somebody would hide a change.
    """
    settings = _sshd(items)
    if not settings:
        return [
            Check(
                "H-SSH-01",
                "SSH configuration collected",
                Result.UNKNOWN,
                "sshd -T was not collected, so nothing about SSH can be asserted.",
                "Add the sshd collector, then re-run.",
            )
        ]

    out = []
    password_auth = settings.get("passwordauthentication", "yes")
    out.append(
        Check(
            "H-SSH-02",
            "Password authentication disabled",
            Result.PASS if password_auth == "no" else Result.FAIL,
            f"PasswordAuthentication {password_auth}",
            "Set PasswordAuthentication no, after confirming key access works from a "
            "second session that is already open.",
            scoring_risk="none",
        )
    )
    root_login = settings.get("permitrootlogin", "yes")
    out.append(
        Check(
            "H-SSH-03",
            "Root login restricted",
            Result.PASS if root_login in ("no", "prohibit-password") else Result.FAIL,
            f"PermitRootLogin {root_login}",
            "Set PermitRootLogin no, or prohibit-password where a key is needed.",
            scoring_risk="none",
        )
    )
    log_level = settings.get("loglevel", "INFO").upper()
    out.append(
        Check(
            "H-SSH-20",
            "Verbose logging, so key use is attributable",
            Result.PASS if log_level == "VERBOSE" else Result.FAIL,
            f"LogLevel {log_level}",
            "Set LogLevel VERBOSE. Without it the log records that a key was used but "
            "not which one, which is the question you will be asking afterwards.",
            scoring_risk="none",
        )
    )
    return out


def check_accounts(items: Iterable[Item]) -> list[Check]:
    """`H-ACC-*`. Sudo grants that are specific rather than blanket."""
    out = []
    blanket = [
        item
        for item in _by_collector(items, "M-ACC-08")
        if "NOPASSWD: ALL" in item.value and not item.value.startswith("#")
    ]
    out.append(
        Check(
            "H-ACC-05",
            "Sudo grants are specific, not blanket",
            Result.PASS if not blanket else Result.FAIL,
            "; ".join(i.value for i in blanket) or "no blanket NOPASSWD grants",
            "Narrow each grant to the command it needs. A NOPASSWD: ALL line dropped "
            "into sudoers.d is trivial to miss by eye and is full root without a "
            "password.",
            scoring_risk="none",
        )
    )

    unlocked = [
        item
        for item in items
        if item.key.startswith("password:") and item.value.startswith("set:")
    ]
    out.append(
        Check(
            "H-ACC-02",
            "Accounts with a usable password are accounted for",
            Result.PASS if len(unlocked) <= 2 else Result.FAIL,
            f"{len(unlocked)} account(s) with a password set",
            "Confirm each one is meant to have interactive access; lock the rest.",
            scoring_risk="low",
        )
    )
    return out


def check_firewall(items: Iterable[Item]) -> list[Check]:
    """`H-FW-*` and `H-PF-*`. The findings from the evidence, restated as live checks."""
    out = []

    antilockout = next((i for i in items if i.key == "pf:antilockout"), None)
    if antilockout is not None:
        out.append(
            Check(
                "H-PF-01",
                "Anti-lockout disabled, with management rules proven first",
                Result.PASS if antilockout.value == "disabled" else Result.FAIL,
                f"anti-lockout {antilockout.value}",
                "This is the single highest-lockout-risk change in the document, and "
                "it is also what makes a management restriction real. Do it only after "
                "the management rule is verified from a second session, and keep that "
                "session open. Whether the exercise permits it at all is HARDENING H-Q4.",
                scoring_risk="none",
            )
        )

    permissive = [
        item
        for item in items
        if item.collector == "M-FW-01" and "descr=" in item.value and item.value.endswith("descr=")
    ]
    out.append(
        Check(
            "H-FW-02",
            "No undescribed pass rules",
            Result.PASS if not permissive else Result.FAIL,
            f"{len(permissive)} rule(s) with no description",
            "Give every rule a description. With filter descriptions on, that string "
            "names the rule in the log, which is how the team debugs at speed.",
            scoring_risk="none",
        )
    )

    listening = [i for i in items if i.collector == "M-SVC-01"]
    plaintext = [i for i in listening if ":23" in i.value or ":161" in i.value]
    out.append(
        Check(
            "H-PF-05",
            "No unauthenticated management services listening",
            Result.PASS if not plaintext else Result.FAIL,
            "; ".join(i.value for i in plaintext) or "none listening",
            "Turn off telnet and SNMP. Fast, low risk, high value — and the observed "
            "estate shipped SNMP with the community string still public.",
            scoring_risk="low",
        )
    )
    return out


def check_routing(items: Iterable[Item]) -> list[Check]:
    """`H-FRR-*`. Scoping depends on `HARDENING.md` H-Q2, which is still open."""
    logins = [i for i in items if i.collector == "M-RT-01" and i.value.startswith("username ")]
    weak = [i for i in logins if "nopassword" in i.value]
    if not logins:
        return [
            Check(
                "H-FRR-01",
                "Router VTY access",
                Result.UNKNOWN,
                "No routing configuration collected.",
                "Add the FRR collector for this host.",
            )
        ]
    return [
        Check(
            "H-FRR-02",
            "Router logins require a password",
            Result.PASS if not weak else Result.FAIL,
            "; ".join(i.value for i in weak) or "all logins require a password",
            "Set a password on each VTY login. Which daemons expose a VTY port at all "
            "is HARDENING H-Q2 and needs a look at a live router.",
            scoring_risk="medium",
        )
    ]


def run_posture(items: Iterable[Item]) -> tuple[Check, ...]:
    """Every check, over one collected item set. Ordered by ID for stable output."""
    collected = list(items)
    checks: list[Check] = []
    for group in (check_ssh, check_accounts, check_firewall, check_routing):
        checks.extend(group(collected))
    return tuple(sorted(checks, key=lambda c: c.id))


def failing(checks: tuple[Check, ...]) -> tuple[Check, ...]:
    return tuple(c for c in checks if c.result is Result.FAIL)


def unknown(checks: tuple[Check, ...]) -> tuple[Check, ...]:
    """Checks that could not be evaluated. **Not passes** — silence is not health."""
    return tuple(c for c in checks if c.result is Result.UNKNOWN)
