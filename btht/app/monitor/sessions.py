"""Who was on the box when it changed.

The tool's purpose is monitoring for **evidence of Red Team activity**, and detecting
change is only half of that. "The management alias gained an address" is a fact; it is
not yet evidence. What turns it into evidence is the session that was open at the time,
the account it used, and the key it authenticated with.

Everything needed was already being collected and never joined. `M-AUTH-01` inventories
the authorised keys on every box. `H-SSH-19` exists precisely so that `LogLevel VERBOSE`
records the **key fingerprint** of each successful authentication. Putting those beside
a change's timestamp answers the question an operator actually has: not "did something
change" but "was that us?".

Two honest limits, stated here because a correlation tool that overclaims is worse than
none. **Correlation is not attribution** — an open session at the right moment is a lead,
not proof, and the wording throughout says so. And **logs on a box the attacker controls
are evidence the attacker controls**, which is why `H-SSH-20` asks for remote syslog and
why a *missing* session for a real change is itself worth noticing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

#: `last -F` gives full timestamps, which is the whole reason for the flag: without it
#: the year is missing and a session cannot be placed against an ISO change time.
LAST_LINE = re.compile(
    r"^(?P<user>\S+)\s+(?P<tty>\S+)\s+(?P<source>\S+)\s+"
    r"(?P<start>\w{3}\s+\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\d{4})"
    r"(?:\s+-\s+(?P<end>\w{3}\s+\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\d{4}))?"
    r"(?P<still>\s+still\s+(?:logged\s+in|running))?"
)

#: sshd at LogLevel VERBOSE. The fingerprint at the end is the valuable part.
ACCEPTED = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2}).*?"
    r"Accepted\s+(?P<method>\S+)\s+for\s+(?P<user>\S+)\s+from\s+(?P<source>\S+)"
    r"(?:\s+port\s+\d+)?(?:\s+\S+)?(?::\s+\S+\s+(?P<fingerprint>SHA256:\S+))?"
)

#: Accounts that log in as part of the machine working, not as a person doing something.
ROUTINE = frozenset({"reboot", "shutdown", "runlevel", "wtmp"})


@dataclass(frozen=True, slots=True)
class Session:
    """One login. `ended` empty means still open."""

    user: str
    source: str
    started: str
    ended: str = ""
    tty: str = ""
    fingerprint: str = ""
    method: str = ""

    @property
    def open_ended(self) -> bool:
        return not self.ended

    def describe(self) -> str:
        when = f"{self.started} → {self.ended or 'still open'}"
        who = f"{self.user}@{self.source}" if self.source else self.user
        key = f", key {self.fingerprint}" if self.fingerprint else ""
        return f"{who} ({when}){key}"


def _iso(stamp: str) -> str:
    """`Wed Aug 27 14:31:02 2026` → ISO. Empty when it will not parse."""
    try:
        return datetime.strptime(stamp, "%a %b %d %H:%M:%S %Y").replace(tzinfo=UTC).isoformat()
    except ValueError:
        return ""


def parse_last(output: str) -> tuple[Session, ...]:
    """Login records from `last -F`."""
    out: list[Session] = []
    for line in output.splitlines():
        match = LAST_LINE.match(line.strip())
        if match is None:
            continue
        user = match.group("user")
        if user in ROUTINE:
            continue
        started = _iso(match.group("start"))
        if not started:
            continue
        end_raw = match.group("end")
        out.append(
            Session(
                user=user,
                source=match.group("source"),
                started=started,
                ended=_iso(end_raw) if end_raw else "",
                tty=match.group("tty"),
            )
        )
    return tuple(out)


def parse_accepted(output: str, year: int | None = None) -> tuple[Session, ...]:
    """Successful authentications, with the key fingerprint where sshd logged one.

    The syslog line carries no year, so one is supplied. During an exercise that is
    always the current year; getting it wrong shifts a correlation window rather than
    inventing one, which is the safer direction to be wrong in.
    """
    year = datetime.now(UTC).year if year is None else year
    out: list[Session] = []
    for line in output.splitlines():
        match = ACCEPTED.search(line)
        if match is None:
            continue
        try:
            when = datetime.strptime(
                f"{match.group('month')} {match.group('day')} {match.group('time')} {year}",
                "%b %d %H:%M:%S %Y",
            ).replace(tzinfo=UTC)
        except ValueError:
            continue
        out.append(
            Session(
                user=match.group("user"),
                source=match.group("source"),
                started=when.isoformat(),
                fingerprint=match.group("fingerprint") or "",
                method=match.group("method") or "",
            )
        )
    return tuple(out)


def merge(logins: tuple[Session, ...], accepted: tuple[Session, ...]) -> tuple[Session, ...]:
    """Attach fingerprints from the auth log to the matching `last` records.

    Matched on account, source and a start time within a minute — `last` and syslog
    record the same login a second or two apart. An unmatched authentication is kept
    rather than dropped: a login sshd recorded and `wtmp` did not is itself interesting.
    """
    out: list[Session] = []
    used: set[int] = set()
    for login in logins:
        best: Session | None = None
        for index, auth in enumerate(accepted):
            if index in used or auth.user != login.user or auth.source != login.source:
                continue
            if abs(_seconds(auth.started) - _seconds(login.started)) <= 60:
                best = auth
                used.add(index)
                break
        out.append(
            Session(
                user=login.user,
                source=login.source,
                started=login.started,
                ended=login.ended,
                tty=login.tty,
                fingerprint=best.fingerprint if best else "",
                method=best.method if best else "",
            )
        )
    out.extend(auth for index, auth in enumerate(accepted) if index not in used)
    return tuple(sorted(out, key=lambda s: s.started, reverse=True))


def _seconds(iso: str) -> float:
    try:
        return datetime.fromisoformat(iso).timestamp()
    except ValueError:
        return 0.0


def around(
    sessions: tuple[Session, ...], when: str, *, window: timedelta = timedelta(minutes=15)
) -> tuple[Session, ...]:
    """Sessions that could account for a change first seen at `when`.

    A session counts if it was open at that moment, or began shortly before it. The
    lead-in matters: a change is noticed on the next poll, so the login that caused it
    is always a little earlier than the timestamp on the finding.
    """
    moment = _seconds(when)
    if not moment:
        return ()
    out = []
    for session in sessions:
        start = _seconds(session.started)
        end = _seconds(session.ended) if session.ended else float("inf")
        if start - window.total_seconds() <= moment <= end + window.total_seconds():
            out.append(session)
    return tuple(out)


def unknown_keys(sessions: tuple[Session, ...], inventory: frozenset[str]) -> tuple[Session, ...]:
    """Sessions authenticated with a key that is not in the estate's own inventory.

    The strongest single signal this module produces, and the reason `M-AUTH-01` and
    `H-SSH-19` are worth having together. A login with a fingerprint nobody issued is
    not ambiguous.
    """
    return tuple(s for s in sessions if s.fingerprint and s.fingerprint not in inventory)
