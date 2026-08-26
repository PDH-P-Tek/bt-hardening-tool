"""Shift handover and digest — `MONITORING.md` §10.9.

An exercise runs across shifts, and the expensive failure is not a missed alert: it is
an alert that was seen, half-understood, and never written down, so the next shift
starts from the dashboard rather than from what the last shift already worked out.

So the handover is built from the triage state the operator has already produced. What
is flagged and why, what was accepted and by implication no longer interesting, and
what has not been looked at yet. No new judgement, no new severity — anything that
needed a decision was decided at triage.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from btht.app.monitor.items import ReviewState
from btht.app.monitor.store import Store


@dataclass(frozen=True, slots=True)
class Digest:
    hosts: int = 0
    unreachable: tuple[str, ...] = ()
    unreviewed: int = 0
    flagged: int = 0
    accepted: int = 0
    suppressed: int = 0

    @property
    def quiet(self) -> bool:
        return not self.unreachable and not self.unreviewed and not self.flagged


def digest_for(store: Store) -> Digest:
    """Counts for the dashboard and the metrics endpoint.

    `unreviewed` counts items that have **changed** and not been triaged, not every
    item sitting quietly at its baseline. Counting the latter would report a healthy
    estate as having hundreds of things outstanding, which is the same noise problem
    the triage model exists to avoid — one number nobody can act on.
    """
    counts = {state: 0 for state in ReviewState}
    for row in store.items():
        state = ReviewState(row["review_state"])
        if state is ReviewState.UNREVIEWED and row["baseline_value"] == row["current_value"]:
            continue
        counts[state] += 1
    beats = store.heartbeats()
    return Digest(
        hosts=len(beats),
        unreachable=tuple(str(b["host"]) for b in beats if not b["reachable"]),
        unreviewed=counts[ReviewState.UNREVIEWED],
        flagged=counts[ReviewState.FLAGGED],
        accepted=counts[ReviewState.ACCEPTED],
        suppressed=counts[ReviewState.SUPPRESSED],
    )


def handover(store: Store, shift: str = "") -> str:
    """The report the next shift reads first. Markdown, so it pastes anywhere."""
    summary = digest_for(store)
    stamp = datetime.now(UTC).isoformat(timespec="minutes")
    lines = [
        f"# Shift handover — {stamp}" + (f" · {shift}" if shift else ""),
        "",
        f"{summary.hosts} host(s) monitored.",
        "",
    ]

    if summary.unreachable:
        lines += [
            "## Not answering",
            "",
            "A host that stops answering is itself an alarm — it does not need a "
            "separate alert to matter.",
            "",
        ]
        lines += [f"- **{host}**" for host in summary.unreachable]
        lines += [""]

    flagged = store.worklist()
    lines += ["## Being dealt with", ""]
    if flagged:
        lines += [
            "Flagged by the previous shift. Each of these was judged *not us*, and each "
            "has stopped re-alerting so it does not drown the next thing.",
            "",
        ]
        for row in flagged:
            lines += [
                f"- **{row['host']} · {row['label']}** ({row['collector']})",
                f"  - was: `{row['baseline_value']}`",
                f"  - now: `{row['current_value']}`",
                f"  - note: {row['note'] or '(none written — ask whoever flagged it)'}",
            ]
    else:
        lines += ["Nothing flagged.", ""]
    lines += [""]

    unreviewed = [r for r in store.items() if r["review_state"] == ReviewState.UNREVIEWED.value]
    changed = [r for r in unreviewed if r["baseline_value"] != r["current_value"]]
    lines += ["## Waiting for a decision", ""]
    if changed:
        lines += [f"{len(changed)} item(s) have changed and nobody has triaged them yet.", ""]
        for row in changed[:20]:
            lines += [f"- {row['host']} · {row['label']} ({row['collector']})"]
        if len(changed) > 20:
            lines += [f"- …and {len(changed) - 20} more"]
    else:
        lines += ["Nothing outstanding.", ""]
    lines += [""]

    if summary.suppressed:
        lines += [
            "## Suppressed",
            "",
            f"{summary.suppressed} item(s) are suppressed and will not appear again. "
            "Worth re-reading their notes once a shift — a suppression made at 2am for "
            "a good reason can outlive the reason.",
            "",
        ]

    return "\n".join(lines)


def metrics(store: Store) -> str:
    """Prometheus text format, for a team that already has somewhere to put it."""
    summary = digest_for(store)
    return "\n".join(
        [
            "# HELP btht_hosts_monitored Hosts in the monitored inventory.",
            "# TYPE btht_hosts_monitored gauge",
            f"btht_hosts_monitored {summary.hosts}",
            "# HELP btht_hosts_unreachable Hosts that did not answer the last poll.",
            "# TYPE btht_hosts_unreachable gauge",
            f"btht_hosts_unreachable {len(summary.unreachable)}",
            "# HELP btht_items_unreviewed Changed items nobody has triaged.",
            "# TYPE btht_items_unreviewed gauge",
            f"btht_items_unreviewed {summary.unreviewed}",
            "# HELP btht_items_flagged Items judged not-us and being dealt with.",
            "# TYPE btht_items_flagged gauge",
            f"btht_items_flagged {summary.flagged}",
            "",
        ]
    )
