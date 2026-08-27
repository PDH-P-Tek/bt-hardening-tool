"""The item store and the diff engine — `MONITORING.md` §3.4, §10.3.

Detection is the easy half. **The triage model is what decides whether this reduces
fatigue or becomes it**, so the design point is that accept, flag and suppress work at
*item* level. If accepting one change re-surfaces the other nine, the operator stops
using accept and the tool is dead.

- **Accept** promotes the current value to baseline. "That was us."
- **Flag** keeps it on the worklist and stops it re-alerting every cycle. "That was not
  us, and I am dealing with it."
- **Suppress** is accept-with-prejudice for a known-noisy item, and requires a note.

State items never enter the diff at all — they are stored for display and skipped, per
`items.Kind`.
"""

from __future__ import annotations

import secrets
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from btht.app.monitor.items import Collection, Kind, ReviewState, Severity

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (name TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS items (
    host TEXT NOT NULL,
    key TEXT NOT NULL,
    collector TEXT NOT NULL,
    kind TEXT NOT NULL,
    label TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL DEFAULT 'medium',
    baseline_value TEXT,
    current_value TEXT,
    review_state TEXT NOT NULL DEFAULT 'unreviewed',
    note TEXT NOT NULL DEFAULT '',
    first_seen TEXT NOT NULL,
    last_changed TEXT NOT NULL,
    PRIMARY KEY (host, key)
);
CREATE TABLE IF NOT EXISTS heartbeats (
    host TEXT PRIMARY KEY,
    last_seen TEXT,
    reachable INTEGER NOT NULL DEFAULT 1,
    error TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS snapshots (
    host TEXT NOT NULL,
    kind TEXT NOT NULL,
    key TEXT NOT NULL,
    collector TEXT NOT NULL DEFAULT '',
    label TEXT NOT NULL DEFAULT '',
    value TEXT,
    taken_at TEXT NOT NULL,
    PRIMARY KEY (host, kind, key)
);
"""


class BaselineKind(StrEnum):
    """`MONITORING.md` S7 — two baselines, and the first one is the one people skip.

    **As received** is what Green Team shipped, before anyone touched it. Taking only
    the hardened baseline throws it away permanently, and with it the ability to answer
    "was that us, or was it always like that?" — which is the question that comes up
    every time something breaks.
    """

    AS_RECEIVED = "as_received"
    HARDENED = "hardened"


class ChangeKind(StrEnum):
    ADDED = "added"
    REMOVED = "removed"
    """A deletion is a change. It is the one least likely to be caught by eye."""

    CHANGED = "changed"


@dataclass(frozen=True, slots=True)
class Change:
    host: str
    key: str
    kind: str
    collector: str
    label: str
    severity: Severity
    before: str = ""
    after: str = ""
    review_state: ReviewState = ReviewState.UNREVIEWED

    @property
    def needs_attention(self) -> bool:
        """Flagged items stay on the worklist without re-alerting every cycle."""
        return self.review_state is ReviewState.UNREVIEWED


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


class Store:
    """SQLite. Working data, never source — gitignored, and it describes the estate."""

    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.connection.executescript(SCHEMA)
        self._ensure_secret()

    def _ensure_secret(self) -> None:
        """A per-store key for digesting things that must never be stored verbatim."""
        row = self.connection.execute("SELECT value FROM meta WHERE name = 'digest_key'").fetchone()
        if row is None:
            self.connection.execute(
                "INSERT INTO meta (name, value) VALUES ('digest_key', ?)",
                (secrets.token_hex(16),),
            )
            self.connection.commit()

    @property
    def secret(self) -> str:
        row = self.connection.execute("SELECT value FROM meta WHERE name = 'digest_key'").fetchone()
        return str(row["value"])

    def close(self) -> None:
        self.connection.close()

    # --- polling -----------------------------------------------------------

    def record_heartbeat(self, collection: Collection) -> None:
        """A host that stops answering is already a visible alarm — `MONITORING.md` §3.1."""
        self.connection.execute(
            "INSERT INTO heartbeats (host, last_seen, reachable, error) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(host) DO UPDATE SET last_seen=excluded.last_seen, "
            "reachable=excluded.reachable, error=excluded.error",
            (collection.host, _now(), int(collection.reachable), collection.error),
        )
        self.connection.commit()

    def adopt_baseline(
        self, collection: Collection, kind: BaselineKind = BaselineKind.AS_RECEIVED
    ) -> None:
        """Take a collection as known-good, and keep a copy of it under `kind`.

        The live `items.baseline_value` is what the diff compares against and moves as
        changes are accepted. The snapshot does not move — it is the record of what the
        box looked like at that moment, and it is the only way to answer later whether
        something was Green Team's or ours.
        """
        now = _now()
        for item in collection.items:
            self.connection.execute(
                "INSERT INTO snapshots (host, kind, key, collector, label, value, taken_at) "
                "VALUES (?,?,?,?,?,?,?) "
                "ON CONFLICT(host, kind, key) DO UPDATE SET value=excluded.value, "
                "taken_at=excluded.taken_at",
                (
                    collection.host,
                    kind.value,
                    item.key,
                    item.collector,
                    item.label,
                    item.value,
                    now,
                ),
            )
        for item in collection.items:
            self.connection.execute(
                "INSERT INTO items (host, key, collector, kind, label, severity, "
                "baseline_value, current_value, first_seen, last_changed) "
                "VALUES (?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(host, key) DO UPDATE SET baseline_value=excluded.baseline_value, "
                "current_value=excluded.current_value",
                (
                    collection.host,
                    item.key,
                    item.collector,
                    item.kind.value,
                    item.label,
                    item.severity.value,
                    item.value,
                    item.value,
                    now,
                    now,
                ),
            )
        self.connection.commit()

    def apply(self, collection: Collection) -> tuple[Change, ...]:
        """Compare a collection against the baseline and return what changed.

        **State items are skipped entirely.** They are stored for display and never
        produce a change, because a counter that moves every poll is not news.
        """
        self.record_heartbeat(collection)
        if not collection.reachable:
            return ()

        now = _now()
        changes: list[Change] = []
        seen: set[str] = set()

        for item in collection.items:
            seen.add(item.key)
            row = self.connection.execute(
                "SELECT * FROM items WHERE host = ? AND key = ?", (collection.host, item.key)
            ).fetchone()

            if row is None:
                self.connection.execute(
                    "INSERT INTO items (host, key, collector, kind, label, severity, "
                    "baseline_value, current_value, first_seen, last_changed) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (
                        collection.host,
                        item.key,
                        item.collector,
                        item.kind.value,
                        item.label,
                        item.severity.value,
                        None,
                        item.value,
                        now,
                        now,
                    ),
                )
                if item.kind is Kind.CONFIG:
                    changes.append(
                        Change(
                            host=collection.host,
                            key=item.key,
                            kind=ChangeKind.ADDED,
                            collector=item.collector,
                            label=item.label,
                            severity=item.severity,
                            after=item.value,
                        )
                    )
                continue

            self.connection.execute(
                "UPDATE items SET current_value = ? WHERE host = ? AND key = ?",
                (item.value, collection.host, item.key),
            )
            if item.kind is Kind.STATE:
                continue
            if row["baseline_value"] != item.value:
                state = ReviewState(row["review_state"])
                if row["current_value"] != item.value:
                    self.connection.execute(
                        "UPDATE items SET last_changed = ? WHERE host = ? AND key = ?",
                        (now, collection.host, item.key),
                    )
                if state is not ReviewState.SUPPRESSED:
                    changes.append(
                        Change(
                            host=collection.host,
                            key=item.key,
                            kind=ChangeKind.CHANGED,
                            collector=item.collector,
                            label=item.label,
                            severity=item.severity,
                            before=str(row["baseline_value"]),
                            after=item.value,
                            review_state=state,
                        )
                    )

        for row in self.connection.execute(
            "SELECT * FROM items WHERE host = ? AND kind = 'config'", (collection.host,)
        ).fetchall():
            if row["key"] in seen or row["baseline_value"] is None:
                continue
            state = ReviewState(row["review_state"])
            if state is ReviewState.SUPPRESSED:
                continue
            changes.append(
                Change(
                    host=collection.host,
                    key=row["key"],
                    kind=ChangeKind.REMOVED,
                    collector=row["collector"],
                    label=row["label"],
                    severity=Severity(row["severity"]),
                    before=str(row["baseline_value"]),
                    review_state=state,
                )
            )

        self.connection.commit()
        return tuple(changes)

    # --- triage ------------------------------------------------------------

    def accept(self, host: str, key: str, note: str = "") -> None:
        """That was us. The current value becomes the baseline, for this item only."""
        self.connection.execute(
            "UPDATE items SET baseline_value = current_value, review_state = ?, note = ? "
            "WHERE host = ? AND key = ?",
            (ReviewState.ACCEPTED.value, note, host, key),
        )
        self.connection.commit()

    def flag(self, host: str, key: str, note: str = "") -> None:
        """That was not us. Stays on the worklist; stops re-alerting every cycle."""
        self.connection.execute(
            "UPDATE items SET review_state = ?, note = ? WHERE host = ? AND key = ?",
            (ReviewState.FLAGGED.value, note, host, key),
        )
        self.connection.commit()

    def suppress(self, host: str, key: str, note: str) -> None:
        """Known-noisy. A note is mandatory — an unexplained silence is worse than noise."""
        if not note.strip():
            raise ValueError("suppressing an item requires a note saying why")
        self.connection.execute(
            "UPDATE items SET baseline_value = current_value, review_state = ?, note = ? "
            "WHERE host = ? AND key = ?",
            (ReviewState.SUPPRESSED.value, note, host, key),
        )
        self.connection.commit()

    # --- reading -----------------------------------------------------------

    def items(self, host: str = "") -> list[sqlite3.Row]:
        if host:
            return list(
                self.connection.execute("SELECT * FROM items WHERE host = ? ORDER BY key", (host,))
            )
        return list(self.connection.execute("SELECT * FROM items ORDER BY host, key"))

    def heartbeats(self) -> list[sqlite3.Row]:
        return list(self.connection.execute("SELECT * FROM heartbeats ORDER BY host"))

    def worklist(self) -> list[sqlite3.Row]:
        """Flagged items. What someone is still dealing with."""
        return list(
            self.connection.execute(
                "SELECT * FROM items WHERE review_state = ? ORDER BY host, key",
                (ReviewState.FLAGGED.value,),
            )
        )

    # --- what the dashboard reads — `MONITORING.md` §8.2 -------------------

    #: An item is *outstanding* when it has drifted from its baseline and nobody has
    #: decided about it yet. Accepting moves the baseline, so an accepted item leaves
    #: this set on its own — there is no separate "cleared" flag to get out of step.
    _OUTSTANDING = (
        "review_state = 'unreviewed' AND kind = 'config' "
        "AND IFNULL(baseline_value, '') != IFNULL(current_value, '')"
    )

    #: Worst first, always. Ordering by time buries a critical under a morning of noise.
    _BY_SEVERITY = (
        "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 "
        "WHEN 'low' THEN 3 ELSE 4 END"
    )

    def outstanding(self, host: str = "") -> list[sqlite3.Row]:
        """Everything still awaiting a decision, worst first."""
        where = self._OUTSTANDING + (" AND host = ?" if host else "")
        return list(
            self.connection.execute(
                f"SELECT * FROM items WHERE {where} "
                f"ORDER BY {self._BY_SEVERITY}, last_changed DESC",
                (host,) if host else (),
            )
        )

    def unreviewed_count(self) -> int:
        """The number that dominates the dashboard. Zero means stop looking."""
        row = self.connection.execute(
            f"SELECT COUNT(*) AS n FROM items WHERE {self._OUTSTANDING}"
        ).fetchone()
        return int(row["n"])

    def host_summary(self) -> list[sqlite3.Row]:
        """One row per host: what is outstanding on it and how bad the worst of it is.

        This is the estate view. A tile per host, coloured by its worst unreviewed
        finding — not by how many, because ten low-severity account changes must never
        outrank one modified firewall rule.
        """
        return list(
            self.connection.execute(
                "SELECT h.host AS host, h.last_seen AS last_seen, h.reachable AS reachable, "
                "h.error AS error, "
                f"(SELECT COUNT(*) FROM items i WHERE i.host = h.host AND {self._OUTSTANDING}) "
                "AS outstanding, "
                "(SELECT COUNT(*) FROM items i WHERE i.host = h.host "
                "AND i.review_state = 'flagged') AS flagged, "
                "(SELECT severity FROM items i WHERE i.host = h.host "
                f"AND {self._OUTSTANDING} ORDER BY {self._BY_SEVERITY} LIMIT 1) AS worst "
                "FROM heartbeats h ORDER BY h.host"
            )
        )

    def item(self, host: str, key: str) -> sqlite3.Row | None:
        row = self.connection.execute(
            "SELECT * FROM items WHERE host = ? AND key = ?", (host, key)
        ).fetchone()
        return None if row is None else row

    def snapshot_value(self, host: str, key: str, kind: BaselineKind) -> str | None:
        """What this item held in one of the two baselines, if it was there at all."""
        row = self.connection.execute(
            "SELECT value FROM snapshots WHERE host = ? AND kind = ? AND key = ?",
            (host, kind.value, key),
        ).fetchone()
        return None if row is None else str(row["value"])

    def baselines_taken(self) -> dict[str, set[str]]:
        """Which baselines exist per host, so setup can say what is still missing."""
        taken: dict[str, set[str]] = {}
        for row in self.connection.execute("SELECT DISTINCT host, kind FROM snapshots"):
            taken.setdefault(str(row["host"]), set()).add(str(row["kind"]))
        return taken

    # --- "changed since I last looked" -------------------------------------

    def last_look(self) -> str:
        row = self.connection.execute("SELECT value FROM meta WHERE name = 'last_look'").fetchone()
        return "" if row is None else str(row["value"])

    def mark_looked(self) -> None:
        """Called when the operator opens the dashboard, not on every page render."""
        self.connection.execute(
            "INSERT INTO meta (name, value) VALUES ('last_look', ?) "
            "ON CONFLICT(name) DO UPDATE SET value=excluded.value",
            (_now(),),
        )
        self.connection.commit()

    def changed_since(self, marker: str) -> list[sqlite3.Row]:
        """What moved since the operator last looked — the handover question."""
        if not marker:
            return []
        return list(
            self.connection.execute(
                f"SELECT * FROM items WHERE last_changed > ? AND {self._OUTSTANDING} "
                f"ORDER BY {self._BY_SEVERITY}, last_changed DESC",
                (marker,),
            )
        )
