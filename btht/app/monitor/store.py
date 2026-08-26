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
"""


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

    def adopt_baseline(self, collection: Collection) -> None:
        """Take the first collection as known-good. `MONITORING.md` S7."""
        now = _now()
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
