"""The collection loop — `MONITORING.md` §3.5.

Three properties, each of which exists because the obvious alternative fails in a way
that is invisible until it matters:

- the **30 second floor** holds whatever a node declares, or the monitor becomes a load
  source on the thing it is watching
- **backoff** is 60 → 120 → 300 and then holds, so a box that is down does not bury the
  one line saying when it went, and is still retried often enough that recovery is noticed
- an **unreachable host is a result, not an exception** — it lands in the store as a
  missed heartbeat, because a silent host is itself the alarm

Nothing here opens a socket. The transport is substituted, which is also how the
"one broken box must not stop the estate" case gets tested rather than hoped about.
"""

from __future__ import annotations

import asyncio
from ipaddress import ip_address
from pathlib import Path

import pytest

from btht.app.model.estate import Estate, Node, Platform
from btht.app.monitor.items import Collection, Item, Kind, Severity
from btht.app.monitor.scheduler import BACKOFF, Credentials, NodeState, Scheduler, collect_once
from btht.app.monitor.store import Store
from btht.app.monitor.transport import CommandResult, TransportError


def a_node(name: str = "r1", poll: int = 60) -> Node:
    return Node(
        name=name,
        platform=Platform.LINUX,
        mgmt_address=ip_address("10.0.0.9"),
        poll_seconds=poll,
    )


def an_estate(*nodes: Node) -> Estate:
    return Estate(team=42, nodes=tuple(nodes))


# --- cadence ----------------------------------------------------------------


def test_the_poll_floor_holds_whatever_a_node_asks_for() -> None:
    """Below 30s the poll cost on pfSense starts to matter — §3.5."""
    # The model refuses a sub-floor interval outright, before the scheduler sees it.
    with pytest.raises(ValueError, match="30s floor"):
        a_node(poll=10)
    assert NodeState(node=a_node(poll=30)).interval == 30
    assert NodeState(node=a_node(poll=90)).interval == 90


def test_backoff_climbs_then_holds() -> None:
    """It must keep trying: a box that comes back has to be noticed reasonably soon."""
    state = NodeState(node=a_node())
    intervals = []
    for _ in range(6):
        state.record(ok=False, error="down", now=0.0)
        intervals.append(state.interval)
    assert intervals[:3] == list(BACKOFF)
    assert intervals[3:] == [BACKOFF[-1]] * 3, "holds rather than growing without bound"


def test_a_success_clears_the_backoff() -> None:
    state = NodeState(node=a_node())
    state.record(ok=False, error="down", now=0.0)
    state.record(ok=False, error="down", now=0.0)
    assert state.failures == 2
    state.record(ok=True, error="", now=0.0)
    assert state.failures == 0
    assert state.interval == 60
    assert state.last_error == ""


# --- a failure is a result --------------------------------------------------


class Broken:
    host = "10.0.0.9"

    def run(self, command: str) -> CommandResult:
        raise TransportError("10.0.0.9: connection timed out")


class Exploding:
    host = "10.0.0.9"

    def run(self, command: str) -> CommandResult:
        raise RuntimeError("the adapter itself is broken")


def test_an_unreachable_host_becomes_a_result_not_an_exception() -> None:
    collection = collect_once(a_node(), Broken(), "k")
    assert collection.reachable is False
    assert "timed out" in collection.error
    assert collection.host == "r1", "keyed by the declared name, which is what a person reads"


def test_a_broken_adapter_does_not_stop_the_estate() -> None:
    """One box failing in an unexpected way must not take the whole cycle with it."""
    collection = collect_once(a_node(), Exploding(), "k")
    assert collection.reachable is False
    assert "collector error" in collection.error


# --- the loop ---------------------------------------------------------------


def test_a_cycle_records_a_heartbeat_even_when_the_box_is_down(tmp_path: Path) -> None:
    """A silent host is itself the alarm — it must reach the store, not vanish."""
    scheduler = Scheduler(
        store_path=tmp_path / "m.db",
        estate_source=lambda: an_estate(a_node()),
    )
    scheduler._poll = lambda state, secret: Collection(  # type: ignore[method-assign]
        host=state.node.name, reachable=False, error="connection refused"
    )
    assert asyncio.run(scheduler.run_due(now=100.0)) == ("r1",)

    store = Store(tmp_path / "m.db")
    try:
        beat = store.heartbeats()[0]
        assert beat["host"] == "r1"
        assert not beat["reachable"]
        assert "refused" in beat["error"]
    finally:
        store.close()


def test_nothing_is_polled_before_it_is_due(tmp_path: Path) -> None:
    scheduler = Scheduler(store_path=tmp_path / "m.db", estate_source=lambda: an_estate(a_node()))
    scheduler._poll = lambda state, secret: Collection(host=state.node.name)  # type: ignore[method-assign]
    assert asyncio.run(scheduler.run_due(now=0.0)) == ("r1",)
    assert asyncio.run(scheduler.run_due(now=30.0)) == (), "still inside its 60s interval"
    assert asyncio.run(scheduler.run_due(now=61.0)) == ("r1",)


def test_a_node_declared_mid_exercise_is_polled_without_a_restart(tmp_path: Path) -> None:
    """The estate is re-read every cycle, so adding a box does not mean bouncing the tool."""
    nodes = [a_node("r1")]
    scheduler = Scheduler(store_path=tmp_path / "m.db", estate_source=lambda: an_estate(*nodes))
    scheduler._poll = lambda state, secret: Collection(host=state.node.name)  # type: ignore[method-assign]
    asyncio.run(scheduler.run_due(now=0.0))
    nodes.append(a_node("r2"))
    assert "r2" in asyncio.run(scheduler.run_due(now=1.0)), "new box polled at once"


def test_a_removed_node_stops_being_polled(tmp_path: Path) -> None:
    nodes = [a_node("r1"), a_node("r2")]
    scheduler = Scheduler(store_path=tmp_path / "m.db", estate_source=lambda: an_estate(*nodes))
    scheduler._poll = lambda state, secret: Collection(host=state.node.name)  # type: ignore[method-assign]
    asyncio.run(scheduler.run_due(now=0.0))
    nodes.pop()
    assert asyncio.run(scheduler.run_due(now=100.0)) == ("r1",)


def test_a_cycle_applies_changes_against_the_baseline(tmp_path: Path) -> None:
    """The point of the loop: what it collects has to reach the triage store."""
    store = Store(tmp_path / "m.db")
    store.adopt_baseline(
        Collection(
            host="r1",
            items=(Item(key="k", collector="M-FW-02", kind=Kind.CONFIG, value="before"),),
        )
    )
    store.close()

    scheduler = Scheduler(store_path=tmp_path / "m.db", estate_source=lambda: an_estate(a_node()))
    scheduler._poll = lambda state, secret: Collection(  # type: ignore[method-assign]
        host="r1",
        items=(
            Item(
                key="k",
                collector="M-FW-02",
                kind=Kind.CONFIG,
                value="after",
                severity=Severity.CRITICAL,
            ),
        ),
    )
    asyncio.run(scheduler.run_due(now=0.0))

    store = Store(tmp_path / "m.db")
    try:
        assert store.unreviewed_count() == 1
        assert store.outstanding("r1")[0]["current_value"] == "after"
    finally:
        store.close()


# --- refusing to be useless -------------------------------------------------


def test_it_stays_idle_without_a_key_and_says_why() -> None:
    """Firing a doomed ssh at every box every minute achieves one thing: a failed-login
    line in each of their auth logs — the exact logs this tool asks people to read."""
    scheduler = Scheduler(store_path=Path("x"), estate_source=lambda: None)
    assert not Credentials().configured
    assert "No monitoring key is configured" in scheduler.idle_reason
    scheduler.start()
    assert scheduler._task is None

    ready = Scheduler(
        store_path=Path("x"),
        estate_source=lambda: None,
        credentials=Credentials(key_path="/keys/monitor"),
    )
    assert ready.idle_reason == ""


def test_switching_collection_off_is_explained_not_silent() -> None:
    scheduler = Scheduler(
        store_path=Path("x"),
        estate_source=lambda: None,
        credentials=Credentials(key_path="/k"),
        enabled=False,
    )
    assert "switched off" in scheduler.idle_reason
