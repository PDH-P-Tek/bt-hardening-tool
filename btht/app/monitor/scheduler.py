"""The collection loop — `MONITORING.md` §3.1, §3.5.

The collector runs *inside* this container, beside the ruleset builder, and polls each
managed node over SSH. Off-box by design: nothing is installed on Green Team's
machines, the baseline sits outside the attacker's reach, and a host that stops
answering is itself a finding rather than a gap in the record.

Three rules from §3.5, each of which exists because the obvious alternative fails:

- **Full collection every cycle, no incremental mode.** An incremental collector cannot
  see a deletion, and a deletion is the change least likely to be caught by eye.
- **Backoff on failure: 60 → 120 → 300, then hold.** A box that is down stays down, and
  hammering it every minute buries the one line saying when it went.
- **A 30 second floor.** Below that the poll cost on pfSense starts to matter, and the
  monitor becomes a load source on the thing it is watching.

Collection is blocking — it shells out to `ssh` — so each poll runs in a worker thread
and the loop itself never blocks. Nothing here can write to a managed host: the
transport refuses any command not on the read-only allow-list, and that refusal is a
crash rather than a warning.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from btht.app.model.estate import Estate, Node, Platform
from btht.app.monitor.adapters import frr, linux, pfsense
from btht.app.monitor.items import Collection
from btht.app.monitor.store import Store
from btht.app.monitor.transport import SSHTransport, Transport, TransportError

log = logging.getLogger("btht.monitor")

#: `MONITORING.md` §3.5. After the last step the interval holds rather than growing —
#: an unreachable host must keep being *tried*, so that recovery is noticed promptly.
BACKOFF = (60, 120, 300)

ADAPTERS = {
    Platform.PFSENSE: pfsense.collect,
    Platform.LINUX: linux.collect,
    Platform.FRR: frr.collect,
}


@dataclass(frozen=True, slots=True)
class Credentials:
    """How the monitor authenticates. Supplied by the operator, never held in the tree.

    The key pair is generated at setup and lives outside this repository, so what is
    stored here is a path — and the account it opens is read-only on the far end.
    """

    user: str = ""
    key_path: str = ""
    known_hosts: str = ""
    timeout: int = 20

    @property
    def configured(self) -> bool:
        """Without a key there is nothing to authenticate with.

        The loop stays idle rather than launching a doomed `ssh` at every managed box
        every minute — which would achieve nothing except a login-failure line in each
        of their auth logs, on the exact boxes whose auth logs the tool asks people to
        read.
        """
        return bool(self.key_path)


def transport_for(node: Node, credentials: Credentials) -> Transport:
    return SSHTransport(
        host=str(node.mgmt_address),
        user=credentials.user,
        key_path=credentials.key_path,
        known_hosts=credentials.known_hosts,
        timeout=credentials.timeout,
    )


def collect_once(node: Node, transport: Transport, secret: str) -> Collection:
    """One full collection from one node. Never raises — a failure is a result.

    An unreachable host is data the operator needs, not an exception to swallow: it
    lands in the store as an unreachable heartbeat and shows on the dashboard.
    """
    adapter = ADAPTERS.get(node.platform)
    if adapter is None:  # pragma: no cover - Platform is exhaustive today
        return Collection(host=node.name, reachable=False, error=f"no adapter for {node.platform}")
    try:
        collection = adapter(transport, secret)
    except TransportError as exc:
        return Collection(host=node.name, reachable=False, error=str(exc))
    except Exception as exc:  # noqa: BLE001 - one bad box must not stop the estate
        log.exception("collection failed for %s", node.name)
        return Collection(host=node.name, reachable=False, error=f"collector error: {exc}")
    # Adapters key their collection by the address they were given; the store and the
    # whole UI key on the node's declared name, which is what a person recognises.
    return Collection(
        host=node.name,
        items=collection.items,
        reachable=collection.reachable,
        error=collection.error,
    )


@dataclass
class NodeState:
    """When a node is next due, and how far into backoff it has fallen."""

    node: Node
    due_at: float = 0.0
    failures: int = 0
    last_error: str = ""

    @property
    def interval(self) -> int:
        if not self.failures:
            return max(self.node.poll_seconds, 30)
        return BACKOFF[min(self.failures - 1, len(BACKOFF) - 1)]

    def record(self, ok: bool, error: str, now: float) -> None:
        self.failures = 0 if ok else self.failures + 1
        self.last_error = "" if ok else error
        self.due_at = now + self.interval


@dataclass
class Scheduler:
    """Polls every managed node for as long as the app is running."""

    store_path: Path
    estate_source: Callable[[], Estate | None]
    credentials: Credentials = field(default_factory=Credentials)
    #: Seconds between checks for which nodes are due. Not the poll interval.
    tick: float = 1.0
    _states: dict[str, NodeState] = field(default_factory=dict)
    _task: asyncio.Task[None] | None = None
    _stopping: asyncio.Event | None = None
    enabled: bool = True

    def states(self) -> tuple[NodeState, ...]:
        return tuple(self._states.values())

    def _sync_nodes(self, estate: Estate) -> None:
        """Follow the declared estate. A node added mid-exercise is polled without a restart."""
        declared = {node.name: node for node in estate.all_nodes()}
        for name, node in declared.items():
            state = self._states.get(name)
            if state is None:
                # Poll a newly declared node immediately: the operator has just added it
                # and is watching to see whether it answers.
                self._states[name] = NodeState(node=node, due_at=0.0)
            else:
                state.node = node
        for name in set(self._states) - set(declared):
            del self._states[name]

    def _poll(self, state: NodeState, secret: str) -> Collection:
        return collect_once(state.node, transport_for(state.node, self.credentials), secret)

    async def run_due(self, now: float | None = None) -> tuple[str, ...]:
        """Poll every node that is due. Returns the names polled, for the tests."""
        estate = self.estate_source()
        if estate is None:
            return ()
        self._sync_nodes(estate)
        now = time.monotonic() if now is None else now
        due = [s for s in self._states.values() if s.due_at <= now]
        if not due:
            return ()

        store = Store(self.store_path)
        try:
            secret = store.secret
            results = await asyncio.gather(
                *(asyncio.to_thread(self._poll, state, secret) for state in due)
            )
            for state, collection in zip(due, results, strict=True):
                store.record_heartbeat(collection)
                if collection.reachable:
                    store.apply(collection)
                state.record(collection.reachable, collection.error, now)
        finally:
            store.close()
        return tuple(s.node.name for s in due)

    async def _loop(self) -> None:
        assert self._stopping is not None
        while not self._stopping.is_set():
            try:
                await self.run_due()
            except Exception:  # noqa: BLE001 - the loop outlives any single failure
                log.exception("collection cycle failed")
            try:
                await asyncio.wait_for(self._stopping.wait(), timeout=self.tick)
            except TimeoutError:
                continue

    @property
    def idle_reason(self) -> str:
        """Why collection is not running, in words the setup page can show."""
        if not self.enabled:
            return "Collection is switched off for this process (BTHT_MONITOR=0)."
        if not self.credentials.configured:
            return (
                "No monitoring key is configured, so nothing is being polled. Generate a "
                "key pair outside this tool, install the public half in the read-only "
                "account on each box, and start the tool with BTHT_SSH_KEY pointing at "
                "the private half."
            )
        return ""

    def start(self) -> None:
        if self._task is not None or self.idle_reason:
            if self.idle_reason:
                log.info("monitor idle: %s", self.idle_reason)
            return
        self._stopping = asyncio.Event()
        self._task = asyncio.create_task(self._loop(), name="btht-monitor")
        log.info("monitor collection started")

    async def stop(self) -> None:
        if self._task is None or self._stopping is None:
            return
        self._stopping.set()
        self._task.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await self._task
        self._task = None
        log.info("monitor collection stopped")
