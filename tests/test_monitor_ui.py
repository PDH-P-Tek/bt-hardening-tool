"""The operator's half of the monitor.

The engine was complete and unreachable for a whole phase: the store had accept, flag
and suppress, and no route called any of them. These tests exercise the path a person
actually takes — dashboard, host, item, decision — so "built" and "reachable" cannot
drift apart again.

The connection test gets its own section because `MONITORING.md` §7 S6 is specific about
it: it must name the failure. "Connection failed" sends someone to check the network
when the real problem was a key, and on a range day that costs an hour.
"""

from __future__ import annotations

from collections.abc import Iterator
from ipaddress import ip_address
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from btht.app import data as data_module
from btht.app.main import app
from btht.app.model.estate import Node, Platform
from btht.app.monitor.connect import Outcome, classify, probe
from btht.app.monitor.items import Collection, Item, Kind, Severity
from btht.app.monitor.scheduler import Credentials
from btht.app.monitor.store import BaselineKind, Store
from btht.app.monitor.transport import CommandResult, RecordedTransport


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    store_dir = tmp_path / "estates"
    monkeypatch.setattr(data_module, "ESTATES", store_dir)
    monkeypatch.setattr("btht.app.web.routes.ESTATES", store_dir)
    monkeypatch.setattr("btht.app.web.routes.MONITOR_DB", store_dir / "monitor.db")
    with TestClient(app) as test_client:
        test_client.post(
            "/range/create",
            data={"team": "42", "vocabulary": "wan, svrs", "tokens": "do_"},
            follow_redirects=False,
        )
        yield test_client


def seed(path: Path, *, value: str = "after", severity: Severity = Severity.CRITICAL) -> Store:
    """A box with one config item that has drifted from its baseline."""
    store = Store(path)
    store.adopt_baseline(
        Collection(
            host="fw1",
            items=(
                Item(key="rule:1", collector="M-FW-01", kind=Kind.CONFIG, value="pass from any"),
            ),
        ),
        BaselineKind.AS_RECEIVED,
    )
    store.apply(
        Collection(
            host="fw1",
            items=(
                Item(
                    key="rule:1",
                    collector="M-FW-01",
                    kind=Kind.CONFIG,
                    value=value,
                    severity=severity,
                    label="filter rule 1",
                ),
            ),
        )
    )
    return store


# --- the three levels -------------------------------------------------------


def test_the_estate_view_leads_with_the_unreviewed_count(
    client: TestClient, tmp_path: Path
) -> None:
    """`MONITORING.md` §8.2 — a single number dominates the page. Zero means stop looking."""
    seed(tmp_path / "estates" / "monitor.db").close()
    body = client.get("/monitor").text
    assert "bignum" in body
    assert "unreviewed change" in body
    assert "fw1" in body


def test_a_clean_estate_says_so_rather_than_showing_an_empty_list(client: TestClient) -> None:
    body = client.get("/monitor").text
    assert "Nothing unreviewed" in body


def test_an_unreachable_box_is_visible_on_the_estate_view(
    client: TestClient, tmp_path: Path
) -> None:
    """A silent host is itself the alarm — it must not read as 'nothing to see'."""
    store = Store(tmp_path / "estates" / "monitor.db")
    store.record_heartbeat(Collection(host="fw1", reachable=False, error="connection refused"))
    store.close()
    body = client.get("/monitor").text
    assert "not answering" in body
    assert "connection refused" in body


def test_the_host_view_groups_by_collector(client: TestClient, tmp_path: Path) -> None:
    seed(tmp_path / "estates" / "monitor.db").close()
    body = client.get("/monitor/host/fw1").text
    assert "M-FW-01" in body
    assert "filter rule 1" in body


def test_the_item_view_shows_the_change_in_the_platforms_own_syntax(
    client: TestClient, tmp_path: Path
) -> None:
    """An operator has to be able to take what they read straight to the box."""
    seed(tmp_path / "estates" / "monitor.db").close()
    body = client.get("/monitor/item/fw1/rule:1").text
    assert "pass from any" in body, "the baseline value, as the box gave it"
    assert "after" in body
    assert "diff" in body


def test_the_item_view_offers_exactly_three_decisions(client: TestClient, tmp_path: Path) -> None:
    seed(tmp_path / "estates" / "monitor.db").close()
    body = client.get("/monitor/item/fw1/rule:1").text
    for decision in ("accept", "flag", "suppress"):
        assert f"/monitor/item/fw1/rule:1/{decision}" in body


def test_a_vanished_item_is_explained_rather_than_a_500(client: TestClient, tmp_path: Path) -> None:
    seed(tmp_path / "estates" / "monitor.db").close()
    response = client.get("/monitor/item/fw1/no-such-key")
    assert response.status_code == 200
    assert "Not found" in response.text


# --- triage actually reaching the store -------------------------------------


def test_accepting_clears_the_item_from_the_count(client: TestClient, tmp_path: Path) -> None:
    """The whole triage model: accept promotes current to baseline. 'That was us.'"""
    database = tmp_path / "estates" / "monitor.db"
    seed(database).close()

    store = Store(database)
    assert store.unreviewed_count() == 1
    store.close()

    response = client.post(
        "/monitor/item/fw1/rule:1/accept", data={"note": "we did that"}, follow_redirects=False
    )
    assert response.status_code == 303

    store = Store(database)
    try:
        assert store.unreviewed_count() == 0
    finally:
        store.close()


def test_flagging_keeps_it_on_the_worklist(client: TestClient, tmp_path: Path) -> None:
    """'That was not us, and I am dealing with it' — it must not disappear."""
    database = tmp_path / "estates" / "monitor.db"
    seed(database).close()
    client.post("/monitor/item/fw1/rule:1/flag", data={"note": "investigating"})

    store = Store(database)
    try:
        assert [row["key"] for row in store.worklist()] == ["rule:1"]
    finally:
        store.close()
    assert "investigating" in client.get("/monitor").text


def test_suppressing_without_a_note_is_refused(client: TestClient, tmp_path: Path) -> None:
    """The note is the only record of why something stopped being watched."""
    seed(tmp_path / "estates" / "monitor.db").close()
    response = client.post("/monitor/item/fw1/rule:1/suppress", data={"note": "  "})
    assert response.status_code == 400
    assert "needs a note" in response.text


def test_accepting_one_item_does_not_resurface_the_others(
    client: TestClient, tmp_path: Path
) -> None:
    """`MONITORING.md` §3.4 — if it did, the operator stops using accept and the model dies."""
    database = tmp_path / "estates" / "monitor.db"
    store = Store(database)
    items = tuple(
        Item(key=f"rule:{n}", collector="M-FW-01", kind=Kind.CONFIG, value="before")
        for n in range(3)
    )
    store.adopt_baseline(Collection(host="fw1", items=items))
    store.apply(
        Collection(
            host="fw1",
            items=tuple(
                Item(key=f"rule:{n}", collector="M-FW-01", kind=Kind.CONFIG, value="after")
                for n in range(3)
            ),
        )
    )
    assert store.unreviewed_count() == 3
    store.close()

    client.post("/monitor/item/fw1/rule:1/accept", data={"note": ""})
    store = Store(database)
    try:
        assert store.unreviewed_count() == 2, "the other two stay exactly as they were"
        assert {r["key"] for r in store.outstanding("fw1")} == {"rule:0", "rule:2"}
    finally:
        store.close()


# --- the two baselines ------------------------------------------------------


def test_both_baselines_are_kept_and_shown(client: TestClient, tmp_path: Path) -> None:
    """`MONITORING.md` S7 — taking only the hardened one throws away what GT shipped."""
    database = tmp_path / "estates" / "monitor.db"
    store = seed(database)
    store.adopt_baseline(
        Collection(
            host="fw1",
            items=(Item(key="rule:1", collector="M-FW-01", kind=Kind.CONFIG, value="hardened"),),
        ),
        BaselineKind.HARDENED,
    )
    assert store.snapshot_value("fw1", "rule:1", BaselineKind.AS_RECEIVED) == "pass from any"
    assert store.snapshot_value("fw1", "rule:1", BaselineKind.HARDENED) == "hardened"
    store.close()

    body = client.get("/monitor/item/fw1/rule:1").text
    assert "as received from Green Team" in body
    assert "pass from any" in body


def test_setup_says_which_baselines_are_still_missing(client: TestClient) -> None:
    body = client.get("/monitor/setup").text
    assert "as-received baseline" in body
    assert "hardened baseline" in body


# --- changed since I last looked ---------------------------------------------


def test_changed_since_i_last_looked(client: TestClient, tmp_path: Path) -> None:
    database = tmp_path / "estates" / "monitor.db"
    seed(database).close()
    client.get("/monitor")  # sets the marker

    store = Store(database)
    try:
        assert store.last_look(), "opening the dashboard records when you looked"
    finally:
        store.close()


# --- metrics and handover ----------------------------------------------------


def test_metrics_are_exposed_for_scraping(client: TestClient, tmp_path: Path) -> None:
    """Grafana was rejected for the operator's view. A scrapeable endpoint was not."""
    seed(tmp_path / "estates" / "monitor.db").close()
    response = client.get("/metrics")
    assert response.status_code == 200
    assert "text/plain" in response.headers["content-type"]


def test_the_handover_report_is_reachable(client: TestClient, tmp_path: Path) -> None:
    seed(tmp_path / "estates" / "monitor.db").close()
    assert client.get("/monitor/handover").status_code == 200


# --- S6: name the specific failure ------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Permission denied (publickey).", Outcome.AUTH),
        ("ssh: connect to host 10.0.0.1 port 22: Connection refused", Outcome.REFUSED),
        ("ssh: connect to host 10.0.0.1 port 22: Connection timed out", Outcome.TIMEOUT),
        ("ssh: Could not resolve hostname r1", Outcome.UNRESOLVED),
        ("Host key verification failed.", Outcome.HOST_KEY),
        ("WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!", Outcome.HOST_KEY),
        ("cat: /etc/shadow: Permission denied", Outcome.PERMISSION),
    ],
)
def test_each_failure_is_named_rather_than_lumped_together(text: str, expected: Outcome) -> None:
    """§7 S6 — never 'connection failed'. Each of these sends you somewhere different."""
    assert classify(text, 255) is expected


def test_every_outcome_carries_something_to_go_and_do() -> None:
    """A diagnosis without a next action is not much use at 0300."""
    from btht.app.monitor.connect import ADVICE

    for outcome, (meaning, _remedy) in ADVICE.items():
        assert meaning, f"{outcome} has no explanation"
    assert all(ADVICE[o][1] for o in Outcome if o not in (Outcome.OK, Outcome.UNKNOWN))


def test_a_changed_host_key_is_treated_as_suspicious() -> None:
    """During an exercise that is what a rebuild — or an interception — looks like."""
    from btht.app.monitor.connect import ADVICE

    assert "suspicious" in ADVICE[Outcome.HOST_KEY][1]


def test_a_working_box_probes_clean() -> None:
    node = Node(name="r1", platform=Platform.LINUX, mgmt_address=ip_address("10.0.0.1"))
    transport = RecordedTransport(
        host="10.0.0.1",
        responses={"uname -a": CommandResult("uname -a", stdout="Linux r1 6.6.0")},
    )
    result = probe(node, Credentials(), transport)
    assert result.ok
    assert result.outcome is Outcome.OK


def test_a_probe_reports_rather_than_raising() -> None:
    class Exploding:
        host = "10.0.0.1"

        def run(self, command: str) -> CommandResult:
            raise RuntimeError("something unexpected")

    node = Node(name="r1", platform=Platform.LINUX, mgmt_address=ip_address("10.0.0.1"))
    assert probe(node, Credentials(), Exploding()).outcome is Outcome.UNKNOWN


# --- S8: proving the monitor actually fires ---------------------------------


def test_the_drill_waits_to_be_started(client: TestClient) -> None:
    """Only changes after the start count, so nothing outstanding gives a false pass."""
    body = client.get("/monitor/drill").text
    assert "Start the drill" in body
    assert "worse than no monitor" in body


def test_the_drill_reports_each_plant_separately(client: TestClient, tmp_path: Path) -> None:
    """Three plants, three verdicts. A single pass/fail hides which collector is dead."""
    client.post("/monitor/drill/start", follow_redirects=False)
    body = client.get("/monitor/drill").text
    assert "Add an account" in body
    assert "Add an authorised key" in body
    assert "Widen an alias by one address" in body
    assert body.count("not seen yet") == 3


def test_a_planted_change_is_detected(client: TestClient, tmp_path: Path) -> None:
    database = tmp_path / "estates" / "monitor.db"
    Store(database).close()
    client.post("/monitor/drill/start", follow_redirects=False)

    store = Store(database)
    store.apply(
        Collection(
            host="fw1",
            items=(
                Item(
                    key="account:intruder",
                    collector="M-ACC-01",
                    kind=Kind.CONFIG,
                    value="intruder:x:1001",
                    label="account intruder",
                ),
            ),
        )
    )
    store.close()

    body = client.get("/monitor/drill").text
    assert "account intruder" in body
    assert body.count("not seen yet") == 2, "the other two are still outstanding"


def test_triaging_the_plant_still_counts_as_detected(client: TestClient, tmp_path: Path) -> None:
    """Otherwise a tidy operator is told the monitor failed when it worked perfectly."""
    database = tmp_path / "estates" / "monitor.db"
    Store(database).close()
    client.post("/monitor/drill/start", follow_redirects=False)

    store = Store(database)
    store.apply(
        Collection(
            host="fw1",
            items=(
                Item(
                    key="k",
                    collector="M-AUTH-01",
                    kind=Kind.CONFIG,
                    value="SHA256:x",
                    label="a key",
                ),
            ),
        )
    )
    store.accept("fw1", "k", "that was the drill")
    store.close()

    assert "a key" in client.get("/monitor/drill").text
