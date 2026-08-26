"""Phase 5 — the monitor core.

Three properties are asserted harder than the plumbing, because each is a way the tool
becomes worse than not having one:

- it is **read-only**, structurally, not by intention
- it **retains no secret** it reads, and it deliberately reads accounts and keys
- it **diffs config and never diffs state**, or it cries wolf every sixty seconds

The suite never opens a socket. Adapters are driven from recorded output, which also
lets the awkward cases — a missing file, a command that is not installed, a host that
stops answering — be tested rather than hoped about.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from btht.app.monitor.adapters.linux import COMMANDS, collect
from btht.app.monitor.items import Collection, Item, Kind, ReviewState, Severity, key_fingerprint
from btht.app.monitor.store import ChangeKind, Store
from btht.app.monitor.transport import (
    CommandResult,
    RecordedTransport,
    RefusedCommand,
    SSHTransport,
    assert_read_only,
)

PASSWD = "root:x:0:0:root:/root:/bin/bash\nanalyst:x:1000:1000::/home/analyst:/bin/bash\n"
SHADOW = "root:$6$abc$verylonghashvalue:19000:0:99999:7:::\nanalyst:!:19000:0:99999:7:::\n"
KEYS = (
    "/home/analyst/.ssh/authorized_keys:"
    'from="10.0.0.5",command="/usr/local/bin/collect" ssh-ed25519 '
    "AAAAC3NzaC1lZDI1NTE5AAAAIEtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tL analyst@laptop\n"
)
SUDOERS = (
    "root ALL=(ALL:ALL) ALL\n# a comment\nbtmon ALL=(root) NOPASSWD: /usr/local/sbin/collect\n"
)


def a_transport(**overrides: str) -> RecordedTransport:
    responses = {
        COMMANDS["M-ACC-01"]: CommandResult(COMMANDS["M-ACC-01"], stdout=PASSWD),
        COMMANDS["M-ACC-03"]: CommandResult(COMMANDS["M-ACC-03"], stdout=SHADOW),
        COMMANDS["M-AUTH-01"]: CommandResult(COMMANDS["M-AUTH-01"], stdout=KEYS),
        COMMANDS["M-ACC-08"]: CommandResult(COMMANDS["M-ACC-08"], stdout=SUDOERS),
        COMMANDS["M-SCHED-01"]: CommandResult(
            COMMANDS["M-SCHED-01"], stdout="@daily /usr/bin/backup\n"
        ),
        COMMANDS["M-SCHED-02"]: CommandResult(COMMANDS["M-SCHED-02"], stdout=""),
        COMMANDS["M-STATE-UPTIME"]: CommandResult(
            COMMANDS["M-STATE-UPTIME"], stdout="up 3 days, load 0.4"
        ),
        COMMANDS["M-STATE-WHO"]: CommandResult(COMMANDS["M-STATE-WHO"], stdout="analyst pts/0"),
    }
    for command, stdout in overrides.items():
        responses[COMMANDS[command]] = CommandResult(COMMANDS[command], stdout=stdout)
    return RecordedTransport(host="host1", responses=responses)


# --- read-only, structurally -----------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        "rm -rf /tmp/x",
        "systemctl restart sshd",
        "pfctl -d",
        "nft flush ruleset",
        "crontab -r",
        "vtysh -c 'configure terminal'",
        "cat /etc/passwd > /tmp/copy",
        "getent passwd; useradd intruder",
        "echo x | tee /etc/motd",
        "cat $(which nft)",
        "find / -exec rm {} +",
        "curl http://elsewhere/payload",
    ],
)
def test_anything_that_could_change_the_host_is_refused(command: str) -> None:
    """`MONITORING.md` §2 — the monitor never writes, and that is not negotiable.

    A collector that can be talked into writing has a read-only claim worth nothing.
    """
    with pytest.raises(RefusedCommand):
        assert_read_only(command)


def test_the_collectors_own_commands_all_pass_the_check() -> None:
    """The refusal must be blunt without being useless.

    `getent passwd` reads the account database; an earlier version refused it because
    the word `passwd` appeared, which is the kind of strictness that gets a control
    turned off rather than trusted.
    """
    for command in COMMANDS.values():
        assert_read_only(command)


@pytest.mark.parametrize(
    "command",
    [
        "pfctl -sr",
        "pfctl -vsr",
        "nft list ruleset",
        "iptables -S",
        "systemctl list-units --type=service",
        "vtysh -c 'show running-config'",
        "crontab -l -u root",
        "sshd -T",
    ],
)
def test_the_reading_mode_of_a_writing_binary_is_permitted(command: str) -> None:
    """The reason for an allow-list: `pfctl -sr` reads and `pfctl -d` disables."""
    assert_read_only(command)


def test_the_transport_refuses_before_connecting() -> None:
    """Refused at the boundary, so a bad command never reaches a managed host."""
    transport = SSHTransport(host="10.0.0.1", user="btmon")
    with pytest.raises(RefusedCommand):
        transport.run("reboot")


def test_ssh_is_key_only_and_checks_the_host() -> None:
    argv = SSHTransport(host="10.0.0.1", user="btmon", key_path="/k")._argv("uptime")
    assert "BatchMode=yes" in argv
    assert "PasswordAuthentication=no" in argv
    assert "StrictHostKeyChecking=yes" in argv
    assert "IdentitiesOnly=yes" in argv


# --- no secret is retained --------------------------------------------------


def test_a_password_hash_never_reaches_an_item() -> None:
    """`MONITORING.md` §4 — store whether it changed, never what it is."""
    collection = collect(a_transport(), secret="k")
    values = " ".join(i.value for i in collection.items)
    assert "$6$" not in values
    assert "verylonghashvalue" not in values

    root = next(i for i in collection.items if i.key == "password:root")
    assert root.value.startswith("set:")


def test_a_locked_account_is_recorded_as_locked_not_as_a_digest() -> None:
    locked = next(
        i for i in collect(a_transport(), secret="k").items if i.key == "password:analyst"
    )
    assert locked.value == "locked"


def test_an_authorised_key_is_stored_as_a_fingerprint_not_a_key() -> None:
    collection = collect(a_transport())
    values = " ".join(i.value + i.key for i in collection.items)
    assert "AAAAC3NzaC1lZDI1NTE5" not in values, "the key body must not be retained"
    key_item = next(i for i in collection.items if i.key.startswith("authorized_key:"))
    assert "SHA256:" in key_item.key


def test_the_key_restriction_options_are_kept_because_they_are_the_restriction() -> None:
    """An appended key without `from=` is full shell where a forced command was assumed."""
    key_item = next(i for i in collect(a_transport()).items if i.key.startswith("authorized_key:"))
    assert "from=" in key_item.value
    assert "command=" in key_item.value


def test_the_digest_only_answers_whether_it_changed() -> None:
    from btht.app.monitor.items import digest

    assert digest("k", "hash-a") == digest("k", "hash-a")
    assert digest("k", "hash-a") != digest("k", "hash-b")
    assert digest("k1", "hash-a") != digest("k2", "hash-a"), "keyed, not a plain hash"
    assert "hash-a" not in digest("k", "hash-a")


def test_a_malformed_key_is_data_not_a_crash() -> None:
    assert key_fingerprint("not base64 at all!!") == "unreadable"


# --- config is diffed, state is never ---------------------------------------


def test_state_items_are_collected_and_marked_as_state() -> None:
    collection = collect(a_transport())
    assert {i.key for i in collection.state_items()} == {
        "state:M-STATE-UPTIME",
        "state:M-STATE-WHO",
    }


def test_state_churn_never_produces_a_change(tmp_path: Path) -> None:
    """`MONITORING.md` §3.3 — the single line that prevents most false positives."""
    store = Store(tmp_path / "m.sqlite")
    store.adopt_baseline(collect(a_transport()))
    later = collect(a_transport(**{"M-STATE-UPTIME": "up 9 days, load 3.1"}))
    assert store.apply(later) == ()
    store.close()


def test_a_new_account_is_a_change(tmp_path: Path) -> None:
    store = Store(tmp_path / "m.sqlite")
    store.adopt_baseline(collect(a_transport()))
    intruder = PASSWD + "svc-backup:x:1001:1001::/home/svc:/bin/bash\n"
    changes = store.apply(collect(a_transport(**{"M-ACC-01": intruder})))
    assert [c.kind for c in changes] == [ChangeKind.ADDED]
    assert changes[0].key == "account:svc-backup"
    assert changes[0].severity is Severity.HIGH
    store.close()


def test_a_removed_line_is_a_change(tmp_path: Path) -> None:
    """Deletions are changes — the ones least likely to be caught by eye."""
    store = Store(tmp_path / "m.sqlite")
    store.adopt_baseline(collect(a_transport()))
    changes = store.apply(collect(a_transport(**{"M-SCHED-01": ""})))
    assert [c.kind for c in changes] == [ChangeKind.REMOVED]
    assert "backup" in changes[0].before
    store.close()


def test_an_added_sudo_rule_is_critical(tmp_path: Path) -> None:
    store = Store(tmp_path / "m.sqlite")
    store.adopt_baseline(collect(a_transport()))
    widened = SUDOERS + "analyst ALL=(ALL) NOPASSWD: ALL\n"
    changes = store.apply(collect(a_transport(**{"M-ACC-08": widened})))
    assert changes[0].severity is Severity.CRITICAL
    store.close()


# --- triage, per item -------------------------------------------------------


def test_accepting_one_change_does_not_resurface_the_others(tmp_path: Path) -> None:
    """`MONITORING.md` §3.4 — if it did, the operator stops using accept.

    This is the property the whole triage model rests on.
    """
    store = Store(tmp_path / "m.sqlite")
    store.adopt_baseline(collect(a_transport()))
    changed = collect(
        a_transport(
            **{
                "M-ACC-01": PASSWD + "svc:x:1001:1001::/home/svc:/bin/sh\n",
                "M-SCHED-01": "@daily /usr/bin/backup\n@hourly /usr/bin/other\n",
            }
        )
    )
    first = store.apply(changed)
    assert len(first) == 2

    store.accept(host="host1", key=first[0].key, note="that was us")
    second = store.apply(changed)
    assert len(second) == 1, "accepting one item must not resurface the other"
    assert second[0].key == first[1].key
    store.close()


def test_flagging_keeps_it_on_the_worklist_without_re_alerting(tmp_path: Path) -> None:
    store = Store(tmp_path / "m.sqlite")
    store.adopt_baseline(collect(a_transport()))
    intruder = PASSWD + "svc:x:1001:1001::/home/svc:/bin/sh\n"
    changes = store.apply(collect(a_transport(**{"M-ACC-01": intruder})))

    store.flag(host="host1", key=changes[0].key, note="not ours, investigating")
    again = store.apply(collect(a_transport(**{"M-ACC-01": intruder})))
    assert again[0].review_state is ReviewState.FLAGGED
    assert again[0].needs_attention is False, "flagged items stop shouting"
    assert [row["key"] for row in store.worklist()] == [changes[0].key]
    store.close()


def test_suppressing_requires_a_note(tmp_path: Path) -> None:
    """An unexplained silence is worse than the noise it replaced."""
    store = Store(tmp_path / "m.sqlite")
    store.adopt_baseline(collect(a_transport()))
    with pytest.raises(ValueError, match="requires a note"):
        store.suppress(host="host1", key="account:root", note="   ")
    store.close()


def test_a_suppressed_item_stops_producing_changes(tmp_path: Path) -> None:
    store = Store(tmp_path / "m.sqlite")
    store.adopt_baseline(collect(a_transport()))
    noisy = PASSWD.replace(
        "analyst:x:1000:1000::/home/analyst:/bin/bash", "analyst:x:1000:1000::/home/analyst:/bin/sh"
    )
    changes = store.apply(collect(a_transport(**{"M-ACC-01": noisy})))
    assert len(changes) == 1, "one account changed, so one change"
    store.suppress(host="host1", key=changes[0].key, note="this box rewrites it nightly")
    assert store.apply(collect(a_transport(**{"M-ACC-01": noisy}))) == ()
    store.close()


# --- heartbeat --------------------------------------------------------------


def test_a_host_that_stops_answering_is_recorded_not_crashed(tmp_path: Path) -> None:
    """`MONITORING.md` §3.1 — a host that goes quiet is already an alarm."""
    store = Store(tmp_path / "m.sqlite")
    dead = RecordedTransport(host="host1", responses={})
    collection = collect(dead)
    assert collection.reachable is False

    assert store.apply(collection) == (), "an unreachable host produces no false removals"
    beat = store.heartbeats()[0]
    assert beat["host"] == "host1"
    assert beat["reachable"] == 0
    store.close()


def test_an_empty_collection_never_deletes_a_baseline(tmp_path: Path) -> None:
    """Otherwise one failed poll reports the entire estate as removed."""
    store = Store(tmp_path / "m.sqlite")
    store.adopt_baseline(collect(a_transport()))
    store.apply(Collection(host="host1", reachable=False, error="timed out"))
    assert len(store.items("host1")) > 0
    store.close()


def test_an_item_without_a_key_cannot_exist() -> None:
    with pytest.raises(ValueError, match="stable key"):
        Item(key="", collector="M-ACC-01", kind=Kind.CONFIG, value="x")


# --- the dashboard, Phase 5.4 -----------------------------------------------


def test_an_unpolled_device_is_not_painted_healthy() -> None:
    """Silence is not health. A device nobody has collected from keeps its own colour."""
    from ipaddress import IPv4Address

    from btht.app.model.estate import Estate, Firewall, Node, Platform
    from btht.app.web.topology import layout

    node = Node(name="fw1", platform=Platform.PFSENSE, mgmt_address=IPv4Address("10.0.0.1"))
    estate = Estate(
        team=1,
        team_padded="1",
        firewalls=(Firewall(enclave="alpha", fqdn="fw1", node=node),),
    )
    unpolled = {s.detail_id: s for s in layout(estate).shapes}
    assert unpolled["fw:alpha"].accent == "accent"
    assert "unreachable" not in unpolled["fw:alpha"].sublabel

    down = {s.detail_id: s for s in layout(estate, {"fw1": "unreachable — timed out"}).shapes}
    assert down["fw:alpha"].accent == "warn"
    assert "unreachable" in down["fw:alpha"].sublabel


def test_the_monitor_view_reuses_the_topology_rather_than_duplicating_it() -> None:
    """One component, two consumers — the same economy as the platform adapters."""
    from pathlib import Path

    template = Path("btht/app/web/templates/monitor.html").read_text(encoding="utf-8")
    assert 'extends "topology.html"' in template


# --- pfSense adapter, Phase 6.1 ---------------------------------------------

#: Read from the exempt credential-fixture directory rather than written inline: the
#: secret-exclusion test caught it here, which is the control doing its job.
PF_CONFIG = (
    Path(__file__).resolve().parents[1]
    / "tests"
    / "fixtures"
    / "credentials"
    / "pfsense-with-secrets.xml"
).read_text(encoding="utf-8")


def a_pfsense_transport(config: str = PF_CONFIG) -> RecordedTransport:
    from btht.app.monitor.adapters.pfsense import COMMANDS as PF

    return RecordedTransport(
        host="fw1",
        responses={
            PF["M-FW-CONFIG"]: CommandResult(PF["M-FW-CONFIG"], stdout=config),
            PF["M-FW-06"]: CommandResult(
                PF["M-FW-06"], stdout="pass in quick on em0\nblock drop in\n"
            ),
            PF["M-SVC-01"]: CommandResult(PF["M-SVC-01"], stdout=""),
        },
    )


def test_the_firewall_config_never_yields_its_hash_or_key_body() -> None:
    """`MONITORING.md` §4 — config.xml holds hashes, keys and service passwords."""
    from btht.app.monitor.adapters.pfsense import collect as pf_collect

    collection = pf_collect(a_pfsense_transport(), secret="k")
    blob = " ".join(i.key + i.value for i in collection.items)
    assert "$2y$" not in blob
    assert "SyntheticHash" not in blob
    assert "QUFBQUJCQkJDQ0NDRERERA==" not in blob, "the key body must not be retained"


def test_a_firewall_rule_is_identified_by_its_tracker() -> None:
    """The awkward part of item identity, and pfSense supplies the answer.

    An edited rule keeps its tracker, so the change reads as a change rather than as a
    deletion plus an unrelated addition.
    """
    from btht.app.monitor.adapters.pfsense import collect as pf_collect

    items = {i.key: i for i in pf_collect(a_pfsense_transport()).items}
    assert "pf:rule:1699900001" in items

    edited = PF_CONFIG.replace("<type>pass</type>", "<type>block</type>")
    after = {i.key: i for i in pf_collect(a_pfsense_transport(edited)).items}
    assert "pf:rule:1699900001" in after, "same identity"
    assert after["pf:rule:1699900001"].value != items["pf:rule:1699900001"].value


def test_a_management_alias_is_stored_as_addresses_not_a_count() -> None:
    """`MONITORING.md` §5.7.1 — the operator should be reading addresses."""
    from btht.app.monitor.adapters.pfsense import collect as pf_collect

    alias = next(
        i for i in pf_collect(a_pfsense_transport()).items if i.key == "pf:alias:Mgmt_Sources"
    )
    assert alias.severity is Severity.CRITICAL
    assert "198.51.100.0/24" in alias.value and "203.0.113.0/24" in alias.value


def test_the_pfsense_adapter_reuses_the_generators_parser() -> None:
    """One parser, two halves — they cannot disagree about whether a rule changed."""
    source = Path("btht/app/monitor/adapters/pfsense.py").read_text(encoding="utf-8")
    assert "from btht.app.ingest.pfsense import" in source


def test_a_mangled_config_is_a_result_not_a_crash() -> None:
    from btht.app.monitor.adapters.pfsense import collect as pf_collect

    collection = pf_collect(a_pfsense_transport("<pfsense><filter>"))
    assert collection.reachable is False
    assert "config.xml" in collection.error


# --- FRR adapter, Phase 6.3 -------------------------------------------------

RUNNING = """Building configuration...
!
router ospf
 network 10.0.0.0/24 area 0
 neighbor 10.0.0.2
!
username admin nopassword
line vty
!
"""


def a_frr_transport(running: str = RUNNING) -> RecordedTransport:
    from btht.app.monitor.adapters.frr import COMMANDS as FRR

    return RecordedTransport(
        host="r1",
        responses={
            FRR["M-RT-01"]: CommandResult(FRR["M-RT-01"], stdout=running),
            FRR["M-RT-02"]: CommandResult(FRR["M-RT-02"], stdout="10.0.0.2 Full/DR 00:00:35"),
            FRR["M-RT-03"]: CommandResult(FRR["M-RT-03"], stdout="O>* 10.0.9.0/24 [110/20]"),
            FRR["M-RT-04"]: CommandResult(FRR["M-RT-04"], stdout="10.0.0.2 up"),
        },
    )


def test_the_running_config_is_config_and_the_routing_table_is_not() -> None:
    """`MONITORING.md` §3.3 — the distinction that decides whether this is usable.

    They live one line apart in the same tool's output, which is how they get confused.
    """
    from btht.app.monitor.adapters.frr import collect as frr_collect

    collection = frr_collect(a_frr_transport())
    config_keys = {i.key for i in collection.config_items()}
    state_keys = {i.key for i in collection.state_items()}

    assert any("router ospf" in k for k in config_keys)
    assert any("neighbor 10.0.0.2" in k for k in config_keys), "a neighbour definition is config"
    assert "frr:state:M-RT-03" in state_keys, "the routing table is state"
    assert "frr:state:M-RT-02" in state_keys, "neighbour up/down is state"


def test_an_adjacency_flapping_produces_no_change(tmp_path: Path) -> None:
    """Otherwise the one line saying a *new* neighbour was configured is buried."""
    from btht.app.monitor.adapters.frr import COMMANDS as FRR
    from btht.app.monitor.adapters.frr import collect as frr_collect

    store = Store(tmp_path / "m.sqlite")
    store.adopt_baseline(frr_collect(a_frr_transport()))

    flapped = a_frr_transport()
    flapped.responses[FRR["M-RT-02"]] = CommandResult(FRR["M-RT-02"], stdout="10.0.0.2 Down")
    flapped.responses[FRR["M-RT-03"]] = CommandResult(FRR["M-RT-03"], stdout="(table rewritten)")
    assert store.apply(frr_collect(flapped)) == ()
    store.close()


def test_a_new_routing_neighbour_is_a_change(tmp_path: Path) -> None:
    from btht.app.monitor.adapters.frr import collect as frr_collect

    store = Store(tmp_path / "m.sqlite")
    store.adopt_baseline(frr_collect(a_frr_transport()))
    changes = store.apply(
        frr_collect(a_frr_transport(RUNNING.replace(" neighbor 10.0.0.2", " neighbor 10.0.0.9")))
    )
    kinds = {c.kind for c in changes}
    assert kinds == {ChangeKind.ADDED, ChangeKind.REMOVED}
    store.close()


def test_a_router_login_line_is_critical() -> None:
    from btht.app.monitor.adapters.frr import collect as frr_collect

    item = next(i for i in frr_collect(a_frr_transport()).items if "username admin" in i.key)
    assert item.severity is Severity.CRITICAL
