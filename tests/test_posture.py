"""Phase 7 — posture checks.

A different question from drift. The monitor asks *has this changed*; these ask *is
this right*, whether or not anybody touched it. Both read the same collected item set,
so the adapters are written once.

The property worth guarding hardest: a check that could not be evaluated is `unknown`
and never `pass`. Silence is not health, and a green board built from missing data is
worse than no board.
"""

from __future__ import annotations

from btht.app.monitor.items import Item, Kind, Severity
from btht.app.validate.posture import (
    Result,
    check_accounts,
    check_firewall,
    check_routing,
    check_ssh,
    failing,
    run_posture,
    unknown,
)


def sshd(**settings: str) -> list[Item]:
    return [
        Item(
            key=f"sshd:{name}",
            collector="H-SSH-CONFIG",
            kind=Kind.CONFIG,
            value=f"{name} {value}",
            severity=Severity.HIGH,
        )
        for name, value in settings.items()
    ]


def sudoers(*lines: str) -> list[Item]:
    return [
        Item(key=f"sudoers:{line}", collector="M-ACC-08", kind=Kind.CONFIG, value=line)
        for line in lines
    ]


# --- unknown is not pass ----------------------------------------------------


def test_a_check_with_nothing_to_read_is_unknown_not_pass() -> None:
    """The property that decides whether a green board means anything."""
    checks = check_ssh([])
    assert [c.result for c in checks] == [Result.UNKNOWN]
    assert unknown(tuple(checks))
    assert not failing(tuple(checks))


def test_an_unknown_check_says_what_is_missing() -> None:
    assert "sshd -T was not collected" in check_ssh([])[0].detail


def test_routing_checks_are_unknown_without_a_router() -> None:
    assert check_routing([])[0].result is Result.UNKNOWN


# --- ssh --------------------------------------------------------------------


def test_password_authentication_is_checked() -> None:
    hardened = {c.id: c for c in check_ssh(sshd(passwordauthentication="no"))}
    assert hardened["H-SSH-02"].result is Result.PASS
    open_box = {c.id: c for c in check_ssh(sshd(passwordauthentication="yes"))}
    assert open_box["H-SSH-02"].result is Result.FAIL


def test_the_remediation_says_to_keep_a_second_session_open() -> None:
    """Never harden yourself out of the box you are hardening — `HARDENING.md` §4."""
    check = {c.id: c for c in check_ssh(sshd(passwordauthentication="yes"))}["H-SSH-02"]
    assert "second session" in check.remediation


def test_verbose_logging_is_checked_and_says_why() -> None:
    check = {c.id: c for c in check_ssh(sshd(loglevel="INFO"))}["H-SSH-20"]
    assert check.result is Result.FAIL
    assert "which one" in check.remediation, "the question you ask afterwards"


# --- accounts ---------------------------------------------------------------


def test_a_blanket_sudo_grant_fails() -> None:
    """`H-ACC-05`. A NOPASSWD: ALL line in sudoers.d is full root, and easy to miss."""
    clean = {c.id: c for c in check_accounts(sudoers("btmon ALL=(root) /usr/sbin/collect"))}
    assert clean["H-ACC-05"].result is Result.PASS

    widened = {c.id: c for c in check_accounts(sudoers("analyst ALL=(ALL) NOPASSWD: ALL"))}
    assert widened["H-ACC-05"].result is Result.FAIL
    assert "trivial to miss by eye" in widened["H-ACC-05"].remediation


# --- firewall ---------------------------------------------------------------


def test_anti_lockout_check_states_the_risk_and_the_open_question() -> None:
    """The single highest-lockout-risk change, and it may not even be permitted."""
    items = [Item(key="pf:antilockout", collector="M-PF-01", kind=Kind.CONFIG, value="enabled")]
    check = {c.id: c for c in check_firewall(items)}["H-PF-01"]
    assert check.result is Result.FAIL
    assert "second session" in check.remediation
    assert "Permitted" in check.remediation, "H-Q4 is closed: it is allowed"
    assert "do not rely on that" in check.remediation, (
        "GT's own rule makes this recoverable, which is not a reason to skip verifying"
    )


def test_unauthenticated_management_services_fail() -> None:
    items = [
        Item(
            key="listen:udp:0.0.0.0:161",
            collector="M-SVC-01",
            kind=Kind.CONFIG,
            value="udp 0.0.0.0:161 snmpd",
        )
    ]
    check = {c.id: c for c in check_firewall(items)}["H-PF-05"]
    assert check.result is Result.FAIL
    assert "community string still public" in check.remediation


# --- routing ----------------------------------------------------------------


def test_a_router_login_without_a_password_fails() -> None:
    items = [
        Item(
            key="frr:config:username admin nopassword",
            collector="M-RT-01",
            kind=Kind.CONFIG,
            value="username admin nopassword",
        )
    ]
    check = {c.id: c for c in check_routing(items)}["H-FRR-02"]
    assert check.result is Result.FAIL
    assert "H-Q2" in check.remediation, "scoping still needs a look at a live router"


# --- the whole run ----------------------------------------------------------


def test_checks_come_out_in_a_stable_order() -> None:
    items = sshd(passwordauthentication="no") + sudoers("root ALL=(ALL) ALL")
    assert [c.id for c in run_posture(items)] == [c.id for c in run_posture(items)]


def test_nothing_here_remediates_anything() -> None:
    """`HARDENING.md` §11 — they show the step, they never take it.

    Same rule as the monitor, for the same reason: a tool that can fix a firewall
    holds a credential that can break one.
    """
    import inspect

    from btht.app.validate import posture

    source = inspect.getsource(posture)
    for writing in ("subprocess", "transport.run", "os.system", "Popen"):
        assert writing not in source, f"posture checks must not be able to {writing}"


# --- pfSense rule tampering — H-PF-* -----------------------------------------


def _rule_item(value: str, label: str = "r") -> Item:
    from btht.app.monitor.items import Item, Kind, Severity

    return Item(
        key=f"pf:rule:{label}",
        collector="M-FW-01",
        kind=Kind.CONFIG,
        value=value,
        severity=Severity.CRITICAL,
        label=label,
    )


def _live(count: int) -> Item:
    from btht.app.monitor.items import Item, Kind, Severity

    return Item(
        key="pf:live",
        collector="M-FW-06",
        kind=Kind.CONFIG,
        value=str(count),
        severity=Severity.HIGH,
        label="loaded",
    )


def test_pfctl_disable_is_caught_by_the_split_between_saved_and_loaded() -> None:
    """`pfctl -d` disables every rule and does not show in the web interface.

    The saved config is untouched, so the only tell is that pf is enforcing far fewer
    rules than are configured. That is exactly why both halves are collected.
    """
    from btht.app.validate.posture import Result, check_pfsense

    items = [_rule_item("pass wan inet src=any dst=x disabled=False", str(n)) for n in range(20)]
    items.append(_live(1))  # pf flushed to almost nothing
    check = next(c for c in check_pfsense(items) if c.id == "H-PF-01")
    assert check.result is Result.FAIL
    assert "pfctl -d" in check.detail


def test_a_healthy_firewall_loads_more_than_it_configures() -> None:
    """pf adds scrub, anti-lockout and defaults, so the live count is normally higher."""
    from btht.app.validate.posture import Result, check_pfsense

    items = [_rule_item("pass wan inet src=any dst=x disabled=False", str(n)) for n in range(20)]
    items.append(_live(31))
    check = next(c for c in check_pfsense(items) if c.id == "H-PF-01")
    assert check.result is Result.PASS


def test_a_floating_any_any_rule_is_flagged() -> None:
    """`EVIDENCE.md` E1 — a floating pass-any-any overrides every block rule below it."""
    from btht.app.validate.posture import Result, check_pfsense

    items = [
        _rule_item(
            "pass wan,lan inet46 proto=any src=any dst=any floating=True "
            "quick=False disabled=False descr=RT any any",
            "rt",
        ),
        _live(30),
    ]
    check = next(c for c in check_pfsense(items) if c.id == "H-PF-02")
    assert check.result is Result.FAIL
    assert "overrides every rule below it" in check.detail


def test_an_ordinary_ruleset_has_no_any_any_finding() -> None:
    from btht.app.validate.posture import Result, check_pfsense

    items = [
        _rule_item("pass lan inet src=lan-net dst=any floating=False disabled=False", "ok"),
        _live(30),
    ]
    check = next(c for c in check_pfsense(items) if c.id == "H-PF-02")
    assert check.result is Result.PASS


def test_pfsense_checks_report_unknown_without_the_collection() -> None:
    from btht.app.validate.posture import Result, check_pfsense

    check = next(c for c in check_pfsense([]) if c.id == "H-PF-01")
    assert check.result is Result.UNKNOWN


# --- OSPF backdoor surface — H-FRR-04/05 -------------------------------------


def _frr(*lines: str) -> list[Item]:
    from btht.app.monitor.items import Item, Kind, Severity

    return [
        Item(
            key=f"frr:{i}",
            collector="M-RT-01",
            kind=Kind.CONFIG,
            value=line,
            severity=Severity.HIGH,
            label="routing",
        )
        for i, line in enumerate(lines)
    ]


def test_ospf_without_passive_default_fails() -> None:
    """The load-bearing OSPF-backdoor defence — without it, any segment can peer."""
    from btht.app.validate.posture import Result, check_routing

    items = _frr("username admin", "router ospf", "network 10.0.0.0/24 area 0")
    check = next(c for c in check_routing(items) if c.id == "H-FRR-04")
    assert check.result is Result.FAIL
    assert "attached segment" in check.detail


def test_ospf_with_passive_default_and_auth_passes() -> None:
    from btht.app.validate.posture import Result, check_routing

    items = _frr(
        "username admin",
        "router ospf",
        "passive-interface default",
        "interface eth1",
        "ip ospf message-digest-key 1 md5 secret",
        "ospf authentication message-digest",
    )
    ids = {c.id: c.result for c in check_routing(items)}
    assert ids["H-FRR-04"] is Result.PASS
    assert ids["H-FRR-05"] is Result.PASS


def test_a_router_not_running_ospf_is_not_marked_down_for_it() -> None:
    """Static-only routers must not fail an OSPF check that does not apply to them."""
    from btht.app.validate.posture import check_routing

    items = _frr("username admin", "ip route 0.0.0.0/0 10.0.0.1")
    assert not any(c.id in ("H-FRR-04", "H-FRR-05") for c in check_routing(items))
