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
    assert "H-Q4" in check.remediation, "whether the exercise permits it is still open"


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
