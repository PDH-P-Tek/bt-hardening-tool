"""Turning change into evidence — `monitor/sessions.py`.

The tool's stated purpose is monitoring for evidence of Red Team activity, and detecting
change is only half of that. These tests pin the join that makes the other half work, and
just as importantly they pin its limits: a session near a change is a lead, and the code
must not be able to drift into asserting more than that.

The strongest signal here is the last one — a login whose key fingerprint is not in the
box's own authorised-key inventory. That is not ambiguous, and it only exists because
`M-AUTH-01` and `H-SSH-19` are collected together.
"""

from __future__ import annotations

from datetime import timedelta

from btht.app.monitor.sessions import (
    Session,
    around,
    merge,
    parse_accepted,
    parse_last,
    unknown_keys,
)

LAST = """\
admin    pts/0        10.20.30.40      Wed Aug 27 14:31:02 2026   still logged in
svc      pts/1        10.20.30.41      Wed Aug 27 09:02:11 2026 - Wed Aug 27 11:14:55 2026  (02:12)
reboot   system boot  6.6.0            Wed Aug 27 08:00:00 2026   still running
"""

AUTH = """\
Aug 27 14:31:01 r1 sshd[1234]: Accepted publickey for admin from 10.20.30.40 port 55123 ssh2: ED25519 SHA256:AAAAknown
Aug 27 09:02:10 r1 sshd[1000]: Accepted publickey for svc from 10.20.30.41 port 4111 ssh2: RSA SHA256:BBBBstrange
"""


def test_a_login_is_read_with_its_year() -> None:
    """`last -F` is used precisely for this: without the year a session cannot be placed."""
    sessions = parse_last(LAST)
    assert [s.user for s in sessions] == ["admin", "svc"]
    assert sessions[0].started.startswith("2026-08-27T14:31:02")
    assert sessions[0].ended == "", "still logged in"
    assert sessions[1].ended.startswith("2026-08-27T11:14:55")


def test_boot_records_are_not_people() -> None:
    """`reboot` in wtmp is the machine working, not somebody doing something."""
    assert all(s.user != "reboot" for s in parse_last(LAST))


def test_the_key_fingerprint_is_read_from_the_auth_log() -> None:
    """`H-SSH-19` exists to put this fingerprint in the log; this is what it buys."""
    accepted = parse_accepted(AUTH, year=2026)
    assert accepted[0].fingerprint == "SHA256:AAAAknown"
    assert accepted[0].user == "admin"
    assert accepted[0].source == "10.20.30.40"


def test_the_two_sources_are_joined_on_account_source_and_time() -> None:
    """`last` and syslog record the same login a second or two apart."""
    merged = merge(parse_last(LAST), parse_accepted(AUTH, year=2026))
    admin = next(s for s in merged if s.user == "admin")
    assert admin.fingerprint == "SHA256:AAAAknown"
    assert admin.ended == "", "the session record's own state survives the join"


def test_an_authentication_with_no_matching_login_record_is_kept() -> None:
    """A login sshd recorded and wtmp did not is itself worth seeing."""
    orphan = "Aug 27 03:00:00 r1 sshd[9]: Accepted publickey for root from 10.9.9.9 port 1 ssh2: ED25519 SHA256:CCCC\n"
    merged = merge(parse_last(LAST), parse_accepted(AUTH + orphan, year=2026))
    assert any(s.user == "root" and s.fingerprint == "SHA256:CCCC" for s in merged)


# --- the window -------------------------------------------------------------


def test_a_session_open_at_the_moment_of_the_change_is_returned() -> None:
    sessions = merge(parse_last(LAST), parse_accepted(AUTH, year=2026))
    found = around(sessions, "2026-08-27T14:45:00+00:00")
    assert [s.user for s in found] == ["admin"], "still open, so it covers 14:45"


def test_a_session_that_had_already_ended_is_not_returned() -> None:
    """The limit that keeps this honest: it must not sweep in everybody who was ever on."""
    sessions = merge(parse_last(LAST), parse_accepted(AUTH, year=2026))
    found = around(sessions, "2026-08-27T13:00:00+00:00", window=timedelta(minutes=15))
    assert [s.user for s in found] == [], "svc logged out at 11:14, well outside the window"


def test_a_login_shortly_before_the_change_still_counts() -> None:
    """A change is noticed on the next poll, so its cause is always a little earlier."""
    sessions = parse_last(LAST)
    assert around(sessions, "2026-08-27T09:00:00+00:00", window=timedelta(minutes=15))


def test_an_unparseable_time_returns_nothing_rather_than_everything() -> None:
    """Failing open here would attribute every change to every session on the box."""
    assert around(parse_last(LAST), "not a timestamp") == ()


# --- the signal that is not ambiguous ---------------------------------------


def test_a_key_nobody_issued_is_singled_out() -> None:
    sessions = merge(parse_last(LAST), parse_accepted(AUTH, year=2026))
    strangers = unknown_keys(sessions, frozenset({"SHA256:AAAAknown"}))
    assert [s.user for s in strangers] == ["svc"]
    assert strangers[0].fingerprint == "SHA256:BBBBstrange"


def test_a_session_with_no_recorded_fingerprint_is_not_accused() -> None:
    """No fingerprint means the log did not say — which is not the same as unknown."""
    assert unknown_keys((Session(user="a", source="1.1.1.1", started="x"),), frozenset()) == ()


def test_malformed_input_yields_nothing_rather_than_raising() -> None:
    assert parse_last("not a last listing at all") == ()
    assert parse_accepted("nothing here") == ()
