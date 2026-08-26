"""Phase 1 milestone — `python -m btht map`.

The map is the first output a human reads, so these assert what it *says*, not
just that it ran. Two lines on it are worth the whole command: which segment
anti-lockout is actually protecting, and which side a firewall is on when its
internals disagree with its WAN.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from btht.__main__ import main

BASELINE = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "baseline"

SETUP = """
interface_roles:
  recognised: [wan, ws, svrs, dmz, port1, port2, stbd1, stbd2]
  enclave_tokens: [bt_wan_, hn_wan_, dsoc_, do_, mcu_]
sides:
  - {network: "25.0.0.0/8", label: deployed}
  - {network: "10.0.0.0/8", label: host_nation}
"""


@pytest.fixture
def setup_file(tmp_path: Path) -> Path:
    path = tmp_path / "setup.yaml"
    path.write_text(SETUP, encoding="utf-8")
    return path


def test_map_resolves_roles_from_the_declared_setup(
    setup_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["map", str(BASELINE / "do-baseline.xml"), "--setup", str(setup_file)]) == 0
    out = capsys.readouterr().out
    assert "lan      ws" in out
    assert "side: deployed" in out
    assert "unresolved" not in out


def test_map_shows_the_inverted_enclave_for_what_it_is(
    setup_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The operator has to be able to see that anti-lockout is on the servers here."""
    assert main(["map", str(BASELINE / "dsoc-baseline.xml"), "--setup", str(setup_file)]) == 0
    out = capsys.readouterr().out
    lan_line = next(line for line in out.splitlines() if line.strip().startswith("lan"))
    assert "svrs" in lan_line
    assert "anti-lockout binds here" in lan_line


def test_map_labels_the_straddling_firewall_from_its_wan(
    setup_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["map", str(BASELINE / "mcu-baseline.xml"), "--setup", str(setup_file)]) == 0
    out = capsys.readouterr().out
    assert "side: host_nation" in out
    assert "25.42.26.1" in out, "its internals are in the other side's range"


def test_map_without_a_setup_declares_nothing_and_says_so(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """No silent defaults. Undeclared interfaces are reported as needing declaration."""
    assert main(["map", str(BASELINE / "do-baseline.xml")]) == 0
    out = capsys.readouterr().out
    assert "side: (not declared)" in out
    assert "3 interface(s) unresolved" in out
    assert "other:do_ws ?" in out


def test_map_reports_a_bad_file_without_a_traceback(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bad = tmp_path / "not-a-config.xml"
    bad.write_text("<opnsense/>", encoding="utf-8")
    assert main(["map", str(bad)]) == 1
    assert "expected 'pfsense'" in capsys.readouterr().err


# --- classify --------------------------------------------------------------


def test_classify_reports_a_clean_baseline_as_needing_no_triage(
    setup_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = Path(__file__).resolve().parents[1]
    assert (
        main(
            [
                "classify",
                str(BASELINE / "do-baseline.xml"),
                "--setup",
                str(setup_file),
                "--profile",
                str(root / "seed-profile.yaml"),
                "--team",
                "42",
            ]
        )
        == 0
    )
    out = capsys.readouterr().out
    assert "everything recognised" in out
    assert "permissive_default" in out, "and it says which rules are the open doors"


def test_classify_names_what_still_needs_a_decision(
    setup_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The lockout-critical flag has to survive onto the screen, not just into the model."""
    root = Path(__file__).resolve().parents[1]
    assert (
        main(
            [
                "classify",
                str(BASELINE / "mcu-baseline.xml"),
                "--setup",
                str(setup_file),
                "--profile",
                str(root / "seed-profile.yaml"),
                "--team",
                "42",
            ]
        )
        == 0
    )
    out = capsys.readouterr().out
    assert "need a decision" in out
    assert "LOCKOUT-CRITICAL" in out
