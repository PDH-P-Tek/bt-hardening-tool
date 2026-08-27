"""Decisions that have to outlive a restart.

Acknowledgements lived in a module-level dict. A container restart therefore threw away
every decision a person had made about the diff gate and slammed it shut again — during
an exercise, with the clock running and no way to tell that was what had happened.
"""

from __future__ import annotations

from pathlib import Path

from btht.app.web import progress


def test_acknowledgements_survive_a_restart(tmp_path: Path) -> None:
    estate = tmp_path / "range.yaml"
    state = progress.load(estate)
    state.acknowledge("do", "V-ORDER-01|wan")
    progress.save(state, estate)

    assert progress.load(estate).keys_for("do") == frozenset({"V-ORDER-01|wan"})


def test_sign_off_is_per_enclave(tmp_path: Path) -> None:
    estate = tmp_path / "range.yaml"
    state = progress.load(estate)
    state.sign_off("do")
    progress.save(state, estate)

    reloaded = progress.load(estate)
    assert "do" in reloaded.signed_off
    assert "ds" not in reloaded.signed_off


def test_changing_a_policy_withdraws_the_sign_off(tmp_path: Path) -> None:
    """The rules are no longer the ones anybody read."""
    state = progress.Progress()
    state.sign_off("do")
    state.acknowledge("do", "k")
    state.withdraw("do")
    assert state.signed_off == set()
    assert state.keys_for("do") == frozenset()


def test_a_missing_file_is_no_decisions_rather_than_a_crash(tmp_path: Path) -> None:
    assert progress.load(tmp_path / "nothing.yaml").signed_off == set()


def test_a_corrupt_file_does_not_stop_the_tool_starting(tmp_path: Path) -> None:
    """Losing progress is bad. Refusing to start because a scratch file is malformed is
    worse, and happens at the least convenient moment."""
    estate = tmp_path / "range.yaml"
    progress.path_for(estate).write_text("{not json at all")
    assert progress.load(estate).signed_off == set()
