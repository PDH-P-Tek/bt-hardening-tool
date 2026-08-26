"""Phase 4.4 — the diff and the export gate.

The gate is the last thing between a generated ruleset and a live firewall, and the
failure it exists to catch is a *plausible* ruleset: one that reads correctly,
generates cleanly, and is wrong in a way nobody notices until a probe fails.

So the two properties that matter are arithmetic rather than presentational. Blocking
findings cannot be acknowledged away, and warnings must be acknowledged one at a time.
"""

from __future__ import annotations

from dataclasses import replace

from conftest import a_ruleset

from btht.app.generate.diff import Gate, diff_rulesets, gate_for
from btht.app.ingest.isa import load_catalogue
from btht.app.model.rules import Action, Rule
from btht.app.validate.rules import Finding, Severity

CATALOGUE = load_catalogue(None)


def a_finding(check_id: str, severity: Severity, item: str = "") -> Finding:
    return Finding(check_id, severity, f"{check_id} fired", item)


# --- the diff --------------------------------------------------------------


def test_the_diff_separates_kept_added_and_removed() -> None:
    ruleset = a_ruleset()
    baseline = (Rule(action=Action.PASS, interfaces=("wan",), descr="an old rule"),)
    diff = diff_rulesets(baseline, ruleset)
    assert diff.counts["added"] > 0
    assert diff.counts["removed"] == 1
    assert diff.removed[0].description == "an old rule"


def test_the_diff_compares_by_fingerprint_not_by_description() -> None:
    """`EVIDENCE.md` E7 — a rule kept its label while its source was widened.

    Comparing labels would have called that unchanged. It is a different rule.
    """
    from btht.app.model.rules import AliasRef, AnyEndpoint

    ruleset = a_ruleset()
    # The management rule: sourced from an alias, exactly the shape that was widened
    # in the evidence while its description stayed the same.
    generated = next(g for g in ruleset.all_rules() if isinstance(g.rule.source, AliasRef))
    widened = replace(generated.rule, source=AnyEndpoint())
    diff = diff_rulesets((widened,), ruleset)

    assert any(c.description == widened.descr for c in diff.removed), (
        "the widened rule is not the generated one, so it must show as removed"
    )
    assert any(c.description == generated.rule.descr for c in diff.added), (
        "and the real one as added — comparing descriptions would have called this kept"
    )


def test_the_action_is_carried_on_every_change() -> None:
    """`EVIDENCE.md` E3 — three rules said BLOCK and did pass. Show the action."""
    diff = diff_rulesets((), a_ruleset())
    assert all(change.action in ("PASS", "BLOCK", "REJECT") for change in diff.added)


# --- the gate --------------------------------------------------------------


def test_a_clean_ruleset_may_export() -> None:
    assert gate_for(()).may_export is True


def test_a_blocking_finding_stops_export_and_cannot_be_acknowledged() -> None:
    """No override. Each blocking finding is a way to be wrong while looking right."""
    findings = (a_finding("V-MGMT-ABSENT", Severity.BLOCKING),)
    gate = gate_for(findings)
    assert gate.may_export is False

    everything = frozenset(Gate.key(f) for f in findings)
    still_blocked = gate_for(findings, acknowledged=everything)
    assert still_blocked.may_export is False, "blocking findings are not acknowledgeable"
    assert "cannot be acknowledged away" in still_blocked.reason


def test_warnings_are_acknowledged_one_at_a_time() -> None:
    """A single accept-all button is how thirty findings become one click."""
    findings = (
        a_finding("V-ICMP6-MINIMUM", Severity.WARNING),
        a_finding("V-ALIAS-NAME-HYGIENE", Severity.WARNING, "Temp"),
    )
    gate = gate_for(findings)
    assert gate.may_export is False
    assert len(gate.unacknowledged) == 2

    one = gate_for(findings, acknowledged=frozenset({Gate.key(findings[0])}))
    assert one.may_export is False
    assert len(one.unacknowledged) == 1

    both = gate_for(findings, acknowledged=frozenset(Gate.key(f) for f in findings))
    assert both.may_export is True


def test_acknowledgement_is_per_finding_not_per_id() -> None:
    """Two findings from one validator are two decisions."""
    findings = (
        a_finding("V-ALIAS-NAME-HYGIENE", Severity.WARNING, "Temp"),
        a_finding("V-ALIAS-NAME-HYGIENE", Severity.WARNING, "test_rule"),
    )
    gate = gate_for(findings, acknowledged=frozenset({Gate.key(findings[0])}))
    assert gate.may_export is False
    assert gate.unacknowledged[0].item == "test_rule"


def test_info_findings_do_not_gate_anything() -> None:
    gate = gate_for((a_finding("V-SCORING-UNCHECKED", Severity.INFO),))
    assert gate.may_export is True


def test_the_gate_says_why_in_words() -> None:
    blocked = gate_for((a_finding("V-OOB-BLOCKED", Severity.BLOCKING),))
    assert "blocking finding" in blocked.reason
    warned = gate_for((a_finding("V-ICMP6-MINIMUM", Severity.WARNING),))
    assert "no accept-all, on purpose" in warned.reason
    assert gate_for(()).reason == "Ready to export."
