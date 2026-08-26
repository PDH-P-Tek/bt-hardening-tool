"""The diff gate — `SPEC.md` §9. The last thing between a ruleset and a firewall.

**Nothing leaves without passing through here.** Not because a diff is a nice feature,
but because the failure this tool exists to prevent is a plausible ruleset: one that
reads correctly, generates cleanly, and is wrong in a way nobody notices until a probe
fails or a team is locked out.

So the gate is arithmetic, not judgement. Blocking findings stop export outright and
cannot be overridden. Warnings must be acknowledged **individually** — a single
"acknowledge all" button is how thirty findings become one click, and at that point the
gate has stopped being a gate.
"""

from __future__ import annotations

from dataclasses import dataclass

from btht.app.generate.order import Ruleset
from btht.app.ingest.fingerprint import strict_fingerprint
from btht.app.model.rules import Rule
from btht.app.validate.rules import Finding, Severity


@dataclass(frozen=True, slots=True)
class Change:
    kind: str
    """`kept` · `added` · `removed`."""

    description: str
    intent: str = ""
    action: str = ""
    """Shown prominently on purpose — `EVIDENCE.md` E3, where three rules labelled
    BLOCK had action `pass`. The label is what a tired reader believes."""


@dataclass(frozen=True, slots=True)
class Diff:
    kept: tuple[Change, ...] = ()
    added: tuple[Change, ...] = ()
    removed: tuple[Change, ...] = ()

    @property
    def counts(self) -> dict[str, int]:
        return {"kept": len(self.kept), "added": len(self.added), "removed": len(self.removed)}


def diff_rulesets(baseline: tuple[Rule, ...], ruleset: Ruleset) -> Diff:
    """Compare by fingerprint, never by description.

    A rule whose description was kept while its source was widened is a *different*
    rule, and the diff has to say so — that is `EVIDENCE.md` E7.
    """
    before = {strict_fingerprint(rule): rule for rule in baseline}
    after = {strict_fingerprint(g.rule): g for g in ruleset.all_rules()}

    kept: list[Change] = []
    added: list[Change] = []
    removed: list[Change] = []
    for digest, generated in after.items():
        change = Change(
            kind="kept" if digest in before else "added",
            description=generated.rule.descr or "(no description)",
            intent=generated.intent,
            action=generated.rule.action.value.upper(),
        )
        (kept if digest in before else added).append(change)
    for digest, rule in before.items():
        if digest not in after:
            removed.append(
                Change(
                    kind="removed",
                    description=rule.descr or "(no description)",
                    action=rule.action.value.upper(),
                )
            )
    return Diff(tuple(kept), tuple(added), tuple(removed))


@dataclass(frozen=True, slots=True)
class Gate:
    """Whether this ruleset may be exported, and what is standing in the way."""

    blocking: tuple[Finding, ...] = ()
    warnings: tuple[Finding, ...] = ()
    acknowledged: frozenset[str] = frozenset()

    @property
    def unacknowledged(self) -> tuple[Finding, ...]:
        return tuple(f for f in self.warnings if self.key(f) not in self.acknowledged)

    @staticmethod
    def key(finding: Finding) -> str:
        """Identifies one finding for acknowledgement. Per finding, never per severity."""
        return f"{finding.id}|{finding.item}"

    @property
    def may_export(self) -> bool:
        return not self.blocking and not self.unacknowledged

    @property
    def reason(self) -> str:
        if self.blocking:
            return (
                f"{len(self.blocking)} blocking finding(s). These cannot be acknowledged "
                "away — each one is a way for this ruleset to be wrong while looking right."
            )
        if self.unacknowledged:
            return (
                f"{len(self.unacknowledged)} warning(s) not yet acknowledged. Acknowledge "
                "them one at a time; there is no accept-all, on purpose."
            )
        return "Ready to export."


def gate_for(findings: tuple[Finding, ...], acknowledged: frozenset[str] = frozenset()) -> Gate:
    return Gate(
        blocking=tuple(f for f in findings if f.severity is Severity.BLOCKING),
        warnings=tuple(f for f in findings if f.severity is Severity.WARNING),
        acknowledged=acknowledged,
    )
