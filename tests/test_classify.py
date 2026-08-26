"""Phase 1.4 — loading the shipped profile and classifying a configuration.

The measure of this step is how much triage it removes. A baseline that arrives
fully recognised takes a minute to confirm; the same baseline arriving as thirty
unknown items takes the morning, and the morning is not available.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from btht.app.ingest.classify import Tier, classify_aliases, classify_rules
from btht.app.ingest.normalise import Template, alias_table
from btht.app.ingest.pfsense import parse_file
from btht.app.ingest.roles import RoleConvention, apply_roles, derive_interfaces
from btht.app.model.profile import load_profile
from btht.app.model.rules import Action, AnyEndpoint, Disposition, Role, Rule

ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "tests" / "fixtures" / "baseline"

DECLARED = RoleConvention(
    vocabulary=("wan", "ws", "svrs", "dmz", "uav", "port1", "port2", "stbd1", "stbd2"),
    enclave_tokens=("bt_wan_", "hn_wan_", "dsoc_", "do_", "ds_", "mcu_"),
)
TEMPLATE = Template(number=42, padded="42")


@pytest.fixture(scope="module")
def profile():  # type: ignore[no-untyped-def]
    return load_profile(ROOT / "seed-profile.yaml")


def ingest(enclave: str):  # type: ignore[no-untyped-def]
    parsed = parse_file(BASELINE / f"{enclave}-baseline.xml")
    interfaces = derive_interfaces(parsed.interfaces, DECLARED)
    roles = frozenset(i.role for i in interfaces)
    rules = apply_roles(parsed.rules, {i.ifname: i.role for i in interfaces})
    return rules, alias_table(parsed.aliases), parsed.aliases, roles


# --- the profile itself ----------------------------------------------------


def test_the_shipped_profile_loads(profile) -> None:  # type: ignore[no-untyped-def]
    assert profile.version == 1
    assert len(profile.rules) == 8
    assert len(profile.aliases) == 2


def test_the_profile_carries_its_known_defect(profile) -> None:  # type: ignore[no-untyped-def]
    """`BASELINE-ANALYSIS.md` F1 travels with the item, so the tool does not "fix" it blindly."""
    routers = next(a for a in profile.aliases if a.alias.name == "Routers")
    assert routers.known_defect is not None
    assert routers.known_defect.id == "F1"
    assert "V-ALIAS-FAMILY" in routers.known_defect.validators


def test_the_lockout_critical_alias_is_flagged(profile) -> None:  # type: ignore[no-untyped-def]
    """Narrow or drop it and the team loses access to its own firewalls."""
    remote = next(a for a in profile.aliases if a.alias.name == "Remote_Access")
    assert remote.lockout_critical is True


def test_the_profile_holds_no_hashes() -> None:
    """`seed-profile.yaml` is declarative — fingerprints are computed at load.

    A hand-written hash drifts from the implementation the moment normalisation
    changes, and then silently matches nothing.
    """
    text = (ROOT / "seed-profile.yaml").read_text(encoding="utf-8")
    assert "sha256:" not in text.lower()


# --- a clean ingest --------------------------------------------------------


@pytest.mark.parametrize("enclave", ("do", "dsoc"))
def test_a_known_baseline_is_recognised_entirely(enclave: str, profile) -> None:  # type: ignore[no-untyped-def]
    """Every rule exact-matched means no triage at all on this firewall."""
    rules, aliases, raw_aliases, roles = ingest(enclave)
    matches = classify_rules(rules, aliases, profile, TEMPLATE, roles)
    assert {m.tier for m in matches} == {Tier.STRICT}
    assert not any(m.needs_a_human for m in matches)
    assert {m.tier for m in classify_aliases(raw_aliases, profile, TEMPLATE)} == {Tier.STRICT}


def test_the_inverted_enclave_is_recognised_too(profile) -> None:  # type: ignore[no-untyped-def]
    """The role layer and the profile have to work together, not just separately.

    The rule on this firewall's `lan` covers servers. The profile describes a rule
    per internal segment. Both agree only because identity is built on roles.
    """
    rules, aliases, _, roles = ingest("dsoc")
    matches = classify_rules(rules, aliases, profile, TEMPLATE, roles)
    on_servers = [m for m in matches if m.rule.interfaces == ("svrs",)]
    assert on_servers and all(m.tier is Tier.STRICT for m in on_servers)
    assert all(m.role is Role.PERMISSIVE_DEFAULT for m in on_servers)


# --- the finding that costs the most ---------------------------------------


@pytest.mark.parametrize(("enclave", "expected"), [("do", 4), ("dsoc", 3), ("mcu", 6)])
def test_every_permissive_default_is_identified(enclave: str, expected: int, profile) -> None:  # type: ignore[no-untyped-def]
    """`EVIDENCE.md` E1 — every enclave finished the exercise with these live.

    They must arrive labelled `permissive_default` and dispositioned for replacement,
    not as unknown items competing for attention with everything else.
    """
    rules, aliases, _, roles = ingest(enclave)
    matches = classify_rules(rules, aliases, profile, TEMPLATE, roles)
    permissive = [m for m in matches if m.role is Role.PERMISSIVE_DEFAULT]
    assert len(permissive) == expected
    assert all(m.disposition is Disposition.REPLACE_GENERATED for m in permissive)


def test_segments_the_profile_never_saw_are_still_recognised(profile) -> None:  # type: ignore[no-untyped-def]
    """A per-segment entry expands over the firewall's segments, not the profile's list.

    This firewall has segments the profile was never written against. Their permissive
    defaults are the same shipped rule and must be classified as such.
    """
    rules, aliases, _, roles = ingest("mcu")
    matches = classify_rules(rules, aliases, profile, TEMPLATE, roles)
    unseen = [m for m in matches if m.rule.interfaces in (("port1",), ("stbd2",))]
    assert len(unseen) == 2
    assert all(m.tier is Tier.STRICT for m in unseen)
    assert all(m.role is Role.PERMISSIVE_DEFAULT for m in unseen)


# --- the structural tier ---------------------------------------------------


def test_different_membership_matches_structurally_and_not_strictly(profile) -> None:  # type: ignore[no-untyped-def]
    """This firewall's aliases hold different addresses for the same purpose.

    Recognised as the same items, but never applied silently — the operator is shown
    what differs and decides. That is the whole reason for a second tier.
    """
    _, _, raw_aliases, _ = ingest("mcu")
    matches = {m.alias.name: m for m in classify_aliases(raw_aliases, profile, TEMPLATE)}
    assert matches["Routers"].tier is Tier.STRUCTURAL
    assert matches["Remote_Access"].tier is Tier.STRUCTURAL
    assert matches["Remote_Access"].lockout_critical is True, (
        "a structural match still carries its lockout flag"
    )


def test_only_an_exact_match_is_applied_silently(profile) -> None:  # type: ignore[no-untyped-def]
    rules, aliases, _, roles = ingest("mcu")
    matches = classify_rules(rules, aliases, profile, TEMPLATE, roles)
    for match in matches:
        assert match.needs_a_human == (match.tier is not Tier.STRICT)


# --- new items -------------------------------------------------------------


def test_an_unknown_rule_is_reported_as_unknown_not_guessed(profile) -> None:  # type: ignore[no-untyped-def]
    """`SPEC.md` §12: an item left `unknown` blocks export. Never a guess."""
    rules, aliases, _, roles = ingest("do")
    invented = Rule(
        action=Action.BLOCK,
        interfaces=("ws",),
        quick=True,
        source=AnyEndpoint(),
        destination=AnyEndpoint(),
        descr="something the team added at 3am",
    )
    matches = classify_rules((*rules, invented), aliases, profile, TEMPLATE, roles)
    new = matches[-1]
    assert new.tier is Tier.NONE
    assert new.role is Role.UNKNOWN
    assert new.needs_a_human


def test_a_label_does_not_make_a_rule_familiar(profile) -> None:  # type: ignore[no-untyped-def]
    """`EVIDENCE.md` E3. Copying a baseline description onto a different rule
    must not inherit the baseline's classification."""
    rules, aliases, _, roles = ingest("do")
    genuine = next(r for r in rules if r.descr == "VPN access for exercise participants")
    impostor = replace(genuine, action=Action.BLOCK, source=AnyEndpoint())
    matches = classify_rules((impostor,), aliases, profile, TEMPLATE, roles)
    assert matches[0].tier is Tier.NONE
    assert matches[0].role is Role.UNKNOWN
