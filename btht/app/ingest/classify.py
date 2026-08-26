"""Matching a configuration against a profile — `SPEC.md` §6.2, §6.3.

Three outcomes per item, and the difference between them is what decides whether
triage takes two minutes or forty:

- **strict** — the exact item. Its stored classification applies silently.
- **structural** — the same rule with different contents. Prompts, with the delta
  in words. This is both the change someone made deliberately and the change an
  attacker would make quietly, which is why it is never applied silently.
- **none** — new. Role defaults to `unknown`, which blocks export until a human
  decides.

Nothing here guesses. An unmatched item is reported as unmatched.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum

from btht.app.ingest.fingerprint import strict_fingerprint, structural_fingerprint
from btht.app.ingest.normalise import Template, canonical_entries
from btht.app.ingest.roles import PF_WAN_IFNAME
from btht.app.model.profile import Profile, ProfileAlias, ProfileRule
from btht.app.model.rules import Alias, Disposition, Role, Rule


class Tier(StrEnum):
    STRICT = "strict"
    STRUCTURAL = "structural"
    NONE = "none"


@dataclass(frozen=True, slots=True)
class RuleMatch:
    rule: Rule
    tier: Tier
    entry: ProfileRule | None = None

    @property
    def role(self) -> Role:
        return self.entry.role if self.entry else Role.UNKNOWN

    @property
    def disposition(self) -> Disposition:
        return self.entry.disposition if self.entry else Disposition.KEEP_VERBATIM

    @property
    def needs_a_human(self) -> bool:
        """Structural and unmatched both do. Only an exact match is applied silently."""
        return self.tier is not Tier.STRICT


@dataclass(frozen=True, slots=True)
class AliasMatch:
    alias: Alias
    tier: Tier
    entry: ProfileAlias | None = None

    @property
    def role(self) -> Role:
        return self.entry.role if self.entry else Role.UNKNOWN

    @property
    def lockout_critical(self) -> bool:
        return bool(self.entry and self.entry.lockout_critical)


def _candidate_rules(entry: ProfileRule, firewall_roles: frozenset[str]) -> tuple[Rule, ...]:
    """Expand one profile entry into the rules it could appear as on this firewall.

    An entry with `applies_to_roles` describes a rule that exists once per segment.
    It is expanded across **every internal segment this firewall has**, not across the
    roles the profile lists: that list records the segments that existed when the
    profile was written, and a firewall with segments the profile never saw still has
    the same shipped baseline on them.

    The alternative — intersecting with the profile's list — was tried and is worse.
    A firewall whose segment names the profile does not know had its permissive
    defaults come back as `unknown`, so the single most expensive finding in the
    evidence arrived as "something new to classify" rather than as "a `pass any → any`
    to replace". It only matches when the entire shape matches, and any rule of that
    shape on an internal segment *is* a permissive default.

    The WAN role is excluded because an otherwise identical WAN entry exists
    separately, and expanding onto WAN would make one rule match two entries.
    """
    if not entry.applies_to_roles:
        return (entry.rule,)

    internal = firewall_roles - {PF_WAN_IFNAME}
    return tuple(replace(entry.rule, interfaces=(role,)) for role in sorted(internal))


def classify_rules(
    rules: tuple[Rule, ...],
    aliases: dict[str, Alias],
    profile: Profile,
    template: Template | None = None,
    firewall_roles: frozenset[str] | None = None,
) -> tuple[RuleMatch, ...]:
    template = template or Template()
    roles = firewall_roles or frozenset()
    profile_aliases = profile.alias_table()

    strict: dict[str, ProfileRule] = {}
    structural: dict[str, ProfileRule] = {}
    for entry in profile.rules:
        for candidate in _candidate_rules(entry, roles):
            strict.setdefault(
                strict_fingerprint(candidate, profile_aliases, template, roles), entry
            )
            structural.setdefault(
                structural_fingerprint(candidate, profile_aliases, template, roles), entry
            )

    out: list[RuleMatch] = []
    for rule in rules:
        exact = strict_fingerprint(rule, aliases, template, roles)
        if exact in strict:
            out.append(RuleMatch(rule=rule, tier=Tier.STRICT, entry=strict[exact]))
            continue
        shape = structural_fingerprint(rule, aliases, template, roles)
        if shape in structural:
            out.append(RuleMatch(rule=rule, tier=Tier.STRUCTURAL, entry=structural[shape]))
            continue
        out.append(RuleMatch(rule=rule, tier=Tier.NONE))
    return tuple(out)


def classify_aliases(
    aliases: tuple[Alias, ...], profile: Profile, template: Template | None = None
) -> tuple[AliasMatch, ...]:
    """Aliases match on name and membership; name alone is the structural tier.

    A renamed alias is a new alias — the name is how every rule refers to it, so it
    is identity here in a way a rule description never is.
    """
    template = template or Template()
    by_name = {entry.alias.name: entry for entry in profile.aliases}

    out: list[AliasMatch] = []
    for alias in aliases:
        entry = by_name.get(alias.name)
        if entry is None:
            out.append(AliasMatch(alias=alias, tier=Tier.NONE))
            continue
        same_members = canonical_entries(alias.entries, template) == canonical_entries(
            entry.alias.entries, template
        )
        out.append(
            AliasMatch(
                alias=alias,
                tier=Tier.STRICT if same_members else Tier.STRUCTURAL,
                entry=entry,
            )
        )
    return tuple(out)
