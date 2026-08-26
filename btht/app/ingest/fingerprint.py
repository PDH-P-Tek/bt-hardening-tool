"""Two-tier fingerprints — `SPEC.md` §6.2.

Identity comes from what a rule *does*, never from what it is called. Descriptions are
display only: in the observed estate three rules labelled BLOCK had action `pass`
(`EVIDENCE.md` E3), and a baseline rule was widened while keeping its original label
(E7). A tool that trusted labels would have agreed with both.

**Strict** — the exact rule. An exact match applies the stored classification silently,
with no prompt, which is what keeps triage short enough that people read it.

**Structural** — the same shape with endpoint contents ignored. A structural-only match
is the interesting case: same rule, different membership. It prompts, with the delta
stated in words, because that is precisely the change someone made on purpose and the
change an attacker would make quietly.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from btht.app.ingest.normalise import Template, canonical_rule
from btht.app.model.rules import Alias, Rule


def canonical_json(value: Any) -> str:
    """One text form for one structure. Sorted keys, no incidental whitespace.

    Determinism starts here: `SPEC.md` §12.9 requires byte-identical output across
    runs and processes, so nothing downstream may depend on dict insertion order.
    """
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(payload: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def strict_fingerprint(
    rule: Rule,
    aliases: dict[str, Alias] | None = None,
    template: Template | None = None,
    all_roles: frozenset[str] | None = None,
) -> str:
    return _digest(canonical_rule(rule, aliases or {}, template or Template(), all_roles=all_roles))


def structural_fingerprint(
    rule: Rule,
    aliases: dict[str, Alias] | None = None,
    template: Template | None = None,
    all_roles: frozenset[str] | None = None,
) -> str:
    return _digest(
        canonical_rule(
            rule, aliases or {}, template or Template(), structural=True, all_roles=all_roles
        )
    )


def fingerprints(
    rule: Rule,
    aliases: dict[str, Alias] | None = None,
    template: Template | None = None,
    all_roles: frozenset[str] | None = None,
) -> tuple[str, str]:
    """Both tiers at once. Cheaper than two passes and keeps them in step."""
    return (
        strict_fingerprint(rule, aliases, template, all_roles),
        structural_fingerprint(rule, aliases, template, all_roles),
    )
