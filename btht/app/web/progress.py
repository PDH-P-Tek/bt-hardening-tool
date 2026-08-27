"""What the operator has already decided.

Two things need to outlive a restart. **Acknowledged findings**: the diff gate refuses
to export until a person has looked at each warning and accepted it, and holding those
decisions in a module-level dict meant a container restart silently threw them away and
slammed the gate shut again — during an exercise, with the clock running. **Sign-off**:
which enclaves a person has actually read the rules for, which is what the next-step
guidance keys off.

Deliberately a plain JSON file beside the estate rather than a table in the monitor's
database. It is operator progress, not collected state, and the monitor's store is
allowed to be deleted and rebuilt from the boxes without losing any of this.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Progress:
    """Decisions a person has made, keyed by enclave."""

    #: enclave -> the gate-warning keys accepted for it
    acknowledged: dict[str, set[str]] = field(default_factory=dict)
    #: enclaves whose generated rules a person has read and signed off
    signed_off: set[str] = field(default_factory=set)

    def keys_for(self, enclave: str) -> frozenset[str]:
        return frozenset(self.acknowledged.get(enclave, set()))

    def acknowledge(self, enclave: str, key: str) -> None:
        self.acknowledged.setdefault(enclave, set()).add(key)

    def sign_off(self, enclave: str) -> None:
        self.signed_off.add(enclave)

    def withdraw(self, enclave: str) -> None:
        """Editing a policy invalidates a sign-off — the rules are no longer the ones read."""
        self.signed_off.discard(enclave)
        self.acknowledged.pop(enclave, None)


def path_for(estate_path: Path) -> Path:
    return estate_path.with_name("progress.json")


def load(estate_path: Path) -> Progress:
    """A missing or unreadable file means no decisions yet, never a crash.

    Losing progress is bad; refusing to start the tool because a scratch file is
    malformed is worse, and happens at the least convenient moment.
    """
    path = path_for(estate_path)
    if not path.exists():
        return Progress()
    try:
        raw = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return Progress()
    if not isinstance(raw, dict):
        return Progress()
    acknowledged = {
        str(enclave): {str(k) for k in keys}
        for enclave, keys in (raw.get("acknowledged") or {}).items()
        if isinstance(keys, list)
    }
    return Progress(
        acknowledged=acknowledged,
        signed_off={str(e) for e in (raw.get("signed_off") or [])},
    )


def save(progress: Progress, estate_path: Path) -> None:
    path = path_for(estate_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "acknowledged": {e: sorted(k) for e, k in progress.acknowledged.items()},
                "signed_off": sorted(progress.signed_off),
            },
            indent=2,
        )
    )
