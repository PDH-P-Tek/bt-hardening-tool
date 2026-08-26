"""Segment types — the kinds of network segment a range has.

Shipped as a default list so nobody starts from an empty box, and editable so nobody
is stuck with names that do not match their range. The same shape as services and host
templates: the tool proposes, the operator confirms.

Free text was the wrong answer here. It let the same segment be spelled two ways —
`svrs` on one enclave and `servers` on another — and then a policy written for one
silently did not apply to the other, with nothing to show for it.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True, slots=True)
class SegmentType:
    name: str
    descr: str = ""
    custom: bool = False


def load_segment_types(path: Path) -> dict[str, SegmentType]:
    if not path.exists():
        return {}
    data: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return {
        str(name): SegmentType(
            name=str(name),
            descr=str((spec or {}).get("descr", "")),
            custom=bool((spec or {}).get("custom", False)),
        )
        for name, spec in (data.get("segment_types") or {}).items()
    }


def save_segment_types(types: dict[str, SegmentType], path: Path) -> None:
    data: dict[str, Any] = {}
    if path.exists():
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    data["segment_types"] = {
        name: {
            **({"descr": t.descr} if t.descr else {}),
            **({"custom": True} if t.custom else {}),
        }
        for name, t in sorted(types.items())
    }
    path.write_text(
        yaml.safe_dump(data, sort_keys=False, default_flow_style=False, allow_unicode=True),
        encoding="utf-8",
    )
