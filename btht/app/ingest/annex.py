"""Annex paste-parse — `SPEC.md` §5.2. An accelerator inside the wizard, never a path around it.

**A silent mis-parse is the failure mode this module is designed against.** Nothing it
produces is applied; it is rendered back for the operator to confirm, row by row. The
annex arrives as a table in a document, gets copied through a clipboard, and lands here
as whatever the source application felt like emitting — tabs, runs of spaces, wrapped
lines, a header row or not.

So the parser does not trust columns. It finds the addresses, which are the one thing
in a row that is unambiguous, and reads the name and description around them. That
survives a column order it has never seen, which matters because the annex format is
not ours and changes between exercises (`BASELINE-ANALYSIS.md` §4).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from ipaddress import IPv4Interface, IPv6Interface, ip_address

#: Deliberately loose. Anything address-shaped is a candidate; `ipaddress` decides.
_V4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?\b")
_V6 = re.compile(r"\b(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?:/\d{1,3})?\b")

#: A row that names columns rather than describing a thing.
_HEADINGS = re.compile(
    r"\b(host\s*name|hostname|ipv4|ipv6|subnet|device|description|domain|name)\b", re.I
)


@dataclass(frozen=True, slots=True)
class Row:
    """One parsed line, with everything needed to show it back for confirmation."""

    name: str
    v4: str = ""
    v6: str = ""
    description: str = ""
    is_network: bool = False
    """True when the IPv4 carried a prefix — a subnet row rather than a host row."""

    source_line: str = ""
    """The line exactly as pasted. Shown alongside the parse so the operator can see
    what the tool made of what they gave it."""

    @property
    def looks_complete(self) -> bool:
        return bool(self.name and (self.v4 or self.v6))


def _clean(token: str) -> str:
    return token.strip().strip(",;|").strip()


def _valid_v4(token: str) -> str:
    try:
        if "/" in token:
            return str(IPv4Interface(token))
        return str(ip_address(token))
    except ValueError:
        return ""


def _valid_v6(token: str) -> str:
    try:
        if "/" in token:
            return str(IPv6Interface(token))
        return str(ip_address(token))
    except ValueError:
        return ""


def parse_rows(text: str) -> tuple[Row, ...]:
    """Parse pasted annex text. Never raises: an unreadable line comes back unreadable.

    A row the parser could not make sense of is still returned, with whatever it did
    find, so the operator sees the gap rather than the line silently disappearing.
    Losing a host quietly is worse than showing a row that needs fixing by hand.
    """
    rows: list[Row] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue

        v4_matches = [m for m in (_valid_v4(_clean(t)) for t in _V4.findall(line)) if m]
        v6_matches = [m for m in (_valid_v6(_clean(t)) for t in _V6.findall(line)) if m]

        if not v4_matches and not v6_matches:
            # A heading, a section title, or prose. Headings are dropped; anything
            # else is kept as a row with no address so it is visible in the preview.
            if _HEADINGS.search(line) or len(line.split()) > 12:
                continue
            rows.append(Row(name=line.split()[0], description=line, source_line=raw))
            continue

        first = min(
            (
                line.find(a.split("/")[0])
                for a in (*v4_matches, *v6_matches)
                if a.split("/")[0] in line
            ),
            default=len(line),
        )
        name = _clean(line[:first]).split("\t")[0].strip() if first else ""
        name = re.split(r"\s{2,}|\t", name)[0].strip() if name else ""

        last_address = max(
            (
                line.rfind(a.split("/")[0]) + len(a.split("/")[0])
                for a in (*v4_matches, *v6_matches)
                if a.split("/")[0] in line
            ),
            default=0,
        )
        description = _clean(line[last_address:]).lstrip("/0123456789 ").strip()

        v4 = v4_matches[0] if v4_matches else ""
        rows.append(
            Row(
                name=name,
                v4=v4,
                v6=v6_matches[0] if v6_matches else "",
                description=description,
                is_network="/" in v4,
                source_line=raw,
            )
        )
    return tuple(rows)


def split_kinds(rows: tuple[Row, ...]) -> tuple[tuple[Row, ...], tuple[Row, ...]]:
    """Separate subnet rows from host rows, by whether the address carried a prefix.

    §1.2 of the annex gives subnets, §2.5 gives hosts. The operator may paste either,
    or both at once, and does not have to say which — the addresses already do.
    """
    networks = tuple(r for r in rows if r.is_network)
    hosts = tuple(r for r in rows if not r.is_network)
    return networks, hosts


def as_interface(row: Row) -> tuple[IPv4Interface | None, IPv6Interface | None]:
    v4 = IPv4Interface(row.v4) if row.v4 and "/" in row.v4 else None
    v6 = IPv6Interface(row.v6) if row.v6 and "/" in row.v6 else None
    return v4, v6


def looks_out_of_bounds(row: Row) -> bool:
    """Whether the annex itself flags this host as out of bounds.

    The annex says so in prose, and it is the difference between a host that must
    keep working and one the operator is free to firewall off — `BASELINE-ANALYSIS.md`
    F8. Detected, then shown for confirmation, never applied on the strength of a
    word in a description.
    """
    text = f"{row.name} {row.description}".lower()
    return "out of bounds" in text or "excon" in text or "out-of-bounds" in text
