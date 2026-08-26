"""The secret-exclusion test — `SPEC.md` §10.2. Runs in CI on every commit.

`.gitignore` is the safety net. This is the control. The tool reads configurations
carrying password hashes, private keys and cleartext service passwords, and none of
that may reach the repository, the fixtures or any generated output.

This file is excluded from its own scan: it necessarily contains the patterns it
looks for.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SELF = Path(__file__).resolve()

#: The one exempt path. `tests/fixtures/credentials/` holds deliberately
#: credential-shaped material so the parser can be *proved* to drop it rather
#: than assumed to. The exemption is guarded by
#: `test_credential_fixtures_are_marked_synthetic`: every file there must carry
#: the marker, so a real secret cannot be dropped in quietly.
CREDENTIAL_FIXTURES = REPO_ROOT / "tests" / "fixtures" / "credentials"
SYNTHETIC_MARKER = "SYNTHETIC-TEST-CREDENTIAL-NOT-REAL"


def is_exempt(path: Path) -> bool:
    return CREDENTIAL_FIXTURES in path.resolve().parents


#: Each pattern describes credential *material*, not a mention of it. Documentation
#: says "ssh-ed25519 AAAA..." and "NOPASSWD: ALL" in several places; those are
#: descriptions of a posture, and must not trip the scan. A real key body is long.
SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("PEM private key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("PuTTY private key", re.compile(r"PuTTY-User-Key-File-\d")),
    ("SSH public key body", re.compile(r"ssh-(?:rsa|dss|ed25519)\s+[A-Za-z0-9+/]{60,}")),
    ("ECDSA key body", re.compile(r"ecdsa-sha2-nistp\d+\s+[A-Za-z0-9+/]{60,}")),
    ("bcrypt hash", re.compile(r"\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}")),
    ("sha-crypt hash", re.compile(r"\$[156]\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{20,}")),
    # Populated elements, not tag names: documentation has to be able to *discuss*
    # `<bcrypt-hash>` without tripping the control, or the control gets relaxed by
    # whoever is writing the documentation at the time.
    ("pfSense hash element", re.compile(r"<(?:bcrypt|sha512)-hash>[^<]{10,}</")),
    ("pfSense password element", re.compile(r"<password>(?:<!\[CDATA\[)?[^<\s]{6,}")),
    ("PSK element", re.compile(r"<pre-shared-key>[^<]{6,}</")),
    ("private key element", re.compile(r"<prv>[A-Za-z0-9+/]{40,}")),
)

TEXT_SUFFIXES = {
    ".md",
    ".py",
    ".yaml",
    ".yml",
    ".xml",
    ".html",
    ".css",
    ".js",
    ".json",
    ".toml",
    ".cfg",
    ".ini",
    ".txt",
    ".sh",
    ".bash",
    ".sql",
    "",
}


def tracked_files() -> list[Path]:
    out = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return [REPO_ROOT / p for p in out.split("\0") if p]


def scan(path: Path) -> list[str]:
    if path.suffix.lower() not in TEXT_SUFFIXES or not path.is_file():
        return []
    try:
        body = path.read_text(encoding="utf-8", errors="strict")
    except (UnicodeDecodeError, OSError):
        return []
    return [name for name, pattern in SECRET_PATTERNS if pattern.search(body)]


def test_tracked_files_carry_no_credential_material() -> None:
    findings: list[str] = []
    for path in tracked_files():
        if path.resolve() == SELF or is_exempt(path):
            continue
        for name in scan(path):
            findings.append(f"{path.relative_to(REPO_ROOT)}: {name}")
    assert not findings, "credential material in tracked files:\n  " + "\n  ".join(findings)


def test_fixtures_carry_no_credential_material() -> None:
    """Fixtures are hand-built and sanitised — `SPEC.md` §10.1."""
    fixtures = sorted((REPO_ROOT / "tests" / "fixtures").rglob("*"))
    findings: list[str] = []
    for path in fixtures:
        if is_exempt(path):
            continue
        for name in scan(path):
            findings.append(f"{path.relative_to(REPO_ROOT)}: {name}")
    assert not findings, "credential material in fixtures:\n  " + "\n  ".join(findings)


def test_gitignore_covers_working_data() -> None:
    """Collected state, baselines and the monitor database are never source."""
    must_be_ignored = [
        "data/estates/team14.yaml",
        "baselines/do-fw1.json",
        "collected/dsoc.json",
        "btmon.sqlite",
        "id_ed25519",
        "known_hosts",
        ".env",
        "capture.pcap",
    ]
    result = subprocess.run(
        ["git", "check-ignore", "--stdin"],
        cwd=REPO_ROOT,
        input="\n".join(must_be_ignored),
        capture_output=True,
        text=True,
    )
    ignored = set(result.stdout.split())
    missing = [p for p in must_be_ignored if p not in ignored]
    assert not missing, f"paths that must be gitignored but are not: {missing}"


def test_credential_fixtures_are_marked_synthetic() -> None:
    """Guards the one exemption above.

    A file in the credential fixture directory is invisible to the scan, so it
    must announce itself as invented. Anything without the marker is treated as
    a real secret that has been put somewhere it would not be noticed.
    """
    if not CREDENTIAL_FIXTURES.is_dir():
        return
    unmarked = [
        str(p.relative_to(REPO_ROOT))
        for p in sorted(CREDENTIAL_FIXTURES.rglob("*"))
        if p.is_file() and SYNTHETIC_MARKER not in p.read_text(encoding="utf-8", errors="ignore")
    ]
    assert not unmarked, (
        "files in the exempt credential-fixture directory without the "
        f"{SYNTHETIC_MARKER} marker: {unmarked}"
    )
