"""How the collector reaches a managed host — `MONITORING.md` §3.1, §7.

**The monitor is read-only, and that is structural rather than a promise.** It holds no
credential that can change a firewall, it never pushes, never reverts, never remediates.
It renders the change and a human acts on the box. The obvious button — revert this —
was considered and rejected (`MONITORING.md` §2), and a write-capable collector would
also destroy the conflict-of-interest position the whole tool rests on (§13).

Two things enforce that here rather than leaving it to discipline:

- every command runs through `run()`, which refuses anything not on the read-only
  allow-list of the adapter that asked for it
- the transport is an interface, so tests drive adapters with recorded output and the
  suite never opens a socket

This is the only outbound network path in the entire package. Everything else is
offline by construction — `SPEC.md` §12.1.
"""

from __future__ import annotations

import shlex
import subprocess
from dataclasses import dataclass
from typing import Protocol


class TransportError(Exception):
    """The host could not be reached, or refused the command."""


class RefusedCommand(Exception):
    """A command that is not read-only. Never sent."""


#: Commands that change state. Matched as words so a path containing `rm` is fine.
FORBIDDEN = (
    "rm",
    "mv",
    "cp",
    "dd",
    "kill",
    "pkill",
    "reboot",
    "shutdown",
    "halt",
    "chmod",
    "chown",
    "useradd",
    "usermod",
    "userdel",
    "passwd",
    "pfctl",
    "iptables",
    "nft",
    "systemctl",
    "service",
    "tee",
    "truncate",
    "sed",
    "vi",
    "vim",
    "nano",
    "install",
    "pkg",
    "apt",
    "yum",
)

#: Shell constructs that could smuggle a write past the word check.
FORBIDDEN_TOKENS = (">", ">>", "|", "$(", "`", ";", "&&", "||", "\n")


@dataclass(frozen=True, slots=True)
class CommandResult:
    command: str
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0

    @property
    def ok(self) -> bool:
        return self.exit_code == 0


def _invoked(words: list[str]) -> list[str]:
    """The words that are actually *run*, not every word on the line.

    `getent passwd` reads the account database and does not invoke `passwd`; refusing
    it would make the check useless in the name of being strict. What matters is the
    command position, and the places another command can be launched from one.
    """
    if not words:
        return []
    launched = [words[0]]
    for index, word in enumerate(words):
        base = word.rsplit("/", 1)[-1]
        launches_another = base in (
            "-exec",
            "-execdir",
            "-ok",
            "xargs",
            "env",
            "sudo",
            "doas",
            "sh",
            "bash",
        )
        if launches_another and index + 1 < len(words):
            launched.append(words[index + 1])
    return [word.rsplit("/", 1)[-1] for word in launched]


def assert_read_only(command: str) -> None:
    """Refuse anything that could change the host. Raises rather than warns.

    Deliberately blunt. A collector that can be talked into writing is a collector
    whose read-only claim is worth nothing, and the cost of a false refusal is one
    obvious error message at development time.
    """
    for token in FORBIDDEN_TOKENS:
        if token in command:
            raise RefusedCommand(
                f"{command!r} contains {token!r}. The collector sends single read-only "
                "commands; anything that could redirect or chain is refused."
            )
    for name in _invoked(shlex.split(command)):
        if name in FORBIDDEN:
            raise RefusedCommand(
                f"{command!r} invokes {name!r}, which can change the host. The monitor "
                "is read-only: it renders the change and a human acts on the box."
            )


class Transport(Protocol):
    """What an adapter is given. Adapters never construct their own connection."""

    host: str

    def run(self, command: str) -> CommandResult: ...


@dataclass
class SSHTransport:
    """OpenSSH, key-only, with host checking on.

    Uses the system client rather than a library so the key, the `known_hosts` file and
    the account restrictions are the operator's own, managed outside this repository —
    the monitor's key pair is generated at setup and never lives in the tree.
    """

    host: str
    user: str = ""
    key_path: str = ""
    known_hosts: str = ""
    timeout: int = 20

    def _argv(self, command: str) -> list[str]:
        argv = [
            "ssh",
            "-n",
            "-o",
            "BatchMode=yes",
            "-o",
            "PasswordAuthentication=no",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            f"ConnectTimeout={self.timeout}",
        ]
        if self.known_hosts:
            argv += ["-o", f"UserKnownHostsFile={self.known_hosts}"]
        if self.key_path:
            argv += ["-i", self.key_path, "-o", "IdentitiesOnly=yes"]
        argv.append(f"{self.user}@{self.host}" if self.user else self.host)
        argv.append(command)
        return argv

    def run(self, command: str) -> CommandResult:
        assert_read_only(command)
        try:
            completed = subprocess.run(  # noqa: S603 - argv form, no shell
                self._argv(command),
                capture_output=True,
                text=True,
                timeout=self.timeout + 10,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise TransportError(f"{self.host}: {exc}") from exc
        return CommandResult(
            command=command,
            stdout=completed.stdout,
            stderr=completed.stderr,
            exit_code=completed.returncode,
        )


@dataclass
class RecordedTransport:
    """A transport backed by recorded output. The only one the test suite uses.

    Keeps the suite offline and makes adapter behaviour reproducible: the awkward
    cases — a missing file, a command that is not installed, a host that answers
    slowly — are recorded rather than simulated by mocking.
    """

    host: str
    responses: dict[str, CommandResult]
    sent: list[str] | None = None

    def run(self, command: str) -> CommandResult:
        assert_read_only(command)
        if self.sent is None:
            self.sent = []
        self.sent.append(command)
        if command not in self.responses:
            return CommandResult(command=command, stderr="not recorded", exit_code=127)
        return self.responses[command]
