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


#: **Allow-list, not deny-list.** A deny-list cannot express what the collectors
#: actually need: `pfctl -sr` reads the ruleset and `pfctl -d` disables the packet
#: filter entirely, and both are the same binary. A deny-list also fails open on
#: anything nobody thought of, which is the wrong direction for a control whose whole
#: claim is that it cannot write.
#:
#: `None` means the binary has no writing mode worth guarding. A tuple means the first
#: real argument must start with one of those.
ALLOWED: dict[str, tuple[str, ...] | None] = {
    # Inherently read-only readers.
    "cat": None,
    "grep": None,
    "getent": None,
    "ls": None,
    "stat": None,
    "head": None,
    "tail": None,
    "wc": None,
    "sort": None,
    "uniq": None,
    "awk": None,
    "date": None,
    "hostname": None,
    "uname": None,
    "id": None,
    "who": None,
    "last": None,
    "uptime": None,
    "ps": None,
    "df": None,
    "ss": None,
    "netstat": None,
    "sockstat": None,
    "sha256sum": None,
    "sha256": None,
    "find": None,
    "echo": None,
    # Binaries with a writing mode. Constrained to the reading one.
    "crontab": ("-l",),
    "pfctl": ("-s", "-vs"),
    "nft": ("list",),
    "iptables": ("-L", "-S", "-n"),
    "ip6tables": ("-L", "-S", "-n"),
    "systemctl": ("list-units", "list-timers", "list-unit-files", "status", "show", "is-enabled"),
    "sysctl": ("-a", "-n"),
    "pkg": ("info", "query", "version"),
    "rpm": ("-qa", "-q"),
    "dpkg": ("-l", "--list"),
    "vtysh": ("-c",),
    "sshd": ("-T",),
}

#: Shell constructs that could smuggle a write past the check.
FORBIDDEN_TOKENS = (">", ">>", "|", "$(", "`", ";", "&&", "||", "\n")

#: `vtysh -c` takes a command string, and only `show` reads.
VTYSH_READS = ("show",)


@dataclass(frozen=True, slots=True)
class CommandResult:
    command: str
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0

    @property
    def ok(self) -> bool:
        return self.exit_code == 0


def _invoked(words: list[str]) -> list[tuple[str, list[str]]]:
    """The commands actually *run*, with their arguments.

    `getent passwd` reads the account database and does not invoke `passwd`; refusing
    it would make the check useless in the name of being strict. What matters is the
    command position, and the places another command can be launched from one.
    """
    if not words:
        return []
    found = [(words[0].rsplit("/", 1)[-1], words[1:])]
    for index, word in enumerate(words):
        base = word.rsplit("/", 1)[-1]
        launches_another = base in ("-exec", "-execdir", "-ok", "xargs", "env", "sudo", "doas")
        if launches_another and index + 1 < len(words):
            found.append((words[index + 1].rsplit("/", 1)[-1], words[index + 2 :]))
    return found


def assert_read_only(command: str) -> None:
    """Refuse anything that could change the host. Raises rather than warns.

    An unrecognised command is refused, so a new collector has to declare what it
    needs rather than discovering later that it could have written.
    """
    for token in FORBIDDEN_TOKENS:
        if token in command:
            raise RefusedCommand(
                f"{command!r} contains {token!r}. The collector sends single read-only "
                "commands; anything that could redirect or chain is refused."
            )

    for name, args in _invoked(shlex.split(command)):
        if name not in ALLOWED:
            raise RefusedCommand(
                f"{command!r} invokes {name!r}, which is not on the read-only "
                "allow-list. Add it there deliberately, with the arguments that read."
            )
        permitted = ALLOWED[name]
        if permitted is None:
            continue
        first = next((a for a in args if not a.startswith("--")), "")
        if not any(first.startswith(prefix) for prefix in permitted):
            raise RefusedCommand(
                f"{command!r} invokes {name!r} with {first!r}. Only "
                f"{', '.join(permitted)} read; anything else can change the host."
            )
        if name == "vtysh":
            position = args.index(first)
            payload = args[position + 1] if len(args) > position + 1 else ""
            if not payload.strip().startswith(VTYSH_READS):
                raise RefusedCommand(
                    f"{command!r}: vtysh may only run 'show' commands. Anything else "
                    "reaches the routing configuration."
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
