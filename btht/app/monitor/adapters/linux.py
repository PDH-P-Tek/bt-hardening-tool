"""Linux collector — `MONITORING.md` §5.1–5.3, §6.2.

First adapter on purpose: easiest to test off-range, and it covers the persistence
surface an intruder actually uses. An account added, a key appended to
`authorized_keys`, a `NOPASSWD: ALL` line dropped into `sudoers.d`, a cron entry — none
of those look like an attack in a log, and all of them are how access survives a reboot
and a password change.

**Deletions are changes.** A removed log-forwarding line or a disabled account is the
change least likely to be caught by eye, so it raises the same alert as an addition.
That falls out of diffing an item set rather than scanning for bad things.
"""

from __future__ import annotations

import json
from dataclasses import asdict

from btht.app.monitor import sessions
from btht.app.monitor.items import Collection, Item, Kind, Severity, digest, key_fingerprint
from btht.app.monitor.transport import Transport, TransportError

#: Read-only, one command per collector, so a failure names what could not be read.
COMMANDS = {
    "M-ACC-01": "getent passwd",
    "M-ACC-02": "getent group",
    "M-ACC-03": "cat /etc/shadow",
    # grep rather than find -exec: it attributes every line to its file and needs no
    # shell metacharacters, which the transport refuses on principle.
    "M-AUTH-01": "grep -rH --include=authorized_keys '' /home /root",
    "M-ACC-08": "cat /etc/sudoers /etc/sudoers.d/*",
    "M-SCHED-01": "crontab -l -u root",
    "M-SCHED-02": "cat /etc/crontab",
    "M-SVC-01": "ss -tulpn",
    "M-SVC-02": "systemctl list-units --type=service --state=running --no-pager --plain",
    "M-BOOT-01": "systemctl list-unit-files --type=service --state=enabled --no-pager --plain",
    "M-BOOT-02": "cat /etc/rc.local",
    "M-FS-01": "find /etc /usr/local/sbin -maxdepth 2 -newer /etc/hostname -type f",
    "M-INT-01": "sha256sum /usr/local/sbin/btmon-collect",
    # `sshd -T` rather than the file: Include and Match blocks resolve, and hashing
    # sshd_config alone misses anything in an included file — which is also where
    # somebody would put a change they did not want read.
    "H-SSH-CONFIG": "sshd -T",
    "M-STATE-UPTIME": "uptime",
    "M-STATE-WHO": "who",
    # An implant has to live somewhere and has to run. `ls -l /proc/*/exe` answers
    # both at once: where each running process came from, and whether that file is
    # still on disk. Neither needs a shell pipeline, which the transport refuses.
    "M-SVC-05": "ls -l /proc/*/exe",
    # Executables in the places a dropped payload goes. `/tmp` and `/var/tmp` are the
    # obvious ones; the interesting case is a binary that has been moved somewhere
    # persistent precisely because /tmp does not survive a reboot.
    "M-FS-05": "find /usr/local/bin /usr/local/sbin /root /home -maxdepth 3 -type f -perm -u+x",
    # Session evidence — see `monitor/sessions.py`. `-F` for full timestamps, without
    # which a login carries no year and cannot be placed against a change.
    "M-SESS-01": "last -F -w -n 120",
    # `-s` so a box that keeps auth records in the other place stays quiet rather than
    # erroring; `-h` so the filename does not prefix every line.
    "M-SESS-02": "grep -sah 'Accepted ' /var/log/auth.log /var/log/secure",
}


def _accounts(output: str) -> list[Item]:
    """Accounts and their shells. A new account is the oldest persistence there is."""
    items = []
    for line in output.splitlines():
        parts = line.split(":")
        if len(parts) < 7:
            continue
        name, _pw, uid, gid, _gecos, home, shell = parts[:7]
        items.append(
            Item(
                key=f"account:{name}",
                collector="M-ACC-01",
                kind=Kind.CONFIG,
                value=f"uid={uid} gid={gid} home={home} shell={shell}",
                severity=Severity.HIGH,
                label=f"account {name}",
            )
        )
    return items


def _password_state(output: str, secret: str) -> list[Item]:
    """Lock state, and a keyed digest of the hash. **Never the hash** — §4."""
    items = []
    for line in output.splitlines():
        parts = line.split(":")
        if len(parts) < 2:
            continue
        name, hashed = parts[0], parts[1]
        if hashed in ("!", "*", "!!", ""):
            state = "locked" if hashed.startswith("!") else "no-password"
            value = state
        else:
            value = f"set:{digest(secret, hashed)}"
        items.append(
            Item(
                key=f"password:{name}",
                collector="M-ACC-03",
                kind=Kind.CONFIG,
                value=value,
                severity=Severity.HIGH,
                label=f"password state for {name}",
            )
        )
    return items


def _authorized_keys(output: str) -> list[Item]:
    """Fingerprint, type, comment and options. **Never the key body** — §4.

    The options string matters as much as the key: `from=` and `command=` are the
    restriction, and an attacker who appends a key without them has full shell where
    the operator believes there is a forced command.
    """
    items = []
    for line in output.splitlines():
        path, _, remainder = line.partition(":")
        entry = remainder.strip()
        if not entry or entry.startswith("#"):
            continue
        parts = entry.split()
        options = ""
        if not parts[0].startswith(("ssh-", "ecdsa-", "sk-")):
            options = parts[0]
            parts = parts[1:]
        if len(parts) < 2:
            continue
        key_type, body = parts[0], parts[1]
        comment = " ".join(parts[2:])
        fingerprint = key_fingerprint(body)
        items.append(
            Item(
                key=f"authorized_key:{path}:{fingerprint}",
                collector="M-AUTH-01",
                kind=Kind.CONFIG,
                value=f"type={key_type} options={options or 'none'} comment={comment}",
                severity=Severity.CRITICAL,
                label=f"authorised key in {path}",
            )
        )
    return items


def _sudoers(output: str) -> list[Item]:
    """`NOPASSWD: ALL` dropped into a new file is trivial to miss by eye — `M-ACC-08`."""
    items = []
    for number, line in enumerate(output.splitlines(), start=1):
        entry = line.strip()
        if not entry or entry.startswith("#"):
            continue
        items.append(
            Item(
                key=f"sudoers:{entry}",
                collector="M-ACC-08",
                kind=Kind.CONFIG,
                value=entry,
                severity=Severity.CRITICAL,
                label=f"sudoers line {number}",
            )
        )
    return items


def _cron(output: str, collector: str) -> list[Item]:
    items = []
    for line in output.splitlines():
        entry = line.strip()
        if not entry or entry.startswith("#"):
            continue
        items.append(
            Item(
                key=f"cron:{collector}:{entry}",
                collector=collector,
                kind=Kind.CONFIG,
                value=entry,
                severity=Severity.HIGH,
                label="scheduled command",
            )
        )
    return items


def _listening(output: str) -> list[Item]:
    """A port that opened is how a foothold becomes reachable — `M-SVC-01`.

    Config rather than state on purpose: the *set* of listening ports is intended to
    be stable, even though the connections through them are not.
    """
    items = []
    for line in output.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 5:
            continue
        local = parts[4]
        items.append(
            Item(
                key=f"listen:{parts[0]}:{local}",
                collector="M-SVC-01",
                kind=Kind.CONFIG,
                value=f"{parts[0]} {local} {' '.join(parts[6:]) if len(parts) > 6 else ''}".strip(),
                severity=Severity.HIGH,
                label=f"listening on {local}",
            )
        )
    return items


def _units(output: str, collector: str, label: str, severity: Severity) -> list[Item]:
    items = []
    for line in output.splitlines():
        parts = line.split()
        if not parts or not parts[0].endswith(".service"):
            continue
        items.append(
            Item(
                key=f"unit:{collector}:{parts[0]}",
                collector=collector,
                kind=Kind.CONFIG,
                value=" ".join(parts[1:3]),
                severity=severity,
                label=f"{label} {parts[0]}",
            )
        )
    return items


def _boot_hook(output: str) -> list[Item]:
    """`rc.local` and friends: run at boot, owned by nobody, rarely read — `M-BOOT-02`."""
    items = []
    for line in output.splitlines():
        entry = line.strip()
        if not entry or entry.startswith("#"):
            continue
        items.append(
            Item(
                key=f"boot:{entry}",
                collector="M-BOOT-02",
                kind=Kind.CONFIG,
                value=entry,
                severity=Severity.CRITICAL,
                label="boot-time command",
            )
        )
    return items


def _canaries(output: str) -> list[Item]:
    """Files changed since the reference point — `M-FS-01`.

    Not a integrity database, and not pretending to be one: a cheap tripwire over the
    directories where persistence is usually written.
    """
    return [
        Item(
            key=f"canary:{path.strip()}",
            collector="M-FS-01",
            kind=Kind.CONFIG,
            value="modified",
            severity=Severity.MEDIUM,
            label=f"changed file {path.strip()}",
        )
        for path in output.splitlines()
        if path.strip()
    ]


def _collector_integrity(output: str) -> list[Item]:
    """The collector script itself — `M-INT-01`.

    An intruder who edits what the monitor runs owns what the monitor reports, so its
    hash is watched like anything else on the box.
    """
    digest_value = output.split()[0] if output.split() else ""
    if not digest_value:
        return []
    return [
        Item(
            key="integrity:collector",
            collector="M-INT-01",
            kind=Kind.CONFIG,
            value=digest_value,
            severity=Severity.CRITICAL,
            label="collector script hash",
        )
    ]


#: Directories no long-running service should be executing from. `/tmp` and `/dev/shm`
#: are where a payload lands first; `/home` because a service running out of somebody's
#: home directory is either a mistake or somebody else's idea.
SUSPICIOUS_PREFIXES = ("/tmp/", "/var/tmp/", "/dev/shm/", "/home/", "/run/shm/")


def _running_from(output: str) -> list[Item]:
    """`M-SVC-05`, `M-SVC-06` — what each process is actually running.

    Two findings hide in one listing. A process whose binary sits in a world-writable
    directory is running something anybody could have put there. A process whose binary
    is marked `(deleted)` is running something that no longer exists on disk — which is
    what a payload does when it unlinks itself after starting, and is close to
    conclusive on a firewall that runs a fixed set of services.

    Both are config rather than state: the set of things running on a firewall is meant
    to be stable, and a new member is exactly the news this tool exists to carry.
    """
    out: list[Item] = []
    for line in output.splitlines():
        if "->" not in line or "/proc/" not in line:
            continue
        left, _, target = line.partition("->")
        target = target.strip()
        pid = ""
        for part in left.split():
            if part.startswith("/proc/"):
                pid = part.split("/")[2]
        if not pid or not target:
            continue

        if target.endswith("(deleted)"):
            binary = target[: -len("(deleted)")].strip()
            out.append(
                Item(
                    key=f"deleted-binary:{binary}",
                    collector="M-SVC-06",
                    kind=Kind.CONFIG,
                    value=f"pid {pid} running {binary}, which is no longer on disk",
                    severity=Severity.CRITICAL,
                    label=f"running a deleted binary: {binary}",
                )
            )
            continue

        if target.startswith(SUSPICIOUS_PREFIXES):
            out.append(
                Item(
                    key=f"writable-path:{target}",
                    collector="M-SVC-05",
                    kind=Kind.CONFIG,
                    value=f"pid {pid} running {target}",
                    severity=Severity.CRITICAL,
                    label=f"running from a writable path: {target}",
                )
            )
    return out


def _executables(output: str) -> list[Item]:
    """`M-FS-05` — executable files where a dropped payload gets moved to persist."""
    return [
        Item(
            key=f"executable:{path.strip()}",
            collector="M-FS-05",
            kind=Kind.CONFIG,
            value=path.strip(),
            severity=Severity.HIGH,
            label=f"executable {path.strip()}",
        )
        for path in output.splitlines()
        if path.strip()
    ]


def collect(transport: Transport, secret: str = "btht") -> Collection:
    """Poll one Linux host. A host that stops answering is itself the alarm.

    No exception escapes: an unreachable host is a result, not a crash, because the
    scheduler polls every host every cycle and one broken box must not stop the rest.
    """
    items: list[Item] = []
    try:
        passwd = transport.run(COMMANDS["M-ACC-01"])
        if not passwd.ok:
            return Collection(host=transport.host, reachable=False, error=passwd.stderr.strip())
        items += _accounts(passwd.stdout)

        shadow = transport.run(COMMANDS["M-ACC-03"])
        if shadow.ok:
            items += _password_state(shadow.stdout, secret)

        keys = transport.run(COMMANDS["M-AUTH-01"])
        if keys.ok:
            items += _authorized_keys(keys.stdout)

        sudo = transport.run(COMMANDS["M-ACC-08"])
        if sudo.ok:
            items += _sudoers(sudo.stdout)

        for collector in ("M-SCHED-01", "M-SCHED-02"):
            cron = transport.run(COMMANDS[collector])
            if cron.ok:
                items += _cron(cron.stdout, collector)

        for collector, parser in (
            ("M-SVC-05", _running_from),
            ("M-FS-05", _executables),
            ("M-SVC-01", _listening),
            ("M-BOOT-02", _boot_hook),
            ("M-FS-01", _canaries),
            ("M-INT-01", _collector_integrity),
        ):
            result = transport.run(COMMANDS[collector])
            if result.ok:
                items += parser(result.stdout)

        sshd = transport.run(COMMANDS["H-SSH-CONFIG"])
        if sshd.ok:
            for line in sshd.stdout.splitlines():
                setting = line.strip()
                if not setting:
                    continue
                name = setting.split(" ", 1)[0]
                items.append(
                    Item(
                        key=f"sshd:{name}",
                        collector="H-SSH-CONFIG",
                        kind=Kind.CONFIG,
                        value=setting,
                        severity=Severity.HIGH,
                        label=f"sshd {name}",
                    )
                )

        for collector, label, severity in (
            ("M-SVC-02", "running service", Severity.HIGH),
            ("M-BOOT-01", "enabled at boot", Severity.CRITICAL),
        ):
            result = transport.run(COMMANDS[collector])
            if result.ok:
                items += _units(result.stdout, collector, label, severity)

        # Who has been on the box. State, emphatically: sessions churn constantly and
        # diffing them would alarm on every legitimate login. They are collected so a
        # change can be put beside the session that might account for it.
        logins = transport.run(COMMANDS["M-SESS-01"])
        accepted = transport.run(COMMANDS["M-SESS-02"])
        merged = sessions.merge(
            sessions.parse_last(logins.stdout) if logins.ok else (),
            sessions.parse_accepted(accepted.stdout) if accepted.ok else (),
        )
        for session in merged:
            items.append(
                Item(
                    key=f"session:{session.started}:{session.user}@{session.source}",
                    collector="M-SESS-01",
                    kind=Kind.STATE,
                    value=json.dumps(asdict(session), sort_keys=True),
                    severity=Severity.INFO,
                    label=session.describe(),
                )
            )

        # State. Displayed, never diffed — see `items.Kind`.
        for collector, label in (("M-STATE-UPTIME", "uptime"), ("M-STATE-WHO", "logged in")):
            result = transport.run(COMMANDS[collector])
            if result.ok:
                items.append(
                    Item(
                        key=f"state:{collector}",
                        collector=collector,
                        kind=Kind.STATE,
                        value=result.stdout.strip(),
                        severity=Severity.INFO,
                        label=label,
                    )
                )
    except TransportError as exc:
        return Collection(host=transport.host, reachable=False, error=str(exc))

    return Collection(host=transport.host, items=tuple(items))
