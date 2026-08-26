"""pfSense collector — `MONITORING.md` §5.7, §6.1.

The highest-value platform, and the easiest, because almost all persistence lives in
one file. That is also what makes it dangerous to collect from: `config.xml` holds
password hashes, the webConfigurator private key, SSH keys and cleartext service
passwords in the same document as the rules.

So there are two allow-lists, not one. The generator's parser already reads only
`<aliases>`, `<filter>` and `<nat>` plus a fixed fact list. The monitor needs more than
that — it deliberately watches accounts and authentication material — so it has its own
explicit element list here, and what it extracts is names, fingerprints and digests.
The raw document is never stored, and neither is anything that could be replayed.

Rules are identified by their `<tracker>`, which pfSense assigns and preserves. That is
the answer to the awkward part of item identity: a rule edited in place keeps its
tracker, so the change shows as a change rather than as one deletion and one addition.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET

from btht.app.ingest.pfsense import ParseError, parse_string
from btht.app.monitor.items import Collection, Item, Kind, Severity, digest, key_fingerprint
from btht.app.monitor.transport import Transport, TransportError

COMMANDS = {
    "M-FW-CONFIG": "cat /conf/config.xml",
    "M-FW-06": "pfctl -sr",
    "M-SVC-01": "sockstat -4l",
}

#: The only elements this adapter reads beyond the three the generator parses.
#: Everything not named here is not looked at — `MONITORING.md` §4.
ACCOUNT_ELEMENTS = ("name", "uid", "scope", "expires", "authorizedkeys", "bcrypt-hash")


def _accounts(root: ET.Element, secret: str) -> list[Item]:
    """Account names, scope and a digest of the hash. `M-ACC-07`.

    pfSense keeps its users in the same file as everything else, so this is the one
    place the monitor has to look at a document it otherwise avoids.
    """
    items: list[Item] = []
    for user in root.findall("system/user"):
        name = (user.findtext("name") or "").strip()
        if not name:
            continue
        hashed = (user.findtext("bcrypt-hash") or "").strip()
        password_state = f"set:{digest(secret, hashed)}" if hashed else "no-password"
        items.append(
            Item(
                key=f"pf:user:{name}",
                collector="M-ACC-07",
                kind=Kind.CONFIG,
                value=(
                    f"uid={(user.findtext('uid') or '').strip()} "
                    f"scope={(user.findtext('scope') or '').strip()} "
                    f"expires={(user.findtext('expires') or '').strip() or 'never'} "
                    f"password={password_state}"
                ),
                severity=Severity.CRITICAL,
                label=f"firewall account {name}",
            )
        )
        for line in (user.findtext("authorizedkeys") or "").splitlines():
            entry = line.strip()
            if not entry:
                continue
            parts = entry.split()
            options = "" if parts[0].startswith(("ssh-", "ecdsa-", "sk-")) else parts.pop(0)
            if len(parts) < 2:
                continue
            fingerprint = key_fingerprint(parts[1])
            items.append(
                Item(
                    key=f"pf:key:{name}:{fingerprint}",
                    collector="M-AUTH-01",
                    kind=Kind.CONFIG,
                    value=f"type={parts[0]} options={options or 'none'}",
                    severity=Severity.CRITICAL,
                    label=f"authorised key for {name}",
                )
            )
    return items


def _groups(root: ET.Element) -> list[Item]:
    items = []
    for group in root.findall("system/group"):
        name = (group.findtext("name") or "").strip()
        if not name:
            continue
        members = ",".join(sorted(m.text or "" for m in group.findall("member")))
        items.append(
            Item(
                key=f"pf:group:{name}",
                collector="M-ACC-02",
                kind=Kind.CONFIG,
                value=f"scope={(group.findtext('scope') or '').strip()} members={members}",
                severity=Severity.HIGH,
                label=f"group {name}",
            )
        )
    return items


def _rules(config_xml: str) -> list[Item]:
    """Rules, aliases and NAT, through the generator's own parser.

    Written once, used twice: the same code that decides what a rule *is* for
    generation decides what it is for monitoring, so the two halves cannot disagree
    about whether a rule changed.
    """
    parsed = parse_string(config_xml)
    items: list[Item] = []

    for index, rule in enumerate(parsed.rules):
        identity = rule.tracker or f"position:{index}"
        items.append(
            Item(
                key=f"pf:rule:{identity}",
                collector="M-FW-01",
                kind=Kind.CONFIG,
                value=(
                    f"{rule.action.value} {','.join(rule.interfaces)} {rule.family.value} "
                    f"proto={rule.protocol or 'any'} quick={rule.quick} "
                    f"disabled={rule.disabled} descr={rule.descr}"
                ),
                severity=Severity.CRITICAL,
                label=rule.descr or f"rule {identity}",
            )
        )

    for alias in parsed.aliases:
        severity = (
            Severity.CRITICAL
            if "mgmt" in alias.name.lower() or "remote" in alias.name.lower()
            else Severity.HIGH
        )
        items.append(
            Item(
                key=f"pf:alias:{alias.name}",
                collector="M-FW-09" if severity is Severity.CRITICAL else "M-FW-07",
                kind=Kind.CONFIG,
                # Membership in full, not a count: a management-source alias is the
                # crown jewel, and the operator should be reading addresses rather
                # than a diff of a number — `MONITORING.md` §5.7.1.
                value=" ".join(sorted(alias.entries)),
                severity=severity,
                label=f"alias {alias.name}",
            )
        )

    items.append(
        Item(
            key="pf:nat:outbound",
            collector="M-FW-08",
            kind=Kind.CONFIG,
            value=parsed.nat.outbound_mode,
            severity=Severity.HIGH,
            label="outbound NAT mode",
        )
    )
    items.append(
        Item(
            key="pf:antilockout",
            collector="M-PF-01",
            kind=Kind.CONFIG,
            value="enabled" if parsed.facts.antilockout_enabled else "disabled",
            severity=Severity.HIGH,
            label="anti-lockout",
        )
    )
    return items


def _live_ruleset(output: str) -> list[Item]:
    """What pf is actually enforcing — `M-FW-06`.

    Config and running state diverging is the interesting case: a rule loaded but not
    saved disappears at reboot, and a rule saved but not loaded is not protecting
    anything now.
    """
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    return [
        Item(
            key="pf:live:ruleset",
            collector="M-FW-06",
            kind=Kind.CONFIG,
            value=str(len(lines)),
            severity=Severity.HIGH,
            label="rules loaded in pf",
        )
    ]


def collect(transport: Transport, secret: str = "btht") -> Collection:
    items: list[Item] = []
    try:
        config = transport.run(COMMANDS["M-FW-CONFIG"])
        if not config.ok:
            return Collection(host=transport.host, reachable=False, error=config.stderr.strip())

        try:
            root = ET.fromstring(config.stdout)
        except ET.ParseError as exc:
            return Collection(host=transport.host, reachable=False, error=f"config.xml: {exc}")

        items += _accounts(root, secret)
        items += _groups(root)
        try:
            items += _rules(config.stdout)
        except ParseError as exc:
            return Collection(host=transport.host, reachable=False, error=str(exc))

        live = transport.run(COMMANDS["M-FW-06"])
        if live.ok:
            items += _live_ruleset(live.stdout)

        listening = transport.run(COMMANDS["M-SVC-01"])
        if listening.ok:
            for line in listening.stdout.splitlines()[1:]:
                parts = line.split()
                if len(parts) < 6:
                    continue
                items.append(
                    Item(
                        key=f"pf:listen:{parts[-2]}",
                        collector="M-SVC-01",
                        kind=Kind.CONFIG,
                        value=f"{parts[0]} {parts[1]} {parts[-2]}",
                        severity=Severity.HIGH,
                        label=f"listening on {parts[-2]}",
                    )
                )
    except TransportError as exc:
        return Collection(host=transport.host, reachable=False, error=str(exc))

    return Collection(host=transport.host, items=tuple(items))
