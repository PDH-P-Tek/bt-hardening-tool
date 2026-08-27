"""Posture checks — `HARDENING.md`. Phase 7.

Different question from drift. The monitor asks *has this changed*; these ask *is this
right*, whether or not anybody touched it. Same collected item set, two evaluations —
one collection, and the adapters are written once.

**They show remediation and never apply it.** Same rule as the monitor, for the same
reason: a tool that can fix a firewall is a tool that holds a credential which can
break one.

Ordering is not by ID. `HARDENING.md` §4 orders the *operator's* day by risk of doing
things in the wrong order, and steps 0–4 are the ones that go wrong — console access
confirmed, management rules in place and *verified*, and only then anti-lockout
disabled. That sequence belongs to the operator; this module reports state.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, replace
from enum import StrEnum

from btht.app.monitor.items import Item


class Result(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    NOT_APPLICABLE = "not_applicable"
    UNKNOWN = "unknown"
    """The collection did not include what this check needs. Not a pass."""


@dataclass(frozen=True, slots=True)
class Check:
    id: str
    title: str
    result: Result
    detail: str = ""
    remediation: str = ""
    """What a human would do. Shown, never run."""

    scoring_risk: str = ""
    """Whether doing this could cost points. `HARDENING.md` orders by it."""


def _by_collector(items: Iterable[Item], collector: str) -> list[Item]:
    return [i for i in items if i.collector == collector]


def _sshd(items: Iterable[Item]) -> dict[str, str]:
    settings: dict[str, str] = {}
    for item in items:
        if item.collector != "H-SSH-CONFIG":
            continue
        name, _, value = item.value.partition(" ")
        settings[name.lower()] = value.strip()
    return settings


def check_ssh(items: Iterable[Item]) -> list[Check]:
    """`H-SSH-*`. Read from `sshd -T`, so `Include` and `Match` resolve.

    Hashing `sshd_config` alone misses anything in an included file — which is both a
    correctness point and where somebody would hide a change.
    """
    settings = _sshd(items)
    if not settings:
        return [
            Check(
                "H-SSH-01",
                "SSH configuration collected",
                Result.UNKNOWN,
                "sshd -T was not collected, so nothing about SSH can be asserted.",
                "Add the sshd collector, then re-run.",
            )
        ]

    out = []
    password_auth = settings.get("passwordauthentication", "yes")
    out.append(
        Check(
            "H-SSH-02",
            "Password authentication disabled",
            Result.PASS if password_auth == "no" else Result.FAIL,
            f"PasswordAuthentication {password_auth}",
            "Set PasswordAuthentication no, after confirming key access works from a "
            "second session that is already open.",
            scoring_risk="none",
        )
    )
    root_login = settings.get("permitrootlogin", "yes")
    out.append(
        Check(
            "H-SSH-03",
            "Root login restricted",
            Result.PASS if root_login in ("no", "prohibit-password") else Result.FAIL,
            f"PermitRootLogin {root_login}",
            "Set PermitRootLogin no, or prohibit-password where a key is needed.",
            scoring_risk="none",
        )
    )
    log_level = settings.get("loglevel", "INFO").upper()
    out.append(
        Check(
            "H-SSH-20",
            "Verbose logging, so key use is attributable",
            Result.PASS if log_level == "VERBOSE" else Result.FAIL,
            f"LogLevel {log_level}",
            "Set LogLevel VERBOSE. Without it the log records that a key was used but "
            "not which one, which is the question you will be asking afterwards.",
            scoring_risk="none",
        )
    )
    return out


def check_accounts(items: Iterable[Item]) -> list[Check]:
    """`H-ACC-*`. Sudo grants that are specific rather than blanket."""
    out = []
    blanket = [
        item
        for item in _by_collector(items, "M-ACC-08")
        if "NOPASSWD: ALL" in item.value and not item.value.startswith("#")
    ]
    out.append(
        Check(
            "H-ACC-05",
            "Sudo grants are specific, not blanket",
            Result.PASS if not blanket else Result.FAIL,
            "; ".join(i.value for i in blanket) or "no blanket NOPASSWD grants",
            "Narrow each grant to the command it needs. A NOPASSWD: ALL line dropped "
            "into sudoers.d is trivial to miss by eye and is full root without a "
            "password.",
            scoring_risk="none",
        )
    )

    unlocked = [
        item for item in items if item.key.startswith("password:") and item.value.startswith("set:")
    ]
    out.append(
        Check(
            "H-ACC-02",
            "Accounts with a usable password are accounted for",
            Result.PASS if len(unlocked) <= 2 else Result.FAIL,
            f"{len(unlocked)} account(s) with a password set",
            "Confirm each one is meant to have interactive access; lock the rest.",
            scoring_risk="low",
        )
    )
    return out


def check_firewall(items: Iterable[Item]) -> list[Check]:
    """`H-FW-*` and `H-PF-*`. The findings from the evidence, restated as live checks."""
    out = []

    antilockout = next((i for i in items if i.key == "pf:antilockout"), None)
    if antilockout is not None:
        out.append(
            Check(
                "H-PF-01",
                "Anti-lockout disabled, with management rules proven first",
                Result.PASS if antilockout.value == "disabled" else Result.FAIL,
                f"anti-lockout {antilockout.value}",
                "Permitted, and it is what makes a management restriction real. Still "
                "the highest-lockout-risk change here: do it only after the management "
                "rule is verified from a second session, and keep that session open. "
                "Green Team's own alias-based anti-lockout rule normally remains, so "
                "the failure mode is recoverable rather than terminal — do not rely on "
                "that instead of verifying.",
                scoring_risk="none",
            )
        )

    permissive = [
        item
        for item in items
        if item.collector == "M-FW-01" and "descr=" in item.value and item.value.endswith("descr=")
    ]
    out.append(
        Check(
            "H-FW-02",
            "No undescribed pass rules",
            Result.PASS if not permissive else Result.FAIL,
            f"{len(permissive)} rule(s) with no description",
            "Give every rule a description. With filter descriptions on, that string "
            "names the rule in the log, which is how the team debugs at speed.",
            scoring_risk="none",
        )
    )

    listening = [i for i in items if i.collector == "M-SVC-01"]
    plaintext = [i for i in listening if ":23" in i.value or ":161" in i.value]
    out.append(
        Check(
            "H-PF-05",
            "No unauthenticated management services listening",
            Result.PASS if not plaintext else Result.FAIL,
            "; ".join(i.value for i in plaintext) or "none listening",
            "Turn off telnet and SNMP. Fast, low risk, high value — and the observed "
            "estate shipped SNMP with the community string still public.",
            scoring_risk="low",
        )
    )
    return out


def check_pfsense(items: Iterable[Item]) -> list[Check]:
    """`H-PF-*` — pfSense rule-tampering that the GUI hides or the operator misreads.

    Two attacks the config-diff alone reads awkwardly:

    - `pfctl -d` disables every rule and **does not show in the web interface**. The
      saved config is untouched, so a person reading Firewall > Rules sees their work
      intact while pf enforces nothing. The tell is the split: many rules configured,
      almost none loaded. We collect both halves precisely so this is visible.
    - A floating **pass from any to any** overrides every crafted block rule beneath it,
      and Blue Teams who do not know pfSense well add block rules under it and wonder why
      nothing works — `EVIDENCE.md` E1. Red Team adds one on purpose.
    """
    checks: list[Check] = []

    configured = [i for i in items if i.collector == "M-FW-01" and "disabled=False" in i.value]
    live = next((i for i in items if i.collector == "M-FW-06"), None)
    if live is None or not configured:
        checks.append(
            Check(
                "H-PF-01",
                "Firewall is enforcing its rules",
                Result.UNKNOWN,
                "The live ruleset or the configured rules were not collected.",
                "Add the pfSense collector for this box.",
                scoring_risk="none",
            )
        )
    else:
        try:
            loaded = int(live.value)
        except ValueError:
            loaded = -1
        # pf loads scrub, anti-lockout and defaults on top of the visible rules, so the
        # live count is normally *higher* than the configured count. A live count that
        # has collapsed below it is the signal — pf is enforcing almost nothing.
        disabled = loaded >= 0 and loaded < len(configured)
        checks.append(
            Check(
                "H-PF-01",
                "Firewall is enforcing its rules",
                Result.FAIL if disabled else Result.PASS,
                f"{len(configured)} rules configured, {loaded} loaded in pf"
                + (" — pf appears to be disabled (pfctl -d)" if disabled else ""),
                "Run `pfctl -e` to re-enable, then `pfctl -sr` to confirm the count "
                "recovers. `pfctl -d` leaves the saved config intact, so the web "
                "interface will have looked correct the whole time. Find out how they "
                "reached the CLI before re-enabling — the access route is still open.",
                scoring_risk="none",
            )
        )

    anyany = [
        i
        for i in items
        if i.collector == "M-FW-01"
        and i.value.startswith("pass ")
        and "src=any" in i.value
        and "dst=any" in i.value
        and "disabled=False" in i.value
    ]
    floating_anyany = [i for i in anyany if "floating=True" in i.value]
    checks.append(
        Check(
            "H-PF-02",
            "No pass-any-to-any rule is shadowing the ruleset",
            Result.FAIL if anyany else Result.PASS,
            (
                "; ".join(i.label for i in anyany)
                + (
                    " — a floating any→any overrides every rule below it"
                    if floating_anyany
                    else ""
                )
            )
            or "none",
            "Remove it. A floating pass-any-any makes every block rule beneath it "
            "irrelevant, which is exactly why it gets added — and why a ruleset can read "
            "as correct while enforcing nothing. Check the Floating tab specifically; it "
            "is the one Blue Teams look at last.",
            scoring_risk="none",
        )
    )
    return checks


def check_routing(items: Iterable[Item]) -> list[Check]:
    """`H-FRR-*`. Scoping depends on `HARDENING.md` H-Q2, which is still open."""
    logins = [i for i in items if i.collector == "M-RT-01" and i.value.startswith("username ")]
    weak = [i for i in logins if "nopassword" in i.value]
    if not logins:
        return [
            Check(
                "H-FRR-01",
                "Router VTY access",
                Result.UNKNOWN,
                "No routing configuration collected.",
                "Add the FRR collector for this host.",
            )
        ]
    config = [i for i in items if i.collector in ("M-RT-01",)]
    config_text = "\n".join(i.value for i in config)

    checks = [
        Check(
            "H-FRR-02",
            "Router logins require a password",
            Result.PASS if not weak else Result.FAIL,
            "; ".join(i.value for i in weak) or "all logins require a password",
            "Set a password on each VTY login. Which daemons expose a VTY port at all "
            "is HARDENING H-Q2 and needs a look at a live router.",
            scoring_risk="medium",
        )
    ]

    # H-FRR-04 — the load-bearing OSPF-backdoor defence. Without `passive-interface
    # default` the router advertises on every attached segment and will form an
    # adjacency with anything that answers, including a crafted OSPF packet from a
    # foothold on that segment. That adjacency is the whole delivery mechanism.
    has_passive_default = "passive-interface default" in config_text
    ospf_configured = any("router ospf" in i.value for i in config)
    if ospf_configured:
        checks.append(
            Check(
                "H-FRR-04",
                "OSPF does not offer adjacency on every interface",
                Result.PASS if has_passive_default else Result.FAIL,
                "passive-interface default is set"
                if has_passive_default
                else "passive-interface default is NOT set — the router will attempt an "
                "adjacency on every attached segment",
                "Set `passive-interface default` and then `no passive-interface` only on "
                "the links that genuinely peer. This is the single line that stops a "
                "foothold on any attached segment becoming a routing peer — and OSPF "
                "adjacency is how the OSPF backdoor delivers its payload.",
                scoring_risk="low",
            )
        )

        # H-FRR-05 — even where an adjacency is meant to form, authentication stops an
        # unauthenticated packet being accepted as a neighbour.
        has_auth = (
            "ospf authentication message-digest" in config_text
            or "ip ospf message-digest-key" in config_text
            or "ip ospf authentication" in config_text
        )
        checks.append(
            Check(
                "H-FRR-05",
                "OSPF adjacencies are authenticated",
                Result.PASS if has_auth else Result.FAIL,
                "OSPF authentication is configured"
                if has_auth
                else "no OSPF authentication found — any packet on a peering segment can "
                "form an adjacency",
                "Enable message-digest authentication on every OSPF interface and area. "
                "With H-FRR-04 it closes the adjacency path completely; the control-plane "
                "nftables ruleset the tool generates is the third layer, restricting OSPF "
                "to declared neighbour addresses.",
                scoring_risk="low",
            )
        )

    return checks


def check_implant(items: Iterable[Item]) -> list[Check]:
    """`H-IMP-*` — indicators of an agent or reverse shell already on the box.

    This is a different question again. `H-SSH-*` and `H-PF-*` ask whether the box is
    configured to resist being taken; these ask whether it has already been taken. They
    are written against one specific chain, observed rather than imagined:

        curl a payload down → move it somewhere persistent, because /tmp and /var are
        memory-backed on pfSense and do not survive a reboot → chmod +x →
        `echo "@reboot /path/to/fwshell" | crontab -`, or an entry in config.xml

    Each step leaves a different trace, and none of them is subtle once you are looking.
    The reason they go unnoticed is that nobody looks at `config.xml` by eye and nobody
    diffs a crontab between shifts. That is the whole job of this tool.

    Every check here reports **UNKNOWN** rather than PASS when the collector that feeds
    it did not run. An implant check that passes because it saw nothing is worse than no
    check at all.
    """
    collected = list(items)
    checks: list[Check] = []

    boot = [i for i in collected if i.collector in ("M-BOOT-02", "M-BOOT-03")]
    checks.append(
        Check(
            id="H-IMP-01",
            title="No commands are run at boot",
            result=Result.FAIL if boot else Result.PASS,
            detail=(
                "; ".join(i.value[:120] for i in boot)
                if boot
                else "no earlyshellcmd or shellcmd entries"
            ),
            remediation="A stock pfSense has none of these. Every entry was put there "
            "deliberately by somebody — establish who, then remove it in the GUI under "
            "Diagnostics or by editing the entry out of config.xml. Removing the binary "
            "without removing this leaves it to be re-run at the next boot.",
            scoring_risk="none",
        )
    )

    deleted = _by_collector(collected, "M-SVC-06")
    checks.append(
        Check(
            id="H-IMP-02",
            title="Nothing is running from a binary that has been deleted",
            result=Result.FAIL if deleted else Result.PASS,
            detail="; ".join(i.value[:120] for i in deleted) or "none",
            remediation="A running process whose executable is gone from disk unlinked "
            "itself after starting. On a firewall running a fixed set of services there "
            "is no benign explanation. Capture the process before killing it — `ls -l "
            "/proc/<pid>/exe`, `ss -tnp`, and the open sockets tell you where it calls "
            "home — then treat the box as compromised.",
            scoring_risk="none",
        )
    )

    writable = _by_collector(collected, "M-SVC-05")
    checks.append(
        Check(
            id="H-IMP-03",
            title="Nothing is running from a world-writable directory",
            result=Result.FAIL if writable else Result.PASS,
            detail="; ".join(i.value[:120] for i in writable) or "none",
            remediation="A service executing out of /tmp, /dev/shm or a home directory "
            "is running something anybody with a shell could have replaced. Identify it "
            "before killing it, and check the scheduled jobs and boot commands for the "
            "thing that will start it again.",
            scoring_risk="none",
        )
    )

    scheduled = [
        i
        for i in collected
        if i.collector in ("M-SCHED-01", "M-SCHED-02", "M-SCHED-04")
        and ("@reboot" in i.value or "/tmp/" in i.value or "/dev/shm/" in i.value)
    ]
    checks.append(
        Check(
            id="H-IMP-04",
            title="No scheduled job restarts something at boot from a writable path",
            result=Result.FAIL if scheduled else Result.PASS,
            detail="; ".join(i.value[:120] for i in scheduled) or "none",
            remediation="`@reboot` in a crontab is the standard way an implant survives "
            "the reboot you were relying on to clear it. Remove the entry before you "
            "reboot, not after — otherwise the reboot is what starts it.",
            scoring_risk="none",
        )
    )

    webshells = _by_collector(collected, "M-FS-08")
    checks.append(
        Check(
            id="H-IMP-06",
            title="No unexpected PHP in the firewall web root",
            result=Result.FAIL if webshells else Result.PASS,
            detail="; ".join(i.value for i in webshells) or "none",
            remediation="A .php in /usr/local/www that is not part of pfSense is a web "
            "shell — NoSense's fallback for when its keys are removed, and it needs no "
            "credentials to use once uploaded. Remove the file, then find how it was "
            "written: a web shell arrives over valid credentials or an existing shell.",
            scoring_risk="none",
        )
    )

    listeners = _by_collector(collected, "M-SVC-01")
    checks.append(
        Check(
            id="H-IMP-05",
            title="Listening ports are the ones you expect",
            result=Result.UNKNOWN if not listeners else Result.PASS,
            detail=f"{len(listeners)} listening socket(s) recorded"
            if listeners
            else "no listening-socket collection in this item set",
            remediation="Compare against the as-received baseline rather than against "
            "memory. A bind shell is a listener that was not there yesterday, and the "
            "baseline is the only reliable record of yesterday.",
            scoring_risk="none",
        )
    )

    # An implant check that passes because nothing was collected is worse than none.
    if not any(
        i.collector
        in ("M-BOOT-02", "M-BOOT-03", "M-SVC-05", "M-SVC-06", "M-SCHED-01", "M-FS-08")
        for i in collected
    ):
        checks = [
            replace(
                check,
                result=Result.UNKNOWN,
                detail="the collectors these depend on did not run on this box",
            )
            if check.result is Result.PASS
            else check
            for check in checks
        ]
    return checks


def run_posture(items: Iterable[Item]) -> tuple[Check, ...]:
    """Every check, over one collected item set. Ordered by ID for stable output."""
    collected = list(items)
    checks: list[Check] = []
    for group in (
        check_ssh,
        check_accounts,
        check_firewall,
        check_pfsense,
        check_routing,
        check_implant,
    ):
        checks.extend(group(collected))
    return tuple(sorted(checks, key=lambda c: c.id))


def failing(checks: tuple[Check, ...]) -> tuple[Check, ...]:
    return tuple(c for c in checks if c.result is Result.FAIL)


def unknown(checks: tuple[Check, ...]) -> tuple[Check, ...]:
    """Checks that could not be evaluated. **Not passes** — silence is not health."""
    return tuple(c for c in checks if c.result is Result.UNKNOWN)
