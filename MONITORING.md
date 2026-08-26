# Monitoring — Estate Change Detection and Situational Awareness

**Status:** design v0.2, pre-build. Nothing has been written yet. This document is the authority on what the tool watches, how it watches it, and what the operator has to do to turn it on.

**Companion:** `HARDENING.md` defines a second, independent evaluation — posture checks (`H-*`) that ask whether a setting is *weak*, rather than whether it *changed*. Same collected data, different question. Read both; do not merge them.

---

## 1. Why this exists

At DCM26 one operator held the firewall and router estate — multiple pfSense boxes plus BSD/FRR VM routers — and the only way to know whether anything had changed was to log into each box in turn and look. That does not scale past about three boxes, it degrades badly with fatigue, and it is precisely the check that gets skipped at 0300 on day three.

Red Team's observed pattern across previous iterations is not subtle and not exotic:

> gain a foothold → create or co-opt an account → escalate privilege → establish a way back in → pivot.

Every stage of that leaves a trace in configuration that is trivially visible **if you are comparing against a known-good state**, and effectively invisible if you are eyeballing a live box you have never memorised.

The tool's single job is to answer, across the whole estate, in one glance:

> **Has anything changed since I last looked, and was it us?**

Everything else in this document serves that sentence.

## 2. What this is not

These are decisions, not omissions. They were argued and taken.

| | |
|---|---|
| **No auto-revert.** | Rejected. Reverting mid-exercise risks self-inflicted outage, fights the operator's own legitimate changes, and destroys evidence before it is read. The tile goes red; a human decides. |
| **No live push. No write access of any kind.** | The tool holds no credential that can change a firewall. Compromising the collector yields situational awareness, not control of the estate. This is what keeps it defensible to build. |
| **Not an IDS.** | It watches *configuration and persistence surface*, not traffic. It will not tell you an exploit landed. It will tell you what the attacker did afterwards. |
| **Not a compliance tool — on its own.** | Drift detection compares against *your* baseline, not against a standard, so a wide-open ruleset that has not changed since baseline is green here. That is correct behaviour for this layer, and it is exactly the blind spot `HARDENING.md` exists to cover. |
| **Not for the whole Blue Team.** | Firewall/router hardening cell only. Scope creep into host monitoring for the whole estate is how this becomes unmaintainable and unowned. |

The tool is deliberately boring. Boring is what gets trusted at 0300.

## 3. Architecture

### 3.1 Shape

An off-box collector, running alongside the ruleset builder in the same container, polls each managed host over SSH using a read-only account, normalises what it gets back, compares it against a stored baseline, and surfaces the differences for triage.

```
  ┌──────────────────────────────────────────────┐
  │  BT Hardening Tool container                 │
  │                                              │
  │   generator ──► baseline artefact ──┐        │
  │                                     ▼        │
  │   scheduler ──► adapters ──► normalise ──►   │
  │                                  diff ──►    │
  │                              SQLite store    │
  │                                     │        │
  │                              triage UI ◄─────┘
  └──────────────┬───────────────────────────────┘
                 │ SSH, read-only, key-only, source-IP restricted
     ┌───────────┼───────────┬─────────────┐
     ▼           ▼           ▼             ▼
  pfSense     pfSense     Linux host    BSD/FRR router
```

Off-box was chosen over an on-box agent for three reasons: nothing is installed on Green Team's boxes that has to be justified; the baseline sits somewhere the attacker on the firewall cannot reach; and a host that stops answering is *already* a visible alarm without building a separate dead-man's switch.

### 3.2 Platform adapters

Three, with a common interface. Each returns a normalised item set; the diff engine is platform-agnostic.

| Adapter | Targets | Notes |
|---|---|---|
| `pfsense` | pfSense CE 2.8.1 | Most persistence lives in one file (`config.xml`), which is a significant advantage. See §6.1. |
| `linux` | Linux firewalls/hosts | nftables or iptables; backend must be detected, not assumed. See §6.2. |
| `frr` | BSD/FRR VM routers — **confirmed FRR, `vtysh`** | Routing config is a first-class persistence surface. Hardening posture in `HARDENING.md` §9. |

### 3.3 The distinction that makes this work: config vs state

This single line prevents most false positives.

**Config** is intended to be stable. Baseline it, diff it strictly, alert on any change.
Firewall rules, NAT, aliases, accounts, group membership, authorised keys, sshd settings, sudoers, cron entries, systemd units and timers, installed packages, boot hooks, static routes, routing neighbour *definitions*.

**State** is expected to churn. Display it, threshold it if useful, **never diff it**.
Connection/state table contents, interface counters, rule hit counters, routing table contents, neighbour up/down status, DHCP leases, uptime, load, logged-in users.

Get this wrong and the tool cries wolf every poll cycle, the operator learns to dismiss it, and it is worse than nothing. The FRR routers are where this bites hardest: `show running-config` is config and locks down; `show ip route` churns constantly and must never be diffed.

### 3.4 Item identity and review state — the actual product

Detection is easy. The triage model is the thing that decides whether this reduces fatigue or adds to it.

Every monitored thing is an **item** with a stable identity. Each item carries:

| Field | Meaning |
|---|---|
| `baseline_value` | The accepted-good value |
| `current_value` | What the last successful poll returned |
| `review_state` | `unreviewed` \| `accepted` \| `flagged` \| `suppressed` |
| `first_seen`, `last_changed` | Timestamps |
| `note` | Free text the operator writes at triage |

- **Accept** promotes `current_value` to `baseline_value`. Used for "that was us."
- **Flag** keeps the item on a worklist and **stops it re-alerting every cycle**. Used for "that was not us, I am dealing with it."
- **Suppress** is accept-with-prejudice for known-noisy items, with a mandatory note.

This has to work at **item level, not host level**. If accepting one change re-surfaces the other nine, the operator stops using the accept button and the whole model collapses.

Which means every item class needs a stable identity key across polls. Most are easy. Firewall rules are the awkward one, and pfSense supplies the answer — see `M-FW-01`.

**Deletions are changes.** A rule quietly removed, a log-forwarding line deleted, an account disabled — these are the changes least likely to be caught by eye and must raise the same alert as additions.

### 3.5 Cadence

| | |
|---|---|
| Default poll interval | 60 s |
| Minimum | 30 s (below this, poll cost on pfSense starts to matter) |
| Backoff on failure | 60 s → 120 s → 300 s, then hold |
| Reconciliation | Full collection every cycle. There is no incremental mode. |

Event-driven detection on the Linux boxes (`nft -j monitor` streamed over a held SSH channel) is **phase 2**, not phase 1. It only buys latency, and the operator's own triage cycle is measured in minutes. Its one genuine advantage is catching a change that is made *and reverted* inside a poll interval — a deliberate evasion against exactly this kind of tooling. Worth having eventually; not worth blocking the first build on.

pf has no notification mechanism, so pfSense is poll-only regardless.

## 4. Handling rule: never retain secrets

The generator already refuses to retain anything beyond `<aliases>`, `<filter>` and `<nat>` because source configs carry password hashes, private keys and cleartext service passwords. **The monitor inherits that rule and needs it more**, because it deliberately reads accounts and authentication material.

| Item | What is stored |
|---|---|
| Password hashes | **Never.** Store a salted digest of the hash, for change detection only, plus the lock state (`locked` / `no-password` / `set`). |
| Private keys | Never read, never stored. |
| Authorised public keys | Fingerprint (SHA256), key type, comment, and options string. Not the key body. |
| Service passwords in config | Never read. The pfSense adapter parses an explicit element allow-list, never the whole file. |
| Raw `config.xml` | Never stored. Only the extracted, allow-listed item set and section digests. |

A monitoring tool that hoovers up the estate's credential material is a worse liability than the problem it solves.

---

## 5. Collection matrix

IDs are stable and map one-to-one onto collectors and detections. Severity is the *default*; the operator can raise or lower per item.

Legend: **P** = pfSense, **L** = Linux, **R** = FRR router.

### 5.1 Accounts and privilege — `M-ACC-*`

This is the class the DCM26 pattern hits first.

| ID | Item | Plat | Identity key | Sev | Why |
|---|---|---|---|---|---|
| `M-ACC-01` | Local user accounts | P L R | username | **CRIT** | New account is the classic post-foothold move. |
| `M-ACC-02` | UID 0 accounts | P L R | username | **CRIT** | A second UID 0 account is never legitimate mid-exercise. |
| `M-ACC-03` | Group membership (admin/wheel/sudo/`admins`) | P L R | group + member | **CRIT** | Escalation without creating a new account — quieter, more common. |
| `M-ACC-04` | Login shell per account | P L R | username | **HIGH** | A service account moved from `/usr/sbin/nologin` to a real shell. |
| `M-ACC-05` | Password lock state | P L R | username | **HIGH** | A previously locked (`!`/`*`) account gaining a password. Digest only — see §4. |
| `M-ACC-06` | pfSense GUI privileges | P | username + priv | **CRIT** | `page-all` granted, or user added to `admins`. Escalation inside the GUI model. |
| `M-ACC-07` | **config.xml vs `/etc/passwd` reconciliation** | P | username | **CRIT** | See §5.1.1. The GUI and the box are separate entity sets. Reconciled, not diffed. |
| `M-ACC-08` | sudoers and `sudoers.d/` | L R | file + line | **CRIT** | `NOPASSWD: ALL` dropped into a new `sudoers.d` file is trivial to miss by eye. |
| `M-ACC-09` | PAM stack | L | file + line | **HIGH** | `/etc/pam.d/` modification for auth bypass. |
| `M-ACC-10` | `nsswitch.conf` | L | line | **MED** | Redirecting account lookup to an attacker-controlled source. |

#### 5.1.1 `M-ACC-07` — reconciling pfSense accounts against box accounts

The highest-value single detection in this document for the pfSense estate, and the one most easily built wrong.

**The GUI user list and the box's account list are separate entity sets, and they legitimately differ.** A naive diff fires on every box, every poll. The correct model has three buckets:

| Bucket | Meaning | Verdict |
|---|---|---|
| In **both** | A GUI user that also holds the shell-access privilege | Normal |
| **`config.xml` only** | A GUI user without shell access | Normal — most users should look like this |
| **`/etc/passwd` only** | Either a base FreeBSD/pfSense system account (`root`, `nobody`, `_dhcp`, `unbound`, `www`, `sshd`, …) — baseline these once — **or an account created outside the GUI** | The second case is the finding |

An account added directly to `/etc/passwd` by someone with shell **does not appear in the User Manager at all**. The web interface is what everyone checks, so this is the escalation path with the longest expected dwell time.

Two mappings must be right or the check misfires:

- **`admin` in `config.xml` corresponds to `root` (uid 0) on the box**, not to a passwd entry named `admin`. Hard-code the mapping.
- A GUI user **gaining** the shell-access privilege legitimately causes a new passwd entry to appear. Correlate that with the privilege change (`M-ACC-06`) and render it as one event, not two unrelated alarms.

A fourth check belongs here and is quieter than all of the above: **a passwd entry whose uid or shell does not match what `config.xml` says it should be.** That is tampering with a legitimate account rather than adding a new one, and nothing else in this document catches it.

> **Test on the box (§12 Q2).** Determine whether pfSense's account sync *reconciles* — deletes strays — or only adds. If it reconciles, a hand-added passwd entry is wiped at the next config write, so an attacker wanting durability must go through `config.xml`, where it is GUI-visible but unwatched. If it only adds, the passwd entry persists invisibly. The answer changes which of the two halves matters more, and therefore which to build first.

### 5.2 Authentication material — `M-AUTH-*`

| ID | Item | Plat | Identity key | Sev | Why |
|---|---|---|---|---|---|
| `M-AUTH-01` | `authorized_keys` entries, all users, all homes | P L R | user + key fingerprint | **CRIT** | The single most common persistence mechanism. Attacker-added keys usually carry innocuous comments — match on fingerprint, never on comment. |
| `M-AUTH-02` | Keys in non-default locations | L R | path + fingerprint | **CRIT** | Resolve `AuthorizedKeysFile` from effective sshd config rather than assuming `~/.ssh/authorized_keys`. |
| `M-AUTH-03` | Effective sshd configuration | L R | directive | **CRIT** | Collect with `sshd -T`, which resolves `Include` and `Match` blocks. Hashing `sshd_config` alone misses anything in an included file. |
| `M-AUTH-04` | `PermitRootLogin`, `PasswordAuthentication`, `PermitEmptyPasswords` | L R | directive | **CRIT** | Explicit named items, not buried in a config blob, because these are the ones that matter. |
| `M-AUTH-05` | `AuthorizedKeysCommand` / `AuthorizedKeysCommandUser` | L R | directive | **CRIT** | A script that returns any key the attacker wants. Elegant, persistent, almost never checked. |
| `M-AUTH-06` | `PermitUserEnvironment`, `~/.ssh/environment` | L R | directive / file | **HIGH** | Environment injection at login. |
| `M-AUTH-07` | `/etc/ssh/sshrc`, `~/.ssh/rc` | L R | path | **HIGH** | Executed on every login. Persistence with no unit, no cron, no key. |
| `M-AUTH-08` | Host key fingerprints | P L R | key type | **HIGH** | Changed host key means rebuild, restore — or man-in-the-middle. |
| `M-AUTH-09` | pfSense SSH settings | P | element | **HIGH** | `<system><ssh>`: enabled state, key-only flag, listening port. |
| `M-AUTH-10` | Shell profile files | L R | path + digest | **MED** | `/etc/profile`, `/etc/profile.d/`, `~/.bashrc`, `~/.bash_profile`. |

> Everything in `M-AUTH-*` detects *change*. Whether the settings are strong in the first place is a separate question, answered by `HARDENING.md` `H-SSH-*`. A box shipped with `PasswordAuthentication yes` will sit green here forever — that is the gap the posture layer closes.

### 5.3 Scheduled execution — `M-SCHED-*`

| ID | Item | Plat | Identity key | Sev | Why |
|---|---|---|---|---|---|
| `M-SCHED-01` | Per-user crontabs | P L R | user + command | **HIGH** | |
| `M-SCHED-02` | `/etc/crontab`, `/etc/cron.d/` | P L R | file + command | **HIGH** | |
| `M-SCHED-03` | `cron.{hourly,daily,weekly,monthly}` | L | path | **HIGH** | Drop a script in, no crontab edit needed. |
| `M-SCHED-04` | pfSense `<cron>` items | P | command | **HIGH** | The Cron package writes into `config.xml`. GUI-visible persistence. |
| `M-SCHED-05` | systemd timers | L | unit name | **HIGH** | The modern equivalent of cron and the one people forget to check. |
| `M-SCHED-06` | `at` jobs | P L R | job id + command | **HIGH** | Single-shot, easy to miss, gone after it fires. |
| `M-SCHED-07` | `anacron` | L | job | **MED** | |

### 5.4 Services and listening ports — `M-SVC-*`

| ID | Item | Plat | Identity key | Sev | Why |
|---|---|---|---|---|---|
| `M-SVC-01` | Listening sockets | P L R | proto + bind addr + port + program | **HIGH** | A new listener on a firewall is a very short list of possibilities, none of them good. |
| `M-SVC-02` | Enabled services / unit files | P L R | unit or rc script name | **HIGH** | Enabled matters more than running — enabled survives reboot. |
| `M-SVC-03` | Running services | P L R | unit or process name | **MED** | Diffed against enabled set; a running service with no unit file is notable. |
| `M-SVC-04` | Installed packages | P L R | package name | **HIGH** | On an Internet-isolated range a newly installed package is a significant event. |
| `M-SVC-05` | Processes running from writable paths | P L R | path + argv digest | **HIGH** | Anything executing out of `/tmp`, `/var/tmp`, `/dev/shm`, `/home`. |
| `M-SVC-06` | Processes with no matching binary on disk | L | pid + exe | **CRIT** | `/proc/<pid>/exe` resolving to `(deleted)`. Classic memory-resident implant. |

### 5.5 Boot and load-time hooks — `M-BOOT-*`

| ID | Item | Plat | Identity key | Sev | Why |
|---|---|---|---|---|---|
| `M-BOOT-01` | `/usr/local/etc/rc.d/` contents | P R | filename + digest | **HIGH** | The FreeBSD place to put a thing that starts at boot. |
| `M-BOOT-02` | pfSense `<system><earlyshellcmd>` | P | command | **CRIT** | Runs at boot, lives in `config.xml`, survives reboot, and is almost never looked at. A pfSense-specific persistence favourite. |
| `M-BOOT-03` | `shellcmd` package entries | P | command | **CRIT** | Same idea, different element. Check whether the package is installed at all — its presence is itself a finding. |
| `M-BOOT-04` | `/etc/rc.local`, `/etc/rc.conf.local` | P L R | line | **HIGH** | |
| `M-BOOT-05` | systemd unit files (enabled) | L | unit name + digest | **HIGH** | Including user units under `~/.config/systemd/user/`. |
| `M-BOOT-06` | `/etc/ld.so.preload` | L | line | **CRIT** | Should be absent or empty. Any content is a finding until proven otherwise. |
| `M-BOOT-07` | `/etc/ld.so.conf.d/` | L | file + line | **HIGH** | |
| `M-BOOT-08` | Loaded kernel modules | P L R | module name | **HIGH** | |
| `M-BOOT-09` | Module autoload config | L | file + line | **HIGH** | `/etc/modules-load.d/`, `/etc/modprobe.d/`. |

### 5.6 Filesystem canaries — `M-FS-*`

Paul's instinct here — "scan for `.py` on the box, there shouldn't be any" — is right, but the rule needs sharpening, because a Linux host has thousands of legitimate `.py` files under `/usr/lib/python3` and some pfSense packages pull Python in as a dependency.

**The rule is not "there should be none". The rule is "there should be no new ones in paths where scripts have no business appearing."** Baseline whatever is there on day one; diff from there. That converts a noisy assertion into a precise one.

| ID | Item | Plat | Identity key | Sev | Why |
|---|---|---|---|---|---|
| `M-FS-01` | Scripts and binaries in canary paths | P L R | path + digest | **HIGH** | Canary paths: `/tmp`, `/var/tmp`, `/dev/shm`, `/root`, `/home/*`, `/usr/local/bin`, `/usr/local/sbin`, `/opt`, `/srv`, and the web root. Extensions `.py .sh .pl .php .rb .ps1` plus any ELF. |
| `M-FS-02` | Setuid/setgid binary inventory | P L R | path + digest | **CRIT** | A new setuid binary is escalation, full stop. |
| `M-FS-03` | File capabilities | L | path + caps | **CRIT** | `getcap -r /`. `cap_setuid` on a Python or Perl interpreter is a clean root path that a setuid scan misses entirely. |
| `M-FS-04` | Interpreter and tool inventory | P L R | binary name | **HIGH** | `python`, `perl`, `nc`, `ncat`, `socat`, `gcc`, `curl`, `wget`, `tcpdump`. Serves two purposes: tells the operator what an attacker on that box can already use, and flags loudly when a *new* one appears. |
| `M-FS-05` | Recently modified files in `/etc` | P L R | path + mtime + digest | **HIGH** | Catches config tampering the specific collectors above do not cover. |
| `M-FS-06` | World-writable files in system paths | P L R | path | **MED** | |
| `M-FS-07` | Immutable/append-only attributes | L | path + attrs | **MED** | `chattr +i` on an attacker's file to resist cleanup. |
| `M-FS-08` | Web root contents, where a GUI is served | P | path + digest | **CRIT** | A webshell dropped into the pfSense GUI tree gives authenticated-equivalent access and is reachable from anywhere the GUI is. |

`M-FS-08` deserves emphasis. The pfSense GUI is PHP. Anything writable under its document root that was not shipped is an emergency.

### 5.7 Firewall, NAT and aliases — `M-FW-*`

| ID | Item | Plat | Identity key | Sev | Why |
|---|---|---|---|---|---|
| `M-FW-01` | Filter rules | P | `<tracker>` | **CRIT** | pfSense assigns every filter rule a `<tracker>` value that persists across edits. Use it as the item key and the operator gets *"rule 17…12 changed action block → pass"* rather than *"the ruleset is different"*. This is the difference between a usable diff and an unusable one. |
| `M-FW-02` | Filter rules | L | normalised rule text within (table, chain) | **CRIT** | No stable identity available. nftables handles change on reload; iptables has none. An edit therefore reads as delete + add. Accept this rather than inventing fuzzy matching. |
| `M-FW-03` | NAT rules and port forwards | P L | tracker / normalised text | **CRIT** | A port forward is the quietest way to expose an internal host. |
| `M-FW-04` | Alias / table / set **definitions** | P L | alias name | **HIGH** | |
| `M-FW-05` | Alias / table / set **membership**, **flattened** | P L | alias name + resolved element | **CRIT** | The change nobody spots by eye. Adding one address to an existing permitted-source alias grants access without touching a single rule, and the rule list still reads exactly as correct as before. DCM26 already produced a `Temp` port alias exposing MySQL — by accident. Deliberately, it is a perfect backdoor. **Diff the resolved membership, not the literal entry list** — see §5.7.1. |
| `M-FW-06` | Live ruleset vs config of record | P | section digest | **CRIT** | pfSense generates the pf ruleset from `config.xml`. Someone with shell can `pfctl -f` a rule straight into the kernel without touching `config.xml` — invisible to anyone checking the GUI. Compare both and alert on divergence. |
| `M-FW-07` | Config change events and attribution | P | revision timestamp | **HIGH** | pfSense writes a backup into `/cf/conf/backup/` on every config change, and `config.xml`'s `<revision>` block records username, source IP and a change description. This is a change log with attribution already attached — collect it and you know *who and from where* before you have diffed anything. |
| `M-FW-08` | Logging configuration | P L | setting | **HIGH** | Disabling rule logging or remote syslog is a pre-attack step, not a post-attack one. |
| `M-FW-09` | **Management-source alias membership** | P L | alias name + resolved element | **CRIT** | The crown jewel. Elevated handling — see §5.7.1. |
| `M-FW-10` | URL-table alias presence and resolved contents | P | alias name | **CRIT** | An alias whose membership changes with no config change at all. See §5.7.1. |

#### 5.7.1 Aliases are the sharpest angle against this design

Adding a CIDR to the management-source alias — the `BT`/`GT` IP allow-lists — grants access from anywhere, changes no rule, and leaves the rule list reading exactly as correct as it did before. Nobody reviewing rules catches it. It is the single best move against a monitored estate, and it deserves treatment beyond a table row.

**Management-source aliases get elevated handling.** Any membership change is CRITICAL, never suppressible, and rendered as the full resolved CIDR list with the delta highlighted rather than as an alias name and a count. The operator should be reading addresses, not diffs of diffs.

**Flatten before diffing.** pfSense aliases nest — an alias can contain another alias. Adding a benign-looking nested alias that itself contains the attacker's range changes the `BT` alias by exactly one innocuous-looking entry. Resolve the full transitive membership and diff *that*; the literal entry list is display only.

**URL-table aliases are remote-controlled allow-lists.** pfSense supports `urltable` and `urltable_ports` alias types, which fetch their contents from a URL on a cron schedule. Their membership changes with **no configuration change at all** — nothing in `config.xml` moves, no revision is written, no backup is taken. On an Internet-isolated range there is no legitimate reason for one to exist, so:

- the **presence** of a URL-table alias is a finding in its own right (and a posture check — `HARDENING.md` `H-FW-05`);
- if one exists and is sanctioned, its **resolved contents** must be polled as a separate item, because the normal config-change detection is blind to it.

### 5.8 Routing — `M-RT-*`

Applies to the FRR routers. Routing is a pivot mechanism, not just plumbing: a static route or an injected neighbour redirects traffic without touching a single firewall rule.

| ID | Item | Plat | Identity key | Sev | Why |
|---|---|---|---|---|---|
| `M-RT-01` | Routing daemon running-config | R | config section | **CRIT** | `vtysh -c 'show running-config'` — the whole routing policy in one artefact. |
| `M-RT-02` | Static routes | P L R | prefix + next-hop | **CRIT** | |
| `M-RT-03` | Neighbour/peer **definitions** | R | peer address | **CRIT** | A new BGP or OSPF neighbour is an adversary joining your routing domain. |
| `M-RT-04` | Neighbour **status** | R | peer address | *state* | Display only. Sessions flap legitimately. Do not diff. |
| `M-RT-05` | Redistribution and route-map policy | R | statement | **HIGH** | |
| `M-RT-06` | `vtysh`/FRR access control | R | line | **CRIT** | `vtysh.conf`, `frr` group membership, enable password state. |
| `M-RT-07` | Interface IP configuration | P L R | interface + address | **HIGH** | A new address or alias on an interface. |

### 5.9 Collector path integrity — `M-INT-*`

The tool must monitor its own ability to monitor.

| ID | Item | Sev | Why |
|---|---|---|---|
| `M-INT-01` | Heartbeat — successful poll per host | **see below** | |
| `M-INT-02` | Collector script digest on target | **CRIT** | If the wrapper script is modified, everything it reports is a lie. See §5.9.1. |
| `M-INT-03` | Monitor account still present and unmodified | **CRIT** | |
| `M-INT-04` | Monitor key still present in `authorized_keys` | **CRIT** | |
| `M-INT-05` | Clock skew between collector and host | **MED** | Breaks `mtime`-based detection and log correlation. |

**Heartbeat failure is three different events, not one.** Rendering them identically throws away the most important signal the tool has:

| Failure | Meaning | Default |
|---|---|---|
| **Authentication failed** | Key removed, account deleted or modified, `authorized_keys` rewritten | **CRITICAL immediately.** No grace period. This is the loudest thing the tool can say. |
| Connection refused | SSH daemon stopped or port changed | **HIGH** after 2 consecutive failures |
| Host unreachable / timeout | Reboot, network fault, or box down | **MED** after 2, **HIGH** after 5. Reboots are normal mid-exercise. |
| Collector script digest mismatch | Tampering with the collection path | **CRITICAL immediately** |

#### 5.9.1 Verifying the collector script

**The expected digest lives on the collector, captured at deploy time. Never on the box.** A script that reports its own hash proves nothing — it is the first thing an attacker rewrites.

The forced command hashes the script with the system digest utility before running it, so the value crossing the wire is produced by something other than the script itself, and the collector compares it against the constant it recorded during setup.

Being straight about the limit: **with root on the box, an attacker can defeat any on-box self-verification.** What this buys is layering. To hide, they would have to modify the script *and* the `authorized_keys` forced-command line (`M-INT-04`) *and* survive the mtime and digest checks on `/usr/local/sbin` (`M-FS-01`, `M-FS-05`) *and* not appear in the VERBOSE sshd log (`HARDENING.md` `H-SSH-19`). Four independent chances to trip instead of none.

The collector script's own path is therefore an explicit member of the `M-FS-01` canary set, so it is covered twice by different mechanisms.

---

## 6. Per-platform collection reference

Indicative commands. The wrapper script (§7.5) runs these and emits JSON; the collector does not parse eight output formats over the wire.

### 6.1 pfSense CE 2.8.1

The advantage here is concentration: **most persistence lives in `config.xml`** — users, groups, privileges, SSH keys, cron entries, installed packages, `earlyshellcmd`, filter rules, NAT and aliases. One parsed artefact covers `M-ACC-01/02/03/04/06`, `M-AUTH-01/09`, `M-SCHED-04`, `M-BOOT-02/03`, `M-FW-01/03/04/05`.

Parse it with an explicit element allow-list, exactly as the generator does. Never store the file.

| Purpose | Command |
|---|---|
| Config of record | Parse `/cf/conf/config.xml`, allow-listed elements only |
| Change log + attribution | `ls -l /cf/conf/backup/` and the `<revision>` block |
| Live ruleset | `pfctl -sr`, `pfctl -sn` |
| Tables (aliases) | `pfctl -sT`, then `pfctl -t <name> -T show` |
| Listening sockets | `sockstat -46l` |
| Enabled rc services | `service -e` |
| Processes | `ps -auxww` |
| Packages | `pkg info` |
| Shell accounts | `getent passwd` — compare against `config.xml` (`M-ACC-07`) |
| Cron outside the GUI | `/etc/crontab`, `/var/cron/tabs/` |
| Boot hooks | `ls /usr/local/etc/rc.d/`, `/etc/rc.local` |
| Kernel modules | `kldstat` |
| Setuid inventory | `find / -xdev -perm -4000 -type f` |
| Digests | `sha256 -q <file>` |

**Privilege: resolved.** The range pfSense boxes have the `sudo` package installed (confirmed 26 Aug 26). The non-root monitor account path in §7 S3 works, and the read-only claim in §2 survives intact — the tool never needs an admin credential. Record `sudo` and any monitoring dependencies explicitly in the expected package set so they do not later read as findings under `M-SVC-04`.

**FreeBSD is not Linux.** `sha256`/`md5` not `sha256sum`/`md5sum`; `sockstat` not `ss`; `kldstat` not `lsmod`; `service -e` not `systemctl`. Writing the pfSense adapter against Linux muscle memory is the fastest way to a broken collector.

**Volatile — exclude before hashing:** `<revision>` (changes on every write), RRD data, DHCP leases, state table, interface counters, rule hit counters.

### 6.2 Linux

**Detect the firewall backend first. Do not assume.**

```
iptables -V        # prints "(nf_tables)" or "(legacy)"
```

If `nf_tables`, `iptables` is a shim over the same netlink API as `nft` — so `nft -j list ruleset` is the single source of truth, and phase-2 event monitoring via `nft -j monitor` covers `iptables` commands too. If `legacy`, `iptables-save`/`ip6tables-save`/`ipset save` are the sources and there is no event mechanism at all.

| Purpose | Command |
|---|---|
| Ruleset (nft) | `nft -j list ruleset` |
| Ruleset (legacy) | `iptables-save`, `ip6tables-save`, `ipset save` |
| Effective sshd config | `sshd -T` |
| Accounts | `getent passwd`, `getent group` |
| Password lock state | `/etc/shadow`, field 2 classified only — see §4 |
| sudo | `/etc/sudoers`, `/etc/sudoers.d/*` |
| Cron | `crontab -l -u <user>` per user, `/etc/crontab`, `/etc/cron.d/`, `/etc/cron.*/`, `/var/spool/cron/` |
| Timers | `systemctl list-timers --all` |
| Units | `systemctl list-unit-files --state=enabled` |
| Listening | `ss -lntup` |
| Packages | `dpkg -l` / `rpm -qa` |
| Modules | `lsmod` |
| Capabilities | `getcap -r / 2>/dev/null` |
| Setuid | `find / -xdev -perm -4000 -type f` |
| Canary paths | `find <canary paths> -xdev -type f \( -name '*.py' -o -name '*.sh' -o … \)` |
| Deleted-binary processes | `ls -l /proc/*/exe` — look for `(deleted)` |

**Normalisation — strip before hashing:**

- nftables counters (`counter packets N bytes N`). `nft -s list ruleset` where `--stateless` is still supported on that version; otherwise strip with a regex. Verify per box.
- nftables rule handles — omit `-a`.
- `iptables-save` counters — omit `-c`.
- Non-listening sockets from `ss` output; ephemeral source ports.
- systemd oneshot units that cycle between active/inactive.
- Timestamps in `systemctl list-timers` (`NEXT`, `LEFT`, `PASSED`) — keep unit name and schedule only.

### 6.3 BSD/FRR routers

| Purpose | Command |
|---|---|
| Routing config | `vtysh -c 'show running-config'` |
| Static routes | `vtysh -c 'show ip route static'` |
| BGP peers (config) | from running-config, not `show bgp summary` |
| Neighbour status (state) | `vtysh -c 'show bgp summary'`, `show ip ospf neighbor` — display only |
| FRR access control | `/etc/frr/vtysh.conf`, `/etc/frr/frr.conf`, `frr`/`frrvty` group membership |
| Host-level items | As §6.1 or §6.2 depending on the underlying OS |

**Never diff `show ip route`.** It churns by design. Diff the static routes and the neighbour definitions from running-config only.

---

## 7. Setup — what the operator actually does

This runs the evening the documents land, or first thing on day one. Assume the operator is tired, working from a checklist, and will not read prose. The wizard is the deliverable; this section is its content.

Realistic budget: **20 minutes for the first box, 5 minutes per box thereafter.**

### S0 — Prerequisites

- [ ] Collector host identified and its IP address fixed (§12 Q1 — this is still open)
- [ ] Management IP of every firewall and router listed
- [ ] Confirmed you have admin access to each box by the normal route
- [ ] Decided whether the estate is being hardened *before* or *after* first baseline (see S7 — the answer is both)

### S1 — Place the collector

The container runs on the collector host. It needs network reach to every managed box on the management path, and nothing else. It should not be reachable *from* the managed boxes.

If the hardening cell only has laptops, monitoring is shift-hours, not 24-hour, and the tool must say so on the dashboard rather than implying continuous cover. A laptop that closes at 2200 is not a monitor.

### S2 — Generate the key pair

Done by the wizard, on the collector, in one click. Ed25519. Passphrase-protected; the passphrase is entered once at container start and held in memory only.

**The Blue Team generates its own key.** The private key never exists anywhere else and is never supplied with the tool. This is not ceremony — it is the thing that makes the tool defensible to have built.

### S3 — Create the monitor account

**pfSense** (per box, GUI):

1. System → User Manager → Groups → Add. Name `btmon`. Assign **only** the privilege needed for shell access.
2. System → User Manager → Users → Add. Name `btmon`. Member of group `btmon` only. **Not** `admins`.
3. Paste the public key into the user's Authorized SSH Keys field.
4. System → Advanced → Admin Access: SSH enabled, key-only authentication on.
5. Deploy the wrapper script and add the `sudo` rule (see below).

> **Resolved 26 Aug 26.** A pfSense shell-access user is *not* root, and `pfctl` and `config.xml` reads need root — but **the range pfSense boxes have the `sudo` package installed**, so the narrow `NOPASSWD` path works exactly as it does on Linux. Grant `btmon` a single entry for the wrapper script and nothing else. The fallbacks that were on the table — using the root-equivalent `admin` account, or accepting reduced collection — are no longer needed, and the tool holds no credential that can change a firewall.

**Linux / FRR host:**

```
useradd -r -m -s /bin/sh btmon
install -o root -g root -m 0755 btmon-collect /usr/local/sbin/btmon-collect
# /etc/sudoers.d/btmon
btmon ALL=(root) NOPASSWD: /usr/local/sbin/btmon-collect
```

The script must be owned by root and **not writable by `btmon`**. A collector account that can rewrite its own collector is not a control.

### S4 — Restrict the access

Two layers. Do both.

**In `authorized_keys`:**

```
from="<collector-ip>",command="/usr/bin/sudo /usr/local/sbin/btmon-collect",\
no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty ssh-ed25519 AAAA...
```

Forced command means the key can do exactly one thing. `no-port-forwarding` matters as much as the rest: without it, a stolen monitor key is a pivot into the management network.

> Verify that pfSense preserves `from=` and `command=` options — it regenerates `authorized_keys` from `config.xml`, and if it strips the options your restriction silently is not there. **Test this, do not assume it** (§12 Q2).

**On the firewall itself:** restrict management SSH to the collector's address. The generator already produces management-access rules — the two halves of the tool close each other's loop, and this rule should be emitted as part of the generated ruleset rather than hand-written.

### S5 — Deploy the collector script

One script per platform family, pushed during setup. Emitting JSON from the box beats parsing eight output formats over the wire, and it means the privilege boundary is one auditable file rather than an open shell.

Requirements:

- Read-only. No arguments that change behaviour. No shell interpolation of anything received over the connection.
- Deterministic output ordering, so digests are stable across runs.
- Bounded runtime (hard timeout ~20 s) — a `find` across a large filesystem must not hang the poll.
- Reports its own SHA256 in its output, and the collector **also** verifies it independently (`M-INT-02`).

### S6 — Test the connection

Wizard round-trips each host and reports pass/fail per box, with the specific failure named — auth, refused, timeout, sudo denied, script missing, digest mismatch. Not "connection failed".

### S7 — Take two baselines

| Baseline | When | Why |
|---|---|---|
| **As-received** | Before the team changes anything | Records exactly what Green Team shipped. Settles "was that us or was it always like that?" for the rest of the exercise, and it is the only chance to capture it. |
| **Hardened** | After the hardening pass is complete | The working baseline everything is diffed against. |

Taking only the hardened baseline throws away the as-received state permanently. Take both.

The generator's output is the natural seed for the firewall portion of the hardened baseline — the ruleset it produced *is* the intended state. Build them to share that artefact.

### S8 — Prove it works

**Do not skip this.** An untested monitor is worse than no monitor, because the operator trusts it.

On one box, with the team watching:

1. Add a dummy user. Confirm it appears as `M-ACC-01` within one poll interval. Remove it. Confirm the removal also alerts.
2. Add an SSH key to a test account. Confirm `M-AUTH-01` fires on the fingerprint.
3. Add one address to an alias without touching any rule. Confirm `M-FW-05` fires. *This is the one people assume will not be caught.*
3a. Add a **nested** alias containing a new range to the management-source alias. Confirm `M-FW-09` resolves it and reports the effective addresses, not just "one entry added". If this test passes, the sharpest angle against the design is covered.
4. Add a cron entry. Confirm `M-SCHED-01`.
5. Drop a `.sh` file into `/tmp`. Confirm `M-FS-01`.
6. Stop SSH on the box. Confirm the heartbeat distinguishes refused from unreachable.
7. Remove the monitor key. Confirm it raises **CRITICAL immediately**, not a grey tile.
8. Accept one change and confirm the other outstanding items stay outstanding. Then confirm the accepted item does not re-alert.

Step 8 tests the triage model, which is the part most likely to be subtly wrong.

### S9 — Operating rhythm

| | |
|---|---|
| Shift handover | Clear the unreviewed queue to zero, or hand over what is outstanding and why. A non-zero unreviewed count at handover is the handover. |
| Before any planned change | Note it. The tool cannot tell "us" from "them" — only the operator can. |
| After any planned change | Accept the resulting items immediately, while you still remember what you did. Deferring this is how the queue becomes noise. |
| On a CRITICAL | Read the diff, decide, act on the box manually. The tool does not act. |

---

## 8. Severity and the dashboard

### 8.1 Severity

| Level | Means | Examples |
|---|---|---|
| **CRITICAL** | Consistent with an active compromise. Act now. | New account, new UID 0, new SSH key, privilege granted, sshd weakened, live-vs-config divergence, alias membership change, monitor auth failure, webshell |
| **HIGH** | Should not have happened without someone knowing. | New cron/timer/service/listener, new package, boot hook change, setuid change |
| **MEDIUM** | Worth a look this shift. | File canaries, module load, world-writable files, clock skew |
| **INFO** | Context, not alarm. | State changes, neighbour flaps, counters |

Severity is per item and adjustable. If the team's own workflow legitimately produces HIGH items every hour, that item gets downgraded with a note — better than the operator learning to ignore the colour.

### 8.2 Dashboard

Three levels, and the top one is the whole point.

**Estate view.** One tile per host. Tile colour is the highest unreviewed severity on that host — not its average, not its most recent. A single number dominates the page: **total unreviewed items across the estate.** If that number is zero the operator can stop looking. That is the fatigue reduction, and everything else is detail.

**Host view.** Items grouped by class (§5), each showing review state, with the outstanding ones first. One-click to launch the box's web GUI or copy an SSH command — the operator's next move is always "log in and look", so make that zero-friction.

**Item view.** The actual diff, before and after, in the platform's own syntax. Plus: when it changed, what the previous value was, attribution if available (`M-FW-07` on pfSense gives username and source IP for free), and the three buttons — accept, flag, suppress-with-note.

Plus one view that earns its place: **"changed since I last looked"**, keyed to the operator, so someone coming back from a break sees their own delta rather than re-reading everything.

**Grafana was considered and rejected.** This is discrete change events and text diffs, not time series. Getting there means Prometheus or Loki plus Grafana provisioned offline, and at the end of it Grafana still cannot render "here is the unified diff of what changed on the DMZ firewall at 14:32". A purpose-built Jinja2 view is less work and more useful. Compromise: expose a Prometheus-format `/metrics` endpoint (unreviewed count, last successful poll per host, per-host state) so the tool is *scrapeable* if the team has monitoring, without owning the stack.

---

## 9. Privilege requirements

Honest summary, because it is the thing that determines whether the read-only claim in §2 survives contact.

| Item class | Needs root? | If unprivileged |
|---|---|---|
| Firewall ruleset | **Yes** | Not collectable |
| `config.xml` (pfSense) | **Yes** | Not collectable |
| Accounts, groups | No | Full |
| Password lock state | **Yes** | Not collectable |
| `authorized_keys`, all users | **Yes** | Own user only |
| `sshd -T` | **Yes** | Fails |
| Root/other-user crontabs | **Yes** | Own user only |
| Listening ports **with process names** | **Yes** | Ports only, no process |
| systemd units/timers | No | Full |
| Packages | No | Full |
| Setuid/capability scan | No | Full |
| `/proc/*/exe` for other users | **Yes** | Own processes only |

Full coverage needs root-equivalent **read**. The tight form of that is a forced-command wrapper invoked through a single-entry `NOPASSWD` rule — the key can execute one root-owned, non-writable script from one address and nothing else. That is a materially different thing from handing the tool an admin credential, and the distinction should be stated plainly to whoever signs this off.

## 10. Build order

Each step is independently useful. Stop at any point and still have something.

| # | Milestone | Why here |
|---|---|---|
| 1 | Inventory model, credential store, SSH transport, heartbeat | Even alone, "are all my boxes up and is my access intact" beats nothing |
| 2 | Linux adapter: accounts, keys, sudo, cron | Easiest to test off-range; hits the DCM26 pattern directly |
| 3 | Diff engine + item identity + review state | The product. Prove it on one adapter before adding more |
| 4 | Estate/host/item dashboard | First point it is genuinely usable |
| 5 | pfSense adapter, `config.xml` parse, `M-ACC-07`, `M-FW-01/06/07` | Highest-value target platform; reuses the generator's parser |
| 6 | Services, ports, boot hooks, filesystem canaries | Broadens coverage |
| 7 | FRR adapter | Platform confirmed; routing is its own persistence surface |
| 8 | Posture checks (`HARDENING.md`) over the collected set | Reuses every adapter. Useful on day one, before any attack |
| 9 | `/metrics`, digest export, shift handover report | Polish |
| 10 | `nft monitor` event streaming | Phase 2. Latency only |

Steps 1–4 are the minimum viable tool. If time runs short, that is what ships.

## 11. Relationship to the generator

One tool, two halves that close each other's loop:

- The generator's output **is** the monitor's firewall baseline. Same artefact, same fingerprinting.
- The monitor's `M-FW-06` (live vs config divergence) checks that what the generator produced is actually what is loaded.
- The generator emits the management-access rule that restricts SSH to the collector (S4).
- The inventory — hosts, addresses, GUI URLs, credentials — is shared. Defined once.
- The generator's "never retain secrets" rule (§4) is inherited and extended.
- `HARDENING.md` runs its posture checks (`H-*`) over the same collected item set — one collection, two evaluations. Adapters are written once.

The estate inventory and the baseline artefact are the shared spine. Design them once, before either half is built.

## 12. Open questions

| # | Question | Blocking | Who |
|---|---|---|---|
| **Q1** | Does the hardening cell get always-on kit in-enclave, or laptops only? Decides 24-hour vs shift-hours monitoring, and whether the dashboard must state its own coverage gap. | Not blocking; changes claims made to the team | Blue Team lead |
| **Q2** | **pfSense box behaviour, two parts.** (a) Does pfSense preserve `from=`/`command=` options when it regenerates `authorized_keys` from `config.xml`? (b) Does its account sync reconcile or only add — see §5.1.1? *The privilege half is closed: `sudo` is installed on the range boxes.* | (a) blocks the access restriction; (b) shapes `M-ACC-07` | Test on a CE 2.8.1 box — same box as the existing section-restore question |
| ~~**Q3**~~ | ~~Confirm the routers are FRR.~~ **Closed 26 Aug 26 — confirmed FRR, `vtysh`.** Hardening posture in `HARDENING.md` §9; `H-Q2` there covers which daemons expose VTY ports. | — | — |
| **Q4** | Is any monitor account/key acceptable to the exercise lead at all, and does Green Team need to be told? An unannounced monitoring account on range infrastructure is the sort of thing that is better raised than discovered. | Not technical, but raise early | Exercise lead |
| **Q5** | Does the team have any existing log collection in-enclave worth emitting to, rather than this being the only pane of glass? | Not blocking | Blue Team lead |

## 13. Conflict of interest

Recorded here so it is not lost.

The tool is built by someone on Red Team. Read-only, no revert and Blue-Team-generated keys remove the serious version of the problem — the tool holds nothing that can change the estate, and its author never holds a credential to it.

What remains is informational: the tool encodes what the Blue Team watches for and what their baseline looks like. The clean line is that it is handed over before the exercise and its author has no access to it during. Raise it explicitly with the exercise lead as a separate item from the generator (Q4) — the two have different risk profiles and bundling them invites a single hurried answer to two different questions.
