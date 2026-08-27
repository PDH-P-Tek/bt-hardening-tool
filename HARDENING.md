# Hardening — Posture Checks

**Status:** design v0.1, pre-build.

**Read `MONITORING.md` first.** This document defines a second, independent evaluation that runs alongside it. The two are easy to confuse and must not be merged.

---

## 1. Why this is separate from drift detection

`MONITORING.md` answers *"has this changed since baseline?"*

That question has a blind spot, and it is a large one: **it will never flag anything that was weak when Green Team shipped it.** If a box arrives with `PasswordAuthentication yes`, that becomes the baseline, the tile stays green, and the tool is silent about it for the entire exercise. Drift detection is only useful *after* an attacker acts.

Posture checks answer a different question: *"is this setting weak, regardless of whether anyone touched it?"*

| | Drift (`M-*`) | Posture (`H-*`) |
|---|---|---|
| Compares against | The team's own baseline | A recommended standard |
| Fires when | Something changed | Something is weak |
| Useful | After an attack | **Before one, from minute zero** |
| Resolution | Accept, or investigate | Fix, or waive with a reason |
| Silent on | A weak but unchanged setting | A change from strong to slightly-less-strong that is still above the bar |

Both run on the same collected data, every poll. A single item can be simultaneously drift-clean and posture-failing, and that combination is extremely common on day one — it is, in fact, the normal state of a freshly-issued range box.

This layer is also what makes the tool useful **before the exercise starts**, which matters when the team has one day of prep and no attacks to detect yet.

## 2. What a check is

Each check is a pure function of collected state, with a stable ID. Checks live in `hardening-checks.yaml`; this document is the rationale and the authority on intent, in the same relationship `EVIDENCE.md` has to the generator's validators.

| Field | Purpose |
|---|---|
| `id` | Stable, e.g. `H-SSH-03` |
| `applies_to` | Platform set — `pfsense`, `linux`, `frr` |
| `title` | One line the operator reads |
| `recommended` | The target value |
| `current` | Collected |
| `rationale` | Why, in one or two sentences. Not a lecture. |
| `remediation` | Exact steps for that platform — GUI path or config line |
| `scoring_risk` | `none` \| `possible` \| **`high`** — does applying this risk breaking a scored service? |
| `lockout_risk` | `none` \| **`high`** — can applying this lock the operator out? |
| `confidence` | `certain` \| `likely` \| `unverified` — honest, same convention as `service-catalogue.yaml` |

`scoring_risk` and `lockout_risk` are not decoration. A hardening tool that gets a team locked out of their own firewall, or that costs them points, will be switched off within the hour and never trusted again.

## 3. Result states and the golden rule

`PASS` · `FAIL` · `NOT-APPLICABLE` · `WAIVED` (requires a note) · `UNKNOWN` (not collectable at current privilege)

**The tool never applies a fix.** It renders the current value, the recommended value, and the exact steps. The operator acts on the box. This is the same line `MONITORING.md` §2 draws and for the same reasons — and here there is an additional one: several of these changes can lock you out of the box you are changing.

`UNKNOWN` must be visually distinct from `PASS`. A check that could not run is not a check that passed, and conflating them is how a dashboard lies.

## 4. Ordering — what to do on day one

Working down the list in ID order is wrong. This sequence is ordered by risk of doing it in the wrong order.

| # | Step | Why here |
|---|---|---|
| **0** | **Confirm console access to every box before changing anything.** VM console via vSphere, or physical. Know the recovery path. | Everything below can lock you out. On pfSense the escape is console → shell → `pfctl -d` to disable the packet filter entirely. If you cannot reach a console, do not start. |
| 1 | Per-operator accounts created, key-based auth working, tested from a second session | Never harden yourself out of the box you are hardening. Keep an authenticated session open in another window throughout. |
| 2 | Management-access rules — every interface, **both address families** | The control that everything else depends on. |
| 3 | Verify step 2 works, from the collector *and* an operator workstation | |
| 4 | **Then** disable anti-lockout (`H-PF-01`), and verify again immediately | This is the single highest-lockout-risk change in the document. It is also the one that makes step 2 real. |
| 5 | SSH key-only, kill password authentication | |
| 6 | Turn off unauthenticated management services — SNMP, telnet, UPnP | Fast, low risk, high value. |
| 7 | Logging: remote syslog, VERBOSE sshd, log on block rules | Do this before you need it. |
| 8 | Take the as-received and hardened baselines (`MONITORING.md` S7) | |
| 9 | Everything else, worst `scoring_risk` last | |

Steps 0–4 are the ones that go wrong. The rest is routine.

## 5. `H-SSH-*` — OpenSSH (Linux, FRR)

Collected from `sshd -T`, so `Include` and `Match` blocks resolve correctly. Hashing `sshd_config` alone misses anything in an included file — a fact worth knowing in both directions, since it is also where an attacker would put something.

### Authentication

| ID | Setting | Recommended | Rationale |
|---|---|---|---|
| `H-SSH-01` | `PermitRootLogin` | `no` | Forces attribution through a named account. `prohibit-password` is an acceptable waiver where automation needs it. |
| `H-SSH-02` | `PasswordAuthentication` | `no` | Removes credential guessing entirely. |
| `H-SSH-03` | `KbdInteractiveAuthentication` | `no` | The way `H-SSH-02` gets silently bypassed. Older builds call it `ChallengeResponseAuthentication` — check both. |
| `H-SSH-04` | `PermitEmptyPasswords` | `no` | |
| `H-SSH-05` | `PubkeyAuthentication` | `yes` | |
| `H-SSH-06` | `AuthorizedKeysCommand` | unset | A script that can return any key the attacker wants. Persistent, invisible to anyone reading `authorized_keys`, and almost never checked. If set and not deliberately, treat as compromise. |
| `H-SSH-07` | `MaxAuthTries` | `3` | |
| `H-SSH-08` | `LoginGraceTime` | `30` | |
| `H-SSH-09` | `StrictModes` | `yes` | |

### Access scope

| ID | Setting | Recommended | Rationale |
|---|---|---|---|
| `H-SSH-10` | `AllowGroups` / `AllowUsers` | Explicit allow-list | An account created by an attacker cannot log in even with a valid key. This is the check that most directly defeats the DCM26 pattern. |
| `H-SSH-11` | `ListenAddress` | Management interface only | Underused, and does more work than most firewall rules. If sshd is not listening on the segment, no rule ordering mistake can expose it. |
| `H-SSH-12` | `Port` | Site decision | Low value alone. Do not spend the outage budget on it. |

### Anti-pivot

These matter far more on a firewall or router than on a general host. A compromised account on a border device with forwarding enabled is a route into every segment that device touches.

| ID | Setting | Recommended | Rationale |
|---|---|---|---|
| `H-SSH-13` | `PermitTunnel` | `no` | Builds a layer-3 tunnel straight through the box. On a firewall this defeats the firewall. Highest-value item in this table. |
| `H-SSH-14` | `AllowTcpForwarding` | `no` | Turns one SSH session into arbitrary access to anything the box can reach. |
| `H-SSH-15` | `AllowAgentForwarding` | `no` | A compromised box can use the connecting operator's agent to reach onward hosts as them. |
| `H-SSH-16` | `GatewayPorts` | `no` | |
| `H-SSH-17` | `X11Forwarding` | `no` | |
| `H-SSH-18` | `PermitUserEnvironment` | `no` | Environment injection at login. Pairs with `~/.ssh/environment`. |

### Forensics

| ID | Setting | Recommended | Rationale |
|---|---|---|---|
| `H-SSH-19` | `LogLevel` | `VERBOSE` | Logs the **key fingerprint** used on each successful authentication. That ties every login to a specific entry in the `M-AUTH-01` key inventory — so when a rogue key is found, the logs say exactly when it was used and from where. Cheap to set, disproportionate value during an incident. |
| `H-SSH-20` | Remote syslog for auth events | Configured | Logs on a box the attacker controls are evidence the attacker controls. |
| `H-SSH-21` | `Ciphers`, `MACs`, `KexAlgorithms` | Modern sets only | Low practical risk in a range enclave. Listed for completeness; `scoring_risk: none`, priority low. |

### pfSense caveat

pfSense generates `sshd_config` itself and **overwrites hand edits**. Almost nothing in this section is settable there. The pfSense SSH posture reduces to key-only authentication, the listening port, and — for everything else — firewall rules. See `H-PF-04` and §6.

## 6. `H-PF-*` — pfSense platform

| ID | Check | Recommended | Notes |
|---|---|---|---|
| `H-PF-01` | **Anti-lockout rule** | Disabled, *after* management rules are proven | pfSense automatically installs a rule on the management interface permitting the **entire** subnet to the GUI and SSH ports, **above** all user rules. Until it is disabled, a BT-alias restriction on management access is decorative. Highest `lockout_risk` in this document — follow §4 steps 2–4 exactly. |
| `H-PF-02` | GUI protocol | HTTPS | |
| `H-PF-03` | GUI/SSH reachable from WAN | No | |
| `H-PF-04` | SSH authentication mode | Public key only | Note the setting has three states in current versions — disabled, public key only, require both. "Not disabled" is not the same as "key only". |
| `H-PF-05` | Per-operator accounts, `admin` not used interactively | Enforced | Shared accounts destroy attribution, which is most of what the monitor is for. |
| `H-PF-06` | GUI session timeout | Set, non-zero | |
| `H-PF-07` | DNS rebind and HTTP referrer checks | Left enabled | Both are on by default and both get switched off by people troubleshooting. Disabling them re-enables browser-based attacks against the GUI. |
| `H-PF-08` | Installed package set | Matches baseline | On an Internet-isolated range, an unexpected package is a significant event. `sudo` and the monitoring dependencies are expected — record them explicitly so they do not read as findings. |
| `H-PF-09` | Config backup history intact | Retained | `/cf/conf/backup/` is the change log with attribution. An attacker clearing it is itself the finding. |
| `H-PF-10` | SNMP | Disabled, or v3 with non-default credentials | A `public` community on a firewall is a full configuration read. Cheap for an attacker, frequently left on. |
| `H-PF-11` | UPnP/NAT-PMP | Disabled | Lets an internal host open its own inbound port forwards. On a compromised host, that is a self-service backdoor. |
| `H-PF-12` | Unused services | Off | Every listener is attack surface on a box whose job is not to serve. |

**The boolean trap applies here.** `CLAUDE.md` ground-truth item 3 — empty element means false, `yes` means true — hits `H-PF-01` directly. A naive presence check on the anti-lockout element reports "disabled" on every real config. Which raises a question worth answering from the DCM26 end-state set you already hold: **was anti-lockout actually still active on every enclave?** If so, the management restrictions those teams wrote were bypassable from their own LAN all exercise, and that belongs in `EVIDENCE.md` alongside the IPv6 finding. It is the same class of defect — careful work silently not applying.

## 7. `H-FW-*` — ruleset posture

Overlaps the generator's validators by design. The difference is that these run against **live collected state** rather than generated output, so they catch drift the generator cannot see and configurations the generator did not produce.

| ID | Check | Recommended | Notes |
|---|---|---|---|
| `H-FW-01` | Management access restricted to the BT source alias | On **every** interface | Rules are evaluated on the ingress interface. A restriction on one interface is not a restriction. |
| `H-FW-02` | IPv6 parity for every management rule | Enforced | `EVIDENCE.md` records 74 v4-only rules across the estate sitting above `inet46` catch-alls. On a management rule that is not a partial failure — the GUI stays reachable over v6 and the control is worthless. |
| `H-FW-03` | No `pass any → any` on any interface | Enforced | 6 of 6 enclaves finished DCM26 with these live. |
| `H-FW-04` | Block rules log | Enabled | You cannot investigate what was never recorded. |
| `H-FW-05` | **No `urltable` / `urltable_ports` aliases** | None present | These fetch their contents from a URL on a schedule, so membership changes with **no configuration change at all**. A remote-controlled allow-list. On an isolated range there is no legitimate use, and the presence of one is a finding in its own right. |
| `H-FW-06` | Alias naming heuristic | No `temp`, `tmp`, `test`, `x` | DCM26 produced a `Temp` port alias exposing MySQL to the greynet. Weak signal, near-zero cost. |
| `H-FW-07` | Description/action agreement | No `pass` rule described as `BLOCK` | Three occurred at DCM26. |
| `H-FW-08` | Anti-spoof and bogon filtering on WAN | Enabled | |
| `H-FW-09` | No port forwards targeting management ports | Enforced | |
| `H-FW-10` | Remote syslog configured and reachable | Enabled | Reachability is part of the check. A syslog target that stopped answering three hours ago is a silent failure. |

## 8. `H-ACC-*` — accounts

| ID | Check | Recommended |
|---|---|---|
| `H-ACC-01` | One account per operator, no shared logins | Enforced |
| `H-ACC-02` | No duplicate UID 0 |Enforced |
| `H-ACC-03` | Unused/default accounts locked | Enforced |
| `H-ACC-04` | No account with an empty password field | Enforced |
| `H-ACC-05` | `sudo` grants are specific, not `ALL=(ALL) NOPASSWD: ALL` | Enforced |
| `H-ACC-06` | The monitor account holds read-only rights only | Enforced — self-check |

`H-ACC-06` is the tool checking its own restraint. If the monitoring account has drifted into holding write access, the read-only claim in `MONITORING.md` §2 has quietly stopped being true and everyone should know.

## 9. `H-FRR-*` — FRR routers

Confirmed platform. Routing is a pivot mechanism: an adversary that joins the routing domain redirects traffic without touching a single firewall rule, and the firewall rules will still read as correct.

| ID | Check | Recommended | Rationale |
|---|---|---|---|
| `H-FRR-01` | **Daemon VTY ports** (`zebra` 2601, `ospfd` 2604, `bgpd` 2605, and siblings) | Bound to loopback or disabled | Each FRR daemon can expose its own telnet-style management port. Reachable, with a default or weak password, that is direct control of routing. Frequently forgotten because the operator uses `vtysh` locally and never thinks about the ports underneath. |
| `H-FRR-02` | `access-class` on VTY | Restricted to management sources | |
| `H-FRR-03` | Enable/vty password | Set, not default | |
| `H-FRR-04` | **`passive-interface default`**, with explicit exceptions | Enforced | Without it, the router will attempt adjacency on every interface. An attacker on any attached segment can form one. Highest-value item in this table. |
| `H-FRR-05` | Routing protocol authentication (OSPF, BGP) | Enabled on every adjacency | |
| `H-FRR-06` | BGP neighbours explicitly configured, no dynamic/listen ranges | Enforced | |
| `H-FRR-07` | Inbound prefix filtering per neighbour | Enforced | |
| `H-FRR-08` | `maximum-prefix` per neighbour | Set | Bounds the damage from a flood of injected routes. |
| `H-FRR-09` | No unfiltered `redistribute` | Route-map on every redistribution | The quiet way an attacker's prefixes enter the domain wearing a legitimate badge. |
| `H-FRR-10` | Log adjacency and neighbour changes | Enabled | Turns a pivot attempt into a log line. |
| `H-FRR-11` | `/etc/frr/` permissions | `frr.conf` 0640 `root:frr`, directory not world-readable | Config carries neighbour authentication keys. |
| `H-FRR-12` | Host-level posture | Per `H-SSH-*`, `H-ACC-*` | The router is also a box. It gets the same checks. |

`H-FRR-04` and `H-FRR-05` together are what stop an adversary with a foothold on any attached segment from becoming a routing peer. On a range with flat-ish enclave segments they are the difference between a compromised host and a compromised path.

## 9.1 `H-IMP-*` — an agent already on the box

The rest of this document asks whether a box is configured to resist being taken. This
asks whether it has already been taken, and it is written against one specific chain
seen in play rather than an imagined one:

1. `curl` a payload down — a Tuoni or Metasploit agent, typically named to look like
   part of the platform (`fwshell` and similar).
2. **Move it somewhere persistent.** On pfSense `/tmp` and `/var` are memory-backed, so
   an implant left there dies at the next reboot. `/usr/` and friends survive, and the
   attacker knows it.
3. `chmod +x`.
4. Persist: `echo "@reboot /path/to/fwshell" | crontab -`, or an entry in `config.xml`.
5. Wake it. The trigger can be as quiet as a crafted ICMP echo of a particular size,
   which matters because availability scoring means echo is never blocked outright.

| ID | Check | Recommended | Rationale |
|---|---|---|---|
| `H-IMP-01` | `earlyshellcmd` / `shellcmd` in `config.xml` | None present | A stock pfSense has neither element. The baseline is empty, so **any** member was put there deliberately by somebody. Removing the binary and leaving this re-runs it at the next boot. |
| `H-IMP-02` | Processes running a **deleted** binary | None | What a payload does when it unlinks itself after starting. On a firewall running a fixed set of services there is no benign explanation. |
| `H-IMP-03` | Processes running from a **world-writable** path | None | `/tmp`, `/dev/shm`, a home directory — it is running something anybody with a shell could have replaced. |
| `H-IMP-04` | `@reboot` or writable-path entries in any scheduled job | None | The standard way an implant survives the reboot you were relying on to clear it. Remove it *before* rebooting, or the reboot is what starts it. |
| `H-IMP-05` | Listening sockets against the as-received baseline | Matches | A bind shell is a listener that was not there yesterday, and the baseline is the only reliable record of yesterday. |

**Every one of these reports `unknown` rather than `pass` when its collector did not
run.** An implant check that passes because it saw nothing is worse than no check.

### What actually stops it

The checks above find an agent that is already there. Two controls stop it arriving, and
both belong to the generator rather than here:

- **Egress default-deny with logging.** Every step of that chain needs the box to reach
  the internet or the attacker's host — the `curl` to fetch the payload, and the shell
  to call home. A firewall that cannot open an outbound connection to an undeclared
  destination defeats the whole sequence at step one, and the log line names the box.
  This is the single highest-value control in the tool and it is one policy setting.
- **ICMP narrowed to the sources that need it** (`V-ICMP-EXPOSURE`). Availability is
  scored over ICMP, so echo is never blocked — but it only ever needs to arrive from
  the scoring sources and the management range. Echo reachable from the whole range is
  a wake-up signal available to everybody. `V-ICMP-EXTRA-TYPES` covers the rest:
  nothing scored needs timestamp, address-mask or redirect, and an accepted redirect
  lets somebody else steer traffic.

---

## 10. Exercise-specific caveats

Read before applying anything.

**Do not harden into a scoring outage.** Several checks can break a scored service. `isa-checks.yaml` is the authority on which ports are scored; `VERIFICATION.md` covers proving the ruleset still does what the policy said. Any check with `scoring_risk: high` is cross-referenced to the affected services and should be applied deliberately, not in a sweep.

**Some Green Team baseline configuration is load-bearing.** `CLAUDE.md` ground-truth item 4: the GT floating rules are non-quick and currently carrying traffic. Hardening that removes or reorders them will break things in ways that are hard to diagnose at speed.

**EXCON hosts live inside the workstation segment.** The scoring bot at `<ws_subnet>.254` and the NPC server at `.249` do not appear on the range diagram. Tightening the workstation segment kills scoring from the inside — a failure mode that looks exactly like good hardening right up until the points stop.

**Waivers are first-class.** A check waived with "breaks the FTP scoring target, accepted, reviewed 0900 day 2" is a better outcome than a check quietly ignored. Require the note; show waived checks on the dashboard; review them at handover.

## 11. Relationship to the rest of the package

| Document | Relationship |
|---|---|
| `MONITORING.md` | Same collected data, different evaluation. `M-*` is drift, `H-*` is posture. ID spaces do not overlap. |
| `SPEC.md` | The generator emits the management-access rules that `H-FW-01`/`H-FW-02` verify. The two halves close each other's loop. |
| `EVIDENCE.md` | `H-FW-02`, `H-FW-03`, `H-FW-06`, `H-FW-07` are the DCM26 findings restated as live checks. `H-PF-01` is a candidate new finding pending the anti-lockout review in §6. |
| `isa-checks.yaml` | Authority for `scoring_risk`. |
| `VERIFICATION.md` | How you prove hardening did not break what it was protecting. |

## 12. Open questions

| # | Question | Blocking | Who |
|---|---|---|---|
| **H-Q1** | Review the DCM26 end-state configs for anti-lockout state, correcting for the boolean inversion. If it was active estate-wide, this is a new `EVIDENCE.md` finding. | Not blocking; changes the pitch | Paul — data already held |
| **H-Q2** | Which FRR daemons are actually running on the routers, and are their VTY ports exposed? Determines whether `H-FRR-01` is theoretical or urgent. | Blocks `H-FRR-01` scoping | Inspect a router |
| **H-Q3** | Does pfSense preserve `from=`/`command=` options when it regenerates `authorized_keys` from `config.xml`? | Shared with `MONITORING.md` Q2 | Test on CE 2.8.1 |
| ~~**H-Q4**~~ | ~~Confirm the exercise permits disabling anti-lockout.~~ **CLOSED — it is permitted.** Green Team ship their own alias-based anti-lockout rule when the range is launched, so built-in anti-lockout is not the only thing keeping access open. See §6.1. | — | — |
| **H-Q5** | Is there a remote syslog target available to the Blue Team in-enclave? `H-SSH-20`, `H-FW-10` and `H-PF-09` all assume one. | Blocks the logging checks | Blue Team lead |

`H-Q4` is closed: disabling anti-lockout is permitted, which unblocks `H-PF-01` and the
whole management-restriction sequence in §4.

### 6.1 Green Team's own anti-lockout rule

**Reported from a previous exercise, and it changes the risk calculation.** Green Team
create their own anti-lockout rule, sourced from an alias, when they launch the range.
So built-in anti-lockout is not the only thing holding the door open — there is a
second, GT-owned rule doing the same job.

Two consequences:

- **Disabling built-in anti-lockout is less exposed than it looks**, because the GT
  rule remains. That does not remove the need to verify management access from a second
  session first; it means the failure mode is recoverable rather than terminal.
- **That rule and its alias are lockout-critical** and must be preserved. It is not in
  the documented protected set because it is created at launch rather than shipped in
  the baseline, so the tool meets it as an unrecognised item at triage and the operator
  must classify it as `remote_access` / `keep_verbatim` rather than dropping it.

Also reported: moving that rule to the **floating tab** so it applies across every
interface. That is the same shape this tool generates for `MGMT ACCESS` (`SPEC.md`
§7.1), for the same reason — a per-interface management rule has to be right on every
interface separately, and on an estate where one enclave inverts LAN that is a mistake
waiting to happen.

**Worth confirming on day one:** the alias name and its contents, so the profile can
recognise the rule on sight instead of surfacing it as unknown.
