# DCM26 End-State Evidence

Analysis of seven Blue Team firewall configurations captured at and near the end of DCM26, one team, plus the pre-build baselines.

This document has two jobs. It is **the business case** — every finding below is something a validator catches in seconds and a competent team under time pressure did not. And it is **the test set** — each finding maps to a validator ID, and each should become a golden test case built from a sanitised fixture.

Nothing here reflects on the teams involved. These are the failure modes the environment produces, which is exactly why a tool should carry them rather than people.

---

## Configurations analysed

| Enclave | Captured | Interfaces | Aliases | Rules |
|---|---|---|---|---|
| `do` baseline | 09 Feb 02:34 | 4 | 2 | 10 |
| `ds` baseline | 09 Feb 02:33 | 5 | 2 | 11 |
| `dsoc` baseline | 09 Feb 02:34 | 3 | 2 | 9 |
| `do` post-compromise | 09 Feb 08:34 | 4 | 10 | 20 |
| `do` end-state | 12 Feb 08:26 | 4 | 12 | 30 |
| `ds` end-state | 12 Feb 08:26 | 5 | 5 | 18 |
| `gov` end-state | 12 Feb 08:27 | 5 | 14 | 21 |
| `mil` end-state | 12 Feb 08:27 | 6 | 7 | 24 |
| `mcu` end-state | 12 Feb 08:26 | 6 | 11 | 31 |
| `bank` end-state | 11 Feb 04:47 | 4 | 23 | 48 |

---

## E1 — Every enclave finished with live `any → any` catch-alls · `V-PERMISSIVE-RETAINED`

Checked programmatically across all end-state configs for enabled `pass`, protocol any, source any, destination any, no ports:

| Enclave | Interfaces still carrying a live catch-all |
|---|---|
| `do` | WAN ×2, ws, svrs, dmz |
| `ds` | WAN, ws, svrs, uav, dmz |
| `gov` | WAN, ws, svrs, scada, dmz |
| `mil` | WAN ×2, ws, svrs, sat, dmz, power |
| `mcu` | WAN ×2, dmz, port1, port2, stbd1, stbd2 |
| `bank` | ws, svrs, dmz |

**Bank was the only enclave to close the WAN catch-all**, and still left all three internal segments wide open.

On `do`, rules 9–16 do careful work — management lockdown, scoring bot allow, service permits — and then rule 17 passes everything anyway. Thirty rules of effort above an open door.

`V-PERMISSIVE-RETAINED` is a fifteen-line check. It would have fired on all six enclaves, on day one.

## E2 — IPv4 hardened, IPv6 wide open · `V-DUALSTACK-ASYMMETRY`

Crafted rules were written `inet` (IPv4 only) while the catch-alls beneath them were `inet46`. IPv6 traffic therefore bypasses the entire ruleset and lands on allow-any.

| Enclave | v4-only crafted rules | `inet46` catch-alls beneath |
|---|---|---|
| `bank` | **31** | 3 |
| `mcu` | 13 | 7 |
| `do` | 12 | 5 |
| `do` post-compromise | 9 | 4 |
| `mil` | 5 | 7 |
| `gov` | 4 | 5 |

Bank did the best work in the estate by a distance — network aliases, per-service port aliases, explicit blocks, WAN closed. **All 31 of those rules applied to IPv4 only.**

Two consequences, both bad: IPv6 was an unfiltered path for Red, and IPv6 service availability was unmanaged despite BT technical rule 3 making it scored. Nothing in the pfSense GUI signals this — the rules look right, and the family column is easy to skim past.

This moves `V-DUALSTACK-ASYMMETRY` from warning to blocking when the asymmetric rule sits above an `inet46` catch-all.

## E3 — Rules labelled BLOCK with action `pass` · `V-LABEL-ACTION-MISMATCH`

Three in `bank` alone:

| # | Description | Actual action |
|---|---|---|
| 33 | `BLOCK WAN → SERVERS` | **pass** |
| 34 | `BLOCK WAN → FW GUI` | **pass** |
| 47 | `BLOCK DMZ → WS` | **pass** |

All three were disabled, so no harm done. But the label is what anyone reviewing the ruleset reads, and all three would have done the exact opposite of their stated intent if enabled.

The strongest available argument for generating rules from declared intent rather than hand-building them — and for putting the *action* prominently in the diff view rather than relying on the description.

## E4 — A port alias named `Temp`, open from any on WAN · `V-ALIAS-NAME-HYGIENE`

`bank` alias `Temp` = ports 22, 3389, 443, 80, **3306**, permitted from `any` on the WAN interface (rule 12, `inet46`).

MySQL exposed to the greynet-equivalent for the duration of the exercise, behind a name that announces it was never meant to survive. Temporary rules outlive the emergency that created them.

## E5 — The FTP port forward did nothing · `V-NAT-MODE-CHANGED`

`do` end-state carries three NAT port forwards and outbound NAT switched from `disabled` to `hybrid`:

```
wan tcp source-port 21 → 25.14.11.22:21     "WAN -> ftp 21"
wan tcp any            → 25.14.11.53:3128   "WAN -> proxy 3128"
wan tcp any            → 25.14.10.25:443    "WAN -> OWA 443"   [disabled]
```

Three problems:

1. **Source port 21 is wrong.** A client connects *from* an ephemeral port *to* 21. That forward would almost never match.
2. **No port forward was needed.** The baseline runs `<nat><outbound><mode>disabled</mode>` — pure routed. The range routers already deliver traffic to `25.14.11.22` directly.
3. **It appeared to work** because rule 17, the WAN catch-all, was passing the traffic regardless.

The team reasonably concluded "opening port 21 worked". It did not; the open door did. This is the precise shape of false confidence the tool exists to prevent — and it only becomes visible when someone diffs intent against effect.

Switching outbound NAT to `hybrid` on a routed range is also a live risk: it can rewrite source addresses on paths the scoring probes and usersims depend on.

**Consequence for the spec: NAT is no longer out of scope.** The tool must ingest, classify and preserve `<nat>`, and treat a mode change from the baseline as blocking until justified.

## E6 — `BLOCK_ALL_FW_EGRESS` versus the Graynet Access check

`do` and `mcu` both carry a floating quick block:

```
block  FLOAT  quick  inet46  tcp  (self) → any    "BLOCK_ALL_FW_EGRESS"
```

The ISA board shows `fw1.mil` scored on HOST, SSH, HTTPS **and "Graynet Access"** — a check that the firewall itself can reach the greynet. If the same check exists on the deployed firewalls, that rule attacks the team's own score directly.

It also sits *above* the non-quick floating DNS/NTP passes, so it is a live instance of the shadowing pattern in `BASELINE-ANALYSIS.md` F3. Being TCP-only it spares UDP DNS and NTP by luck rather than design.

Validators: `V-EGRESS-CHECK`, `V-SHADOW-FLOATING`.

## E7 — Descriptions drifted from behaviour · confirms fingerprint design

`do` end-state rule 16 reads `pass any → any` on WAN with the description **"Firewall outbound traffic"**. The baseline rule of that name is `pass (self) → any`. Someone widened the source and left the label.

Separately, the three preserved GT floating rules had logging enabled — a real modification to the protected set.

Both are exactly why `SPEC.md` forbids descriptions as identity. The first would pass a description-based match while meaning something entirely different; the second would fail an exact match while being semantically the same rule. The two-tier fingerprint handles both: E7's rule 16 fails strict *and* structural matching on the source endpoint and surfaces for a decision; the logging change matches structurally and prompts with the delta stated.

## E8 — Shadowed and redundant rules · `V-SHADOWED-RULE`

`do` end-state, workstation interface:

```
21  pass  tcp/udp  any → opt2        "WS -> DMZ allow"
22  pass  tcp/udp  any → any         "DS_SVRS net"        ← swallows everything below
23  pass  any      any → any
24  pass  tcp/udp  lanip → opt1ip:53 "WS -> DC DNS"       ← unreachable
25  pass  tcp/udp  any → any         "WS -> any allow"    ← unreachable
```

Rule 22 is `tcp/udp any → any` and quick, so rules 24 and 25 never evaluate. Rule 23 makes the rest moot. Five rules, one of which does anything.

## E9 — Scoring topology, recovered the hard way

The teams worked out the scoring sources during the exercise and encoded them:

| Enclave | Alias | Value |
|---|---|---|
| `do` | `Scoring_Bot` | `25.14.9.254` |
| `mcu` | `Scoring_Bot` | `10.181.2.214` |
| `bank` | `MONITOR_HOSTS` | `10.14.1.254`, `10.181.2.214` |

Bank's rules are annotated "ISA checks" against specific host/port pairs — someone read the ISA board and worked backwards. That is the right method, and it is now `isa-checks.yaml` so nobody has to rediscover it under fire.

The `10.14.1.254` entry initially looked like a copy-paste error, since bank's own workstation subnet is `10.14.17.0/24`. It is not: **Annex G §2.6 states "Scoringbot in Host Nation Government (GOV) must be able to communicate with all DNMP systems for availability scoring purposes."** Deployed enclaves host a local bot; Host Nation enclaves are served from GOV.

## E10 — AD ports exposed from `any` on the WAN

`bank` WAN rules 4–11 permit SMB, RPC, NetBIOS, LDAP, LDAP GC, AD Web Services and Kerberos from **any** source, IPv4, on the WAN interface.

The intent was almost certainly to satisfy the eleven ISA checks on `dc01`/`dc02`. The correct rule is those ports from the **scoring source** to the **DC hosts**, which is what the tool generates from the ISA check set. Permitting SMB and NetBIOS from anywhere to satisfy an availability check is a very expensive way to score a point.

`bank` rule 15 has the same shape at smaller scale: described as "monitor → WS 22 (ISA checks)" with source `any`.

Also `bank` rule 17 specifies protocol `igmp` for a check described as ICMP. IGMP is not ICMP; that rule does nothing.

---

## Patterns worth keeping

Two things the teams built independently are good and should ship as templates:

**`FW_Management` port alias (22, 443)** with allow-from-`Remote_Access`, allow-from-`Scoring_Bot`, then quick-block-everything-else. This is the management rule `SPEC.md` specifies, arrived at independently under pressure. Adopt their naming.

**`BLOCKED_IPs` host alias with a floating block at the top.** The post-compromise `do` config carries `103.63.27.91`. A pre-wired, empty-on-day-one IOC block list is worth having as a first-class feature.

---

## Validator test set

Every finding becomes a golden test built from a **sanitised** fixture — no real range configuration in the repository.

| Finding | Validator | Severity |
|---|---|---|
| E1 | `V-PERMISSIVE-RETAINED` | blocking |
| E2 | `V-DUALSTACK-ASYMMETRY` | blocking when above an `inet46` catch-all |
| E3 | `V-LABEL-ACTION-MISMATCH` | warning |
| E4 | `V-ALIAS-NAME-HYGIENE` | warning |
| E5 | `V-NAT-MODE-CHANGED` | blocking |
| E6 | `V-EGRESS-CHECK`, `V-SHADOW-FLOATING` | blocking / warning |
| E7 | two-tier fingerprint behaviour | test, not validator |
| E8 | `V-SHADOWED-RULE` | warning |
| E9 | `V-SCORING-ABSENT` | blocking |
| E10 | `V-OVERBROAD-SCORING-SOURCE` | warning |
