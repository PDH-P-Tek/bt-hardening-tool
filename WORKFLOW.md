# Operator Workflow

What a Blue Team operator actually does, in order, from receiving the documents to applying a ruleset. Written to be followed by someone who has had the range documents for one day and has not used pfSense in anger.

Timings are for the first firewall. The second is faster.

---

## What you have, and when

| | |
|---|---|
| **Day −1** | Blue Team handbook, range diagram, one Technical Annex per enclave |
| **Day 0** | Range opens. Firewall access, ISA board, live estate |

Everything in Phase 1 below runs off the documents alone. **Do it the night before.** By the time the range opens you should be confirming, not authoring.

---

# Phase 1 — Off-range, from the documents

## Step 1 · Estate setup · 2 min, once

Enter your team number. Every `X` / `XX` token in the templates resolves from it.

Add the enclaves you are responsible for. For each, you should have a Technical Annex.

## Step 2 · Firewall wizard · ~20 min per enclave

Run once per firewall. The wizard walks the firewall the way you would.

### 2.1 — How many interfaces besides WAN?

From the annex §1.2 subnet table. DO has 3. DS has 4. MCU has 5.

### 2.2 — Name and address each one

| Field | Where it comes from |
|---|---|
| Segment name | §1.2 "Name of Subnet" |
| Role | picked from `wan, ws, svrs, dmz, uav, scada, power, sat, port1, port2, stbd1, stbd2` |
| IPv4 | §1.2 |
| IPv6 | §1.2 — **do not skip this, IPv6 availability is scored** |

> **Shortcut:** select the §1.2 table in the PDF, copy, and use **Paste table**. The wizard parses it and shows the result back for confirmation. If the paste mis-parses, type it — four rows is not a hardship.

### 2.3 — What runs on each interface?

Per segment, add the hosts from annex §2.5. Each host gets a role, auto-suggested from its hostname (`dc01` → domain controller, `ws2*` → Windows workstation).

> **Shortcut:** paste the whole §2.5 Known Device List. The wizard assigns hosts to segments by subnet, matches roles by hostname pattern, and carries the IPv6 addresses across — which is the part nobody types by hand.

**Watch for hosts marked Out of Bounds.** Annex A DO lists `scoringbot` (`25.XX.9.254`) and `npc-server-do` (`25.XX.9.249`), both inside the workstation subnet. The wizard flags them as protected. Do not remove the flag.

Not every annex lists them — Annex G BANK does not. Absence does not mean absence from the network.

### 2.4 — Connectivity requirements

Annex §2.6 presented as a checklist, each item pre-ticked and expandable to show the rules it will generate.

You are confirming Green Team's stated baseline, not authoring policy. Untick only what genuinely does not apply.

Note the variation between enclaves — DO sends DNS to the domain controllers, BANK sends it to the DMZ proxy. Read your own annex; don't assume.

### 2.5 — Egress posture

Per segment: permit, or deny-and-log. Deny-and-log is the better defensive posture and what you want for beacon detection.

The mandatory allows are inserted above the deny automatically. **This is the step where teams historically break things** — a bare egress deny severs Elastic Agent from Fleet, kills the NPC server's scored outbound path, and fails any Graynet Access check.

## Step 3 · Service ports · ~10 min per enclave

The annexes give no port numbers. Three tiers:

- **Known** — domain controller, mail, file server, RDP, SSH. Pre-filled from `service-catalogue.yaml`, confirm and move on.
- **Assumed** — proxy (3128? 8080?), FTP (21 plus a passive range). Shown in amber. Confirm on day 0 if you can.
- **Unverified** — `apj`, `modgpt`, anything bespoke. Left as allow-all, labelled `BTHT | UNVERIFIED`, and reported on every export until closed.

Allow-all on an unknown service is the right day-one call. Leaving it there on day three is not — which is why it stays visible.

---

# Phase 2 — Day 0, on the range

## Step 4 · Read the ISA board · 15 min, highest value of the day

Open **ISA → Situational Awareness → Target Checks Status**, filter to your team.

Each card is one target and lists the checks that run against it. **Those check names are the definitive scored port list.** Everything checked must stay reachable; everything else is yours to close.

In the wizard, tick the checks against each host. Defaults are pre-loaded from `isa-checks.yaml` — a domain controller offers HOST, AD DS Web, DNS, Kerberos ×2, LDAP, LDAP GC, NetBIOS, RDP, RPC, SMB. Confirm against what the board actually shows.

Three things to look for specifically:

- **Your firewalls are scored targets.** HOST, SSH, HTTPS, and possibly Graynet Access. Any management lockdown must let the scoring source reach 22 and 443 on the firewall itself.
- **`Graynet Access` and `Agents Status` are egress checks.** No ingress rule satisfies them. They constrain your egress policy.
- **Anything with no checks** is unscored — the place where hardening is cheapest.

This step is what turns "we think these ports matter" into a list. Fifteen minutes here saves hours of guessing and prevents the expensive mistake of permitting SMB from `any` to satisfy one check.

## Step 5 · Export the firewall configs · 2 min each

**Diagnostics → Backup & Restore → Backup.**

Use the **Backup area** dropdown to export three sections separately:

- `Aliases`
- `Firewall Rules`
- `Interfaces`

Three small files per firewall, and **no credential material leaves the box** — no password hashes, no private key, no service passwords.

A full export works too and the tool strips it on upload, but then you are carrying secrets on team kit for no benefit.

## Step 6 · Ingest and triage · 5 min per firewall

Upload the exports. The tool classifies the pre-existing rules against the shipped profile.

- **Everything recognised** → one line and a Continue button.
- **Something changed** → a short list with the delta stated in words. Confirm or override.
- **Something new** → unclassified, needs a decision before you can continue.

Cross-checks run here. Annex versus config disagreement means something moved between documentation and build — worth knowing before you write rules against it.

## Step 7 · Generate and review · 10 min per firewall

Generation is automatic. **The diff is the gate.**

Three columns — kept, removed, added. Validator findings sit inline against the rules that caused them.

Blocking findings must be cleared. Warnings must be acknowledged individually. The ones that matter most, from what happened last time:

| Finding | What it means |
|---|---|
| `V-PERMISSIVE-RETAINED` | An `any → any` catch-all survived. Every enclave in DCM26 finished with these live. |
| `V-DUALSTACK-ASYMMETRY` | A rule covers IPv4 but not IPv6, above an `inet46` catch-all. Your hardening does not apply to v6. |
| `V-SCORING-ABSENT` | No rule permits the scoring source. Points start draining. |
| `V-EGRESS-CHECK` | Egress policy would fail a Graynet Access or Agents Status check. |
| `V-NAT-MODE-CHANGED` | NAT mode differs from the baseline. On a routed range you almost certainly do not want this. |

## Step 8 · Apply · 5 min per firewall

**Before anything else: Diagnostics → Backup & Restore → Backup, full config, save it.** Config History on the same page also gives you a revert.

Then restore the two generated sections — aliases first, then firewall rules.

**Section restore replaces, it does not merge.** The generated file is the complete intended state for that section. That is deliberate.

## Step 9 · Verify · 10 min per firewall

Run the generated verification manifest and confirm the ruleset does what the policy said. See `VERIFICATION.md`.

Then watch ISA. Checks should stay green. Anything that goes red within a few minutes of applying is yours.

---

# Phase 3 — During the exercise

**Re-ingest before each change.** Anything a teammate altered directly on the box appears in triage as new or changed, rather than being silently overwritten by your next export.

**Save a policy file per phase.** `phase1-baseline.yaml`, `phase2-post-incident.yaml`. They diff, they hand over between shifts, and they are most of the post-exercise write-up already written.

**Close the unverified services.** Once you have watched real traffic (Diagnostics → States, and the firewall log, which names the matching rule) you will know what `apj` and `modgpt` actually use. Tighten and regenerate.

**Add IOCs to the block list.** The `BLOCKED_IPs` alias is pre-wired and empty. A confirmed Red address goes in it and takes effect at the top of the floating tab.

---

## Time budget

| Phase | Per enclave | Four enclaves |
|---|---|---|
| Wizard + services (off-range, day −1) | 30 min | 2 hrs |
| ISA board (day 0) | — | 15 min |
| Export, ingest, triage | 7 min | 30 min |
| Generate, review, apply, verify | 25 min | 1 hr 40 |

Roughly an evening beforehand and two hours on the morning of day 0, for an estate-wide ruleset that is reviewed, validated and reproducible.

---

## If something breaks

1. **Config History** — Diagnostics → Backup & Restore → Config History. Revert to the previous configuration. Faster than debugging under pressure.
2. **The firewall log names the rule.** `<filterdescriptions>` is on, so Status → System Logs → Firewall tells you which rule matched. Generated rules carry descriptions of the form `BTHT | BLOCK | intent`.
3. **`pfctl -sr` is ground truth.** The generated ruleset in real evaluation order; `pfctl -vsr` adds per-rule counters. The GUI will not show you where your rule actually sits relative to the floating tab.
4. **Locked out?** Built-in anti-lockout is still enabled and binds to the `lan` interface — but remember `dsoc` inverts that, so on the SOC firewall it protects servers, not workstations. Console access via VLM-Up is the fallback. Note that reverting a VM to snapshot deducts points; reverting a firewall *config* does not.
