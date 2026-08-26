# BT Hardening Tool — Technical Specification

Version 0.2 (design) · 21 Aug 26 · Status: pre-build

Changes from 0.1: wizard-first interaction model; annex and ISA import; NAT in scope; full role vocabulary; validator catalogue expanded from evidence.

---

## 1. Purpose

A self-hosted tool that turns range documentation into a correct, correctly-ordered pfSense ruleset, while guaranteeing Green Team's pre-loaded configuration survives intact.

It is not a firewall manager. It is a **generator with a conscience**: it produces a complete intended state, refuses to produce a dangerous one, and shows exactly what changed before anything is applied.

`EVIDENCE.md` documents what happens without it. Every enclave in DCM26 finished with `pass any → any` live on every internal segment; every enclave had IPv4-only rules above `inet46` catch-alls, so IPv6 bypassed the entire ruleset.

### Non-goals

- Live connection to a pfSense box. No API, no SSH, no push. The tool produces files; a human applies them.
- Replacing Green Team build tooling. Built from Blue Team Information Book content only.
- Anything outside `<aliases>`, `<filter>` and `<nat>`.

## 2. Users and operating context

Blue Team network defenders. Assume:

- pfSense GUI admin access only. No Ansible, no API, no shell tooling on the range.
- Competent, but new to *these* firewalls, working against a clock, with scoring consequences.
- **Documents arrive the day before the range opens.** Phase 1 of `WORKFLOW.md` runs entirely off them, so the tool must be fully usable with no range access.
- Runs off-range on team kit. Fully offline — no outbound network calls of any kind, ever.

## 3. Architecture

Python 3.11+ · FastAPI · Jinja2 · server-rendered HTML with light vanilla JS (HTMX acceptable if vendored). Single container, no external services.

```
        ┌──── annex paste ────┐
        ├──── ISA checks  ────┤
        ├──── wizard input ───┤──► estate policy (YAML) ──► generate ──► validate ──► diff ──► export
        └──── config ingest ──┘            ▲                                                    │
                     │                     │                                                    ▼
                     └──► triage ──► profile                                          verification manifest
```

Generation is a pure function of `(baseline, policy, profile)`. Same inputs, byte-identical output. This is a test, not an aspiration.

### Repository layout

```
btht/
  app/
    main.py
    ingest/
      pfsense.py          config XML → domain objects (aliases, filter, nat + a fixed fact list)
      annex.py            §1.2 / §2.5 paste-parse
      isa.py              ISA check-set assignment
      nmap.py             verification result import
      normalise.py        canonicalisation (§5.2)
      fingerprint.py      strict + structural hashing (§5.3)
    model/
      estate.py           Estate, Firewall, Interface, Host
      rules.py            Rule, Alias, NatRule, Role, Disposition
      policy.py           estate policy schema + loader
      profile.py          classification profile
    generate/
      order.py            deterministic ordering (§7)
      emit.py             domain objects → pfSense XML fragments
      manifest.py         verification manifest
      templates/          filter.xml.j2, aliases.xml.j2, nat.xml.j2, checklist.md.j2
    validate/
      rules.py            validator catalogue (§8), each a pure function
    web/
      routes.py
      templates/          wizard/*.html, triage.html, diff.html, export.html
    data/
      seed-profile.yaml
      isa-checks.yaml
      service-catalogue.yaml
      templates/          per-enclave starters
  data/estates/           per-team policy files (gitignored)
  tests/
    fixtures/             SANITISED only — see §10.1
    golden/
```

---

## 4. Data model

```python
Estate:
    team: int; team_padded: str
    firewalls: list[Firewall]
    profile: Profile
    shared_aliases: list[Alias]
    dependencies: list[CrossEnclaveDep]

Firewall:
    enclave: str                  # do | ds | dsoc | mcu | gov | mil | bank | hndc
    fqdn: str
    estate_side: str              # "deployed" | "host_nation"  — MCU straddles, see §4.2
    config_version: str           # must be 23.3
    interfaces: list[Interface]
    hosts: list[Host]
    aliases: list[Alias]
    rules: list[Rule]
    nat: NatConfig
    baseline_sha256: str

Interface:
    ifname: str                   # emission target: wan | lan | opt1 …
    role: str                     # matching token: wan | ws | svrs | dmz | uav |
                                  #   scada | power | sat | port1 | port2 | stbd1 | stbd2
    descr: str; nic: str
    v4: IPv4Interface; v6: IPv6Interface
    is_lan: bool                  # anti-lockout binds here

Host:
    hostname: str
    v4: IPv4Address; v6: IPv6Address
    segment_role: str
    service_role: str             # from service-catalogue hostname_patterns
    isa_checks: list[str]         # from isa-checks.yaml — drives SCORING rules + manifest
    out_of_bounds: bool           # EXCON. protected, never blocked, never a policy target
    source_of_truth: str          # "annex" | "wizard" | "nmap"

NatConfig:
    outbound_mode: str            # baseline is "disabled"
    port_forwards: list[NatRule]
```

`Endpoint` is a tagged union: `Any` · `Self` · `Network(cidr)` · `Host(addr)` · `AliasRef(name)` · `InterfaceNet(role)` · `Not(Endpoint)`.

### 4.1 Interface roles

Fingerprints and policy must never embed `lan` / `opt1` — `dsoc` maps `lan` to servers while every other enclave maps it to workstations. Derive a role token:

```
if ifname == "wan":  role = "wan"
else:
    d = descr.lower()
    strip a leading enclave token (longest-first): bt_wan_, hn_wan_, dsoc_, do_, ds_, mcu_, gov_, mil_, bank_
    role = remainder
    if remainder not in vocabulary: role = "other:" + d   # surfaces in triage, never guessed
```

Vocabulary: `wan, ws, svrs, dmz, uav, scada, power, sat, port1, port2, stbd1, stbd2`. Configurable, not hardcoded.

Emission always uses `ifname`; matching always uses `role`.

### 4.2 Estate side

`mcu` has its WAN on the Host Nation side (`10.XX.80.16`) and internal segments in deployed space (`25.XX.26–30`). Derive `estate_side` from the WAN interface's address, never from the internal ranges, and never assume `25.x` implies deployed.

This matters because the scoring source differs: deployed enclaves host a local bot at `<ws_subnet>.254`; Host Nation enclaves are served from GOV. See `isa-checks.yaml`.

### 4.3 Classification

Two orthogonal attributes plus a flag.

**Role** — drives validators: `remote_access` · `routing` · `essential_services` · `management` · `scoring` · `out_of_bounds` · `permissive_default` · `enclave_policy` · `threat_block` · `unknown` (blocks export).

**Disposition** — drives output: `keep_verbatim` · `keep_edit` · `replace_generated` · `drop`.

**`lockout_critical: bool`** — separate flag. Cannot be dropped without typed confirmation. Set on the `Remote_Access` alias, its WAN rule, and any management rule.

---

## 5. Input paths

Four, all optional except the wizard, all cross-validating.

### 5.1 Wizard — primary

Walks each firewall interface by interface. Full operator sequence in `WORKFLOW.md` §2. Every step that can be filled from the annex offers a paste shortcut; every step is completable by typing.

The wizard is the spine because it works with no range access, tolerates annex format changes, and is teachable. Paste-parse is an accelerator inside it, never an alternative to it.

### 5.2 Annex paste-parse

Two tables, pasted as text. **Not PDF parsing** — too brittle across revisions, and a mis-parse is invisible.

**§1.2 Subnets** → `Name | IPv4 | IPv6 | Domain`. Four columns, one row per segment.

**§2.5 Known Device List** → `Hostname | IP Address | Description`. The IP cell contains both families, usually on separate lines, and the fw1 row contains several labelled pairs.

Grammar rules:

- Tolerate heading variance — Annex A says "Known devices", Annex G says "Known Device List".
- Resolve `XX` / `X` tokens against the team number.
- Assign hosts to segments by subnet containment, not by hostname.
- Match `service_role` via `service-catalogue.yaml` `hostname_patterns`.
- Detect Out-of-Bounds markers in the description column and set `out_of_bounds`.
- **Render the parse back for confirmation before accepting.** Silent mis-parse is the failure mode to design against.

**Nothing about the annex may be hardcoded.** DNS destination, scoring source and EXCON host presence all vary between enclaves — see `BASELINE-ANALYSIS.md` §4.

### 5.3 ISA check assignment

Per host, tick which ISA checks apply. Defaults pre-loaded per `service_role` from `isa-checks.yaml`; the operator confirms against the live board.

This is the authoritative port source. `service-catalogue.yaml` covers what a service additionally needs to *function* (the DC RPC dynamic range is the standing example — needed, never checked).

Checks with `proto: egress` (`Graynet Access`, `Agents Status`) cannot be satisfied by ingress rules and constrain egress policy instead. They drive `V-EGRESS-CHECK`.

### 5.4 Config ingest

Read `<aliases>`, `<filter>` and `<nat>`. Everything else is read **only** for this fixed fact list and retained no further:

`<interfaces>` · `<version>` · `<system><webgui><noantilockout>` · `<syslog><filterdescriptions>` · `<installedpackages>` FRR BFD peers and OSPF router-ids.

Never read, store or emit password hashes, keys, certificates or service passwords.

**Boolean rule: empty element = `False`, `yes` = `True`.**

Accepts either a full config export or the three partial section exports (`Aliases`, `Firewall Rules`, `Interfaces`) that `WORKFLOW.md` §5 recommends. Partial exports are preferred: no credential material leaves the box.

---

## 6. Identity, normalisation and triage

### 6.1 Normalisation

Applied before fingerprinting. A brittle fingerprint fires the triage modal constantly, people click through it blind, and the tool becomes worse than nothing.

| Input | Canonical |
|---|---|
| `<any/>`, `0.0.0.0/0`, `::/0` | `Any` |
| `(self)` | `Self` |
| missing `<protocol>` | `None` (any) |
| `53`, `53-53` | `PortSpec(53,53)` |
| `inet46` | equal to the `{inet, inet6}` pair of otherwise-identical rules |
| alias reference | `AliasRef(name)` **and** resolved entry set — both compared, see §6.2 |
| IPv6 literals | lowercase, RFC 5952 |
| address lists | sorted, deduplicated |
| team number | templated to `{X}` / `{XX}` before hashing |
| `<descr>`, `<id>`, `<tracker>`, `<detail>`, `<log>` | **excluded from the fingerprint** |

### 6.2 Two-tier fingerprint

**Strict** — SHA-256 over canonical JSON of `type, floating, quick, direction, sorted(interface_roles), ipprotocol, protocol, sorted(icmptype), source, destination, srcport, dstport, statetype`. Exact match applies the stored classification silently, no prompt.

**Structural** — same, with each `Endpoint` reduced to its kind and alias contents ignored. Structural-only match prompts with the delta stated in words:

> This matches your **Remote_Access** rule except the Blue Team entry is now `198.19.15.0/24` where the profile expected `198.19.14.0/24`. Same role?

Both tiers are validated by real cases in `EVIDENCE.md` E7 — a baseline rule whose source was widened while keeping its description (fails both tiers, correctly surfaces), and the preserved floating rules with logging added (matches structurally, prompts with the delta).

No match at either tier → new, role defaults to `unknown`.

### 6.3 Triage modal

An **exception queue**, not a list of everything. Strict matches are applied silently and reported as a count.

States: `clean` (all strict) · `review` (≥1 structural, accept-all available) · `unknown` (≥1 no-match, no accept-all) · `conflict` (referential integrity broken, blocking).

Each row shows, in priority order: plain-English summary, role dropdown, disposition dropdown, lockout-critical toggle, match-tier badge, alias reference count, raw fields collapsed.

The plain-English summary is the primary control surface — under time pressure people classify from that sentence alone. Budget real effort on the wording.

Dropping a `lockout_critical` item requires typing its name. Not a checkbox; checkboxes get clicked reflexively.

Wireframe: `wireframes/triage-modal.html`.

### 6.4 Cross-validation

Where two sources describe the same fact, disagreement is a finding, not something to silently reconcile:

| Sources | Validator |
|---|---|
| annex §1.2 subnets vs config `<interfaces>` | `V-ANNEX-CONFIG-MISMATCH` |
| annex §2.5 hosts vs nmap discovery | `V-UNEXPECTED-HOST` |
| ISA checks vs generated allow rules | `V-SCORING-UNCOVERED` |
| config FRR peers vs `routing`-role rules | `V-ROUTING-PEERS` |

### 6.5 Audit record

Every classification stamped: fingerprint, role, disposition, operator, timestamp, baseline SHA-256, match tier, suggestion accepted or overridden. Exported with the policy.

---

## 7. Generation

### 7.1 The ordering contract

**Generated output must be correct without depending on non-quick evaluation semantics.** Every intended pass is an explicit quick rule. Preserved GT floating rules remain underneath as a backstop but are never load-bearing.

**Floating tab**, in order:

| Pos | Block | Quick | Notes |
|---|---|---|---|
| 1 | `THREAT BLOCK` | ✓ | `BLOCKED_IPs` alias, empty on day one. Pattern taken from DCM26 practice. |
| 2 | `MGMT ACCESS` | ✓ | `Mgmt_Sources` → This Firewall, tcp 443+22, direction in, all internal interfaces. Uniform across enclaves regardless of which interface is `lan`. |
| 3 | `SCORING` | ✓ | Scoring source → the exact host:port set from the ISA check assignment. **Includes the firewall itself** — it is a scored target (`BASELINE-ANALYSIS.md` F9). |
| 4 | `OUT OF BOUNDS` | ✓ | EXCON host ingress and egress preserved: `scoringbot`, `npc-server-*`. |
| 5 | `ESSENTIAL SERVICES` | ✓ | DNS to the enclave's declared DNS destination, NTP to its local time server, ICMP/ICMPv6 minimum type set. Scoped to known destinations — tighter than GT's `any → any`, never narrower than needed. |
| 6+ | preserved GT floating rules | ✗ | verbatim, original order |

**Per internal interface**: policy rules in declared order, then `BLOCK ALL` + log.

**WAN**: preserved GT rules 4–6 verbatim, then policy ingress, then `BLOCK ALL` + log. The GT `any → any` is dropped by default.

A `<separator>` precedes each named block. Every generated rule carries a description of the form `BTHT | <BLOCK> | <intent>` — with `<filterdescriptions>` on, that string appears in the firewall log against every match, which is how the team debugs at speed.

Emit a `<tracker>` on every generated rule, derived deterministically from its fingerprint so output stays reproducible.

### 7.2 Dual-stack

Every generated rule is `inet46` where endpoints permit. Where an alias holds one family only, emit the paired rule and flag `V-DUALSTACK-ASYMMETRY`.

**Never emit a v4-only rule silently.** `EVIDENCE.md` E2: every DCM26 enclave had IPv4-only rules above `inet46` catch-alls, so all their hardening was bypassed on IPv6.

### 7.3 NAT

The baseline is `outbound_mode: disabled` with no port forwards — pure routed. The tool preserves whatever it ingests and treats a mode change as blocking (`V-NAT-MODE-CHANGED`).

It does **not** generate port forwards. On a routed range they are unnecessary; `EVIDENCE.md` E5 documents a team adding malformed ones that appeared to work only because a catch-all was passing the traffic.

### 7.4 Identity binding

Output carries `enclave`, `fqdn`, `baseline_sha256` and the role→ifname map. Import into a firewall whose identity does not match is **refused**, not warned. Applying a `do` ruleset to `dsoc` would be actively destructive given the LAN inversion.

---

## 8. Validator catalogue

Pure functions, stable IDs, one golden test each asserting both that it fires on its case and stays silent on a clean baseline.

### Blocking

| ID | Check | Evidence |
|---|---|---|
| `V-UNKNOWN-UNRESOLVED` | An item is still `unknown` | |
| `V-LOCKOUT-DROP` | `lockout_critical` dropped without typed confirmation | |
| `V-ALIAS-MISSING` | Rule references an alias absent from output | |
| `V-ALIAS-ORPHAN-DROP` | Alias dropped while referenced | |
| `V-MGMT-ABSENT` | No management rule reaching every internal segment | |
| `V-DENY-WITHOUT-ESSENTIAL` | Block emitted with no essential-services pass ahead of it | |
| `V-IF-MISMATCH` | Output identity ≠ target identity | |
| `V-CONFIG-VERSION` | Baseline is not config format `23.3` | |
| `V-PERMISSIVE-RETAINED` | An `any → any` catch-all survives into output | **E1** |
| `V-DUALSTACK-ASYMMETRY` | v4-only rule above an `inet46` catch-all | **E2** |
| `V-NAT-MODE-CHANGED` | NAT mode differs from baseline | **E5** |
| `V-SCORING-ABSENT` | No rule carries role `scoring` | **E9** |
| `V-EGRESS-CHECK` | Egress posture would fail a `Graynet Access` or `Agents Status` check | **E6**, F9 |
| `V-OOB-BLOCKED` | An Out-of-Bounds EXCON host's path is blocked | F8 |

### Warning — acknowledgement required

| ID | Check | Evidence |
|---|---|---|
| `V-ALIAS-FAMILY` | Alias IPv6 entries inconsistent with the firewall's own addressing | F1 |
| `V-ROUTING-PEERS` | An FRR BFD/OSPF peer is not covered by a `routing` rule | F1 |
| `V-SHADOW-FLOATING` | A quick block shadows a preserved non-quick floating pass | F3, **E6** |
| `V-SHADOWED-RULE` | Rule unreachable behind an earlier quick rule | **E8** |
| `V-LABEL-ACTION-MISMATCH` | Description says block/deny, action is `pass` (or vice versa) | **E3** |
| `V-ALIAS-NAME-HYGIENE` | Alias name contains `temp`/`tmp`/`test`/`todo`/`xxx` | **E4** |
| `V-OVERBROAD-SCORING-SOURCE` | A scoring rule uses source `any` instead of the scoring source | **E10** |
| `V-ICMP6-MINIMUM` | ICMPv6 types 2, 128, 129, 133–136 not all passed | F5 |
| `V-UNVERIFIED-SERVICE` | A service is permitted allow-all pending port discovery | |
| `V-ANTILOCKOUT-DISABLED` | Output disables built-in anti-lockout | |
| `V-ANNEX-CONFIG-MISMATCH` | Annex subnets disagree with config interfaces | |
| `V-SCORING-UNCOVERED` | An ISA check has no corresponding allow rule | |
| `V-CROSS-ENCLAVE-ORPHAN` | Egress allow with no matching ingress on the peer firewall | |

### Info

`V-BASELINE-DRIFT` (protected set differs from seed profile) · `V-UNEXPECTED-HOST` (nmap found a host not in the annex) · `V-SCORING-UNCHECKED` (a host has no ISA checks — confirm it is unscored) · `V-NO-SEPARATORS`.

---

## 9. Output

**Tier 1 — GUI checklist.** Markdown and printable HTML. Ordered alias table, rules grouped by tab in entry order, every GUI field spelled out.

**Tier 2 — section restore XML.** `<team>-<enclave>-aliases.xml` and `<team>-<enclave>-filter.xml`, each a complete section. Applied via Diagnostics → Backup & Restore.

> Section restore **replaces**, it does not merge. The generated file is always the complete intended state. State this on the export screen alongside: take a full backup first, and Config History provides a revert.

> **Build task:** verify on a test pfSense CE 2.8.1 box which restore-area names map to `<aliases>`, `<filter>` and `<interfaces>`, whether `<separator>` survives a filter restore, and whether restore triggers a filter reload. Record the answer here. Do not ship Tier 2 on assumption — `OPEN-QUESTIONS.md` Q2.

**Verification manifest.** Per source position, from policy + ISA checks. Format and guardrails in `VERIFICATION.md`.

**Diff view.** Mandatory gate. Kept / removed / added, plain-English per rule, validator findings inline, **action shown prominently** (E3). No export until blocking findings clear and warnings are individually acknowledged.

**Estate policy file.** The durable artefact. YAML, human-editable, diffable, one per phase.

---

## 10. Testing

### 10.1 Fixtures — hard rule

**No real range configuration in the repository.** Fixtures are hand-built, sanitised files reproducing the *structure* of the baseline — same protected set, same interface layouts including the `dsoc` inversion and the `mcu` straddle — with placeholder addressing and every credential-bearing element removed. `BASELINE-ANALYSIS.md` and `seed-profile.yaml` contain everything needed to build them.

### 10.2 Required tests

| Test | Assertion |
|---|---|
| Determinism | Same inputs → byte-identical output across runs and processes |
| Round-trip | Re-ingesting output classifies every protected item as an exact strict match |
| Protected-set integrity | Every `keep_verbatim` rule byte-identical to baseline, original relative order |
| Interface roles | `dsoc` `lan`/`opt1` resolve to `svrs`/`ws`; `mcu` resolves to `dmz`/`port1`/`port2`/`stbd1`/`stbd2` |
| Estate side | `mcu` classified host_nation from its WAN, not deployed from its internals |
| Identity binding | A `do` ruleset applied to `dsoc` is refused |
| Normalisation | Property test: `any`/`0.0.0.0/0`, `53`/`53-53`, ordering permutations collapse to one fingerprint |
| **Secret exclusion** | Fixture containing hashes and keys produces no output or persisted state containing them. **CI, every commit.** |
| Validator coverage | One golden case per ID — fires on its case, silent on the clean baseline |
| Evidence regressions | One case per `EVIDENCE.md` finding E1–E10 |
| Annex parse | Both Annex A and Annex G table shapes parse, including heading variance |

---

## 11. Build order

Each milestone independently useful.

1. **Parse + interface map.** All seven enclave structures, roles derived correctly including `dsoc` and `mcu`. Print the map.
2. **Normalise + fingerprint.** Both tiers, proven by property tests. No UI yet.
3. **Seed profile + classification.** Load, classify a fixture, report match tiers.
4. **Wizard.** Interface-by-interface, typed input only.
5. **Annex paste-parse.** As a shortcut inside wizard steps.
6. **ISA check assignment + service catalogue.**
7. **Generator + Tier 1 output.** Usable at this point.
8. **Triage modal.** All four states.
9. **Validators.** Blocking set first, then warnings.
10. **Diff view.** Then, and only then, unlock export.
11. **Tier 2 XML.** After the Q2 test-box verification.
12. **Verification manifest + nmap import.**
13. **Estate-level cross-enclave checks.**

---

## 12. Non-negotiables

1. No network calls. Offline, always.
2. Only `<aliases>`, `<filter>` and `<nat>` are written. Credentials never persist.
3. No output without passing the diff gate.
4. No deny emitted without an essential-services pass ahead of it.
5. No dropping a lockout-critical item without typed confirmation.
6. Descriptions are never identity. Fingerprints only.
7. Interface roles, never raw `lan`/`opt1`, in any matching logic.
8. Output bound to one firewall identity; refuses to load elsewhere.
9. Deterministic output.
10. No real range configuration in the repository.
11. Out-of-Bounds EXCON hosts are never blocked and never policy targets.
12. Every ISA-checked host:port pair is permitted, dual-stack, above any deny.
