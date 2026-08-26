# Build Plan

The merged, ordered sequence. `SPEC.md` §11 and `MONITORING.md` §10 each order their
own half; this file joins them, puts the shared work first, and marks what is gated
on something outside the code.

**This does not replace those lists.** Every step cites its source, and the source
stays authoritative on *what* the step must do. This file is authoritative on *when*.

Status: **Phases 0–7 complete, 8.2 and 8.3 done. Stopped at a blocker.** 8.1 (Tier 2 XML) cannot ship until a CE 2.8.1 box answers Q2, Q12 and MONITORING Q2 — one sitting closes all three. 8.4 is polish; 8.5 is deferred by design.

---

## The three rules that shape the order

1. **The spine before either half.** The estate inventory and the baseline artefact
   are shared by the generator and the monitor. They are designed once, first, or
   they get designed twice and disagree — `MONITORING.md` §11.
2. **Fingerprinting before UI.** A brittle fingerprint makes the tool worse than
   nothing, and a UI will not reveal that. Property tests gate Phase 2 — `SPEC.md` §11.
3. **The topology is a view, not an editor.** It is drawn from the declared estate and
   never becomes a second place the estate can be defined. No drag-to-edit: if node
   positions ever need tuning, they are overrides stored in the estate file.
4. **Each phase ends somewhere useful.** Stop at the end of any phase and what exists
   still earns its keep. The two lines worth knowing: the generator is usable at the
   end of **Phase 3**, and the monitor at the end of **Phase 5**.

---

## Phase 0 — Foundation

Nothing else starts until this is done. None of it appears in the source build orders,
which is why it is here.

| # | Step | Done when |
|---|---|---|
| 0.1 | ✅ Package skeleton per `SPEC.md` §3 (`btht/`), `pyproject.toml`, pytest, ruff, mypy, task runner | `make test` runs green on an empty suite; **commands recorded in `CLAUDE.md`** |
| 0.2 | ✅ CI on every commit, carrying the secret-exclusion test from day one | Suite runs on push; the secret test exists, even if it starts as a stub over an empty fixture set |
| 0.3 | ✅ **The shared spine.** Estate / Firewall / Interface / Host (`SPEC.md` §4) plus what the monitor needs on top: platform type, management address, credential reference | One model, imported by both halves. No second inventory anywhere |
| 0.4 | ✅ Sanitised fixtures (`SPEC.md` §10.1) — protected set, `dsoc` LAN inversion, `mcu` straddle, placeholder addressing | Fixtures load; secret-exclusion test now has real credential-bearing input to prove itself against |

> 0.4 is the step it is tempting to defer. Almost every test downstream needs it, and
> building fixtures late means building them to fit whatever the code already does.

---

## Phase 1 — Parse and identity · *shared by both halves*

`SPEC.md` §11 steps 1–3. The pfSense parser here is the same one the monitor's adapter
uses at 6.1 — write it once.

| # | Step | Source | Done when |
|---|---|---|---|
| 1.1 | ✅ pfSense config ingest → domain objects. `<aliases>`, `<filter>`, `<nat>` and the fixed fact list, nothing else | §5.4 | Round-trips a fixture; retains nothing outside the allow-list |
| 1.2 | ✅ Interface role derivation and `estate_side` | §4.1, §4.2 | `dsoc` `lan`→`svrs` / `opt1`→`ws`; `mcu` classifies host_nation from its WAN |
| 1.3 | ✅ Normalisation and the two-tier fingerprint | §6.1, §6.2 | **Property tests pass.** `any`/`0.0.0.0/0`, `53`/`53-53`, ordering permutations collapse to one fingerprint |
| 1.4 | ✅ Seed profile load and classification | §4.3 | Classifies a fixture, reports match tier per item |

**Milestone reached: `python -m btht map <config>...`** prints the interface map, the
side label and which segment anti-lockout is really protecting. Run without a declared
setup it resolves nothing and says so, which is the behaviour, not a gap.

**Gate: 1.3 must pass before Phase 2 begins.** No UI ahead of it.

---

## Phase 2 — Policy capture

`SPEC.md` §11 steps 4–6. The wizard is the spine; paste-parse is an accelerator inside it.

| # | Step | Source | Done when |
|---|---|---|---|
| 2.1 | ✅ **Estate setup.** Declare the estate: enclaves and their names, each device and its platform, management addresses, interfaces and what each segment is for, what the hosts run. Establishes the role vocabulary | §4, §5.1 | An estate exists that the operator named end to end. **This is the same inventory 5.1 polls** — captured once |
| 2.2 | ✅ **Topology view.** The declared estate drawn as inline SVG — enclaves, routers, firewalls, segments. Click a node for its detail. Deterministic tiered layout, no library | §4 | Same estate renders the same picture; a setup error is visible in it. **5.4 reuses it** with live status |
| 2.3 | ✅ Estate policy schema and loader — the durable artefact | §4, §9 | Round-trips YAML; human-editable and diffable |
| 2.4 | ✅ Wizard, interface by interface, **typed input only** | §5.1 | Every step completable without pasting anything |
| 2.5 | ✅ Annex paste-parse as a shortcut inside wizard steps | §5.2 | Both annex table shapes parse; **the parse renders back for confirmation** |
| 2.6 | ✅ Scoring check assignment and service catalogue. **Catalogue optional** — with none loaded nothing is proposed and no scoring rules generate | §5.3 | Every host carries a confirmed check set; unscored hosts flagged for confirmation |

---

## Phase 3 — Generate · *first shippable*

`SPEC.md` §11 step 7.

| # | Step | Source | Done when |
|---|---|---|---|
| 3.1 | ✅ Ordering engine — floating blocks 1–6, per-interface, WAN | §7.1 | Every intended pass is an explicit quick rule; no reliance on non-quick semantics |
| 3.2 | ✅ Dual-stack emission | §7.2 | No v4-only rule emitted silently; asymmetry flagged |
| 3.3 | ✅ Tier 1 output — GUI checklist, markdown and printable HTML | §9 | One line per rule, every GUI field spelled out |

**Milestone: the tool is worth having.** A team can work from Tier 1 with no validators,
no XML and no diff view.

**Test that lands here: determinism.** Byte-identical output across runs and separate
processes. If it fails, it fails now, before more code depends on emission.

---

## Phase 4 — Safety rails

`SPEC.md` §11 steps 8–10. Export stays locked until the end of this phase.

| # | Step | Source | Done when |
|---|---|---|---|
| 4.1 | ✅ Triage modal, all four states | §6.3 | Every item reaches a role and disposition; `unknown` blocks export |
| 4.2 | ✅ Validators — blocking set (14 IDs) | §8 | One golden test per ID: fires on its case, silent on the clean baseline |
| 4.3 | ✅ Validators — warnings and info | §8 | As above; warnings require individual acknowledgement |
| 4.4 | ✅ Diff view, then unlock export | §9 | No export path exists that bypasses it |

**Also here:** one regression case per `EVIDENCE.md` finding E1–E10.

---

## Phase 5 — Monitor core · *minimum viable monitor*

`MONITORING.md` §10 steps 1–4. **Can run in parallel with Phases 2–4** — it needs Phase 0
and 1.3, nothing from the generator's front half.

| # | Step | Source | Done when |
|---|---|---|---|
| 5.1 | ✅ Inventory, credential store, SSH transport, heartbeat | §10.1 | "Are all my boxes up, is my access intact" answerable |
| 5.2 | ✅ Linux adapter — accounts, keys, sudo, cron | §5.1–5.3 | Easiest platform to test off-range; hits the DCM26 pattern directly |
| 5.3 | ✅ **Diff engine, item identity, review state** | §3.4 | Accept / flag / suppress work **per item**. Accepting one change does not resurface nine others |
| 5.4 | ✅ Estate / host / item dashboard — **the 2.2 topology with live status on it** | §8.2 | First point the monitor is genuinely usable. A host that stops answering is visible as a shape, not a log line |

> 5.3 is the product, not the plumbing. Prove it on one adapter before adding more.
> **Config is diffed, state is never diffed** (§3.3) — the rule that decides whether this
> reduces alert fatigue or becomes it.

---

## Phase 6 — Monitor breadth

`MONITORING.md` §10 steps 5–7.

| # | Step | Source | Done when |
|---|---|---|---|
| 6.1 | ✅ pfSense adapter — **reuses the Phase 1.1 parser** | §6.1 | `M-ACC-07`, `M-FW-01/06/07` reporting |
| 6.2 | ✅ Services, listening ports, boot hooks, filesystem canaries | §5.4–5.6 | Coverage broadened across all platforms |
| 6.3 | ✅ FRR adapter | §6.3 | `show running-config` diffed; `show ip route` displayed and never diffed |

---

## Phase 7 — Posture checks

`MONITORING.md` §10 step 8. `H-*` evaluates the same collected set — one collection,
two evaluations. Useful on day one, before anything is attacked.

| # | Step | Source | Done when |
|---|---|---|---|
| 7.1 | ✅ `H-SSH-*`, `H-PF-*`, `H-FW-*`, `H-ACC-*` over the collected item set | `HARDENING.md` §5–8 | Each check reports pass / fail / not-applicable with remediation shown, never applied |
| 7.2 | ⚠️ `H-FRR-*` — implemented; scoping still gated on **H-Q2** | `HARDENING.md` §9 | Scoping depends on **H-Q2** |

> `HARDENING.md` §4 orders what the *operator* does on day one. It is not a build order —
> do not confuse the two.

---

## Phase 8 — Gated and deferred

Nothing here blocks anything above it.

| # | Step | Source | Gate |
|---|---|---|---|
| 8.1 | Tier 2 section-restore XML | `SPEC.md` §9 | **BLOCKED on Q2** — verify on a CE 2.8.1 box first. Do not ship on assumption |
| 8.2 | ✅ Verification manifest and nmap import | `SPEC.md` §11.12, `VERIFICATION.md` | — |
| 8.3 | ✅ Estate-level cross-enclave checks | `SPEC.md` §11.13 | Needs two or more enclaves modelled |
| 8.4 | Monitor polish — `/metrics`, digest export, shift handover | `MONITORING.md` §10.9 | — |
| 8.5 | `nft monitor` event streaming | `MONITORING.md` §10.10 | Phase 2 by design. Buys latency only |

---

## What is gated on something outside the code

None of these stop the build. They stop specific steps.

| Question | Blocks | Resolution |
|---|---|---|
| `Q2` — pfSense section-restore behaviour | **8.1** | Test on a CE 2.8.1 box. Nobody needs to answer it; someone needs to try it |
| `Q12` — which boolean convention rule-level `<disabled>` / `<log>` use | Correctness of every parsed rule's active state | Same box: disable a rule, enable logging on another, export, read what the GUI wrote |
| `MONITORING Q2(a)` — does pfSense preserve `from=`/`command=` in `authorized_keys` | Collector access restriction (setup S4) | Same box, same sitting |
| `H-Q4` — is disabling anti-lockout permitted | `H-PF-01` | Exercise lead. **Ask early** — it is the pivot the management-restriction story turns on |
| `H-Q5` — is there a remote syslog target | Logging checks in 7.1 | Blue Team lead |
| `H-Q2` — which FRR daemons expose VTY | `H-FRR-01` scoping | Inspect a router |
| `Q3` — single-digit team addressing | Address handling in 2.3 | One config export from any single-digit team |
| `Q10` — which ISA checks apply to deployed firewalls | `V-EGRESS-CHECK` precision | Read the ISA board on day 0. Two minutes |

Two of these — `Q2` and `MONITORING Q2(a)` — are the same test box. Book it once.

---

## Definition of done, every step

Applies throughout, not just where named:

- **Validators are pure functions with stable IDs.** One golden test per ID, asserting
  it fires on its case *and* stays silent on the clean baseline.
- **Fixtures are sanitised and hand-built.** No real range configuration in the tree.
- **The secret-exclusion test runs on every commit** and covers whatever the step added.
- **Generation stays a pure function of `(baseline, policy, profile)`** — byte-identical
  across runs and processes.
- **The monitor stays read-only.** It renders change; a human acts on the box. The same
  binds the posture checks: they show remediation, they never apply it.

---

## If time runs short

The honest fallback, in priority order:

1. **Phases 0–3** — the generator through Tier 1 output. A correct, ordered, plain-English
   ruleset a team can type in. This is the floor.
2. **Phase 4** — validators and the diff gate. Turns "a ruleset" into "a ruleset that
   refuses to be wrong".
3. **Phase 5** — the monitor's first four steps. Change detection with working triage.

Everything from Phase 6 on is breadth. Useful, not load-bearing.
