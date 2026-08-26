# BT Hardening Tool

A design package for a self-hosted, offline tool that turns range documentation into a correct pfSense ruleset, while guaranteeing the Green Team's pre-loaded configuration survives intact.

**Status:** design v0.2, pre-build. Nothing has been written yet.

## The problem, in numbers

Seven Blue Team firewall configurations from the end of DCM26 were analysed:

| | |
|---|---|
| Enclaves that finished with `pass any → any` live on every internal segment | **6 of 6** |
| Enclaves that closed the WAN catch-all | 1 |
| IPv4-only rules sitting above `inet46` catch-alls, so bypassed on IPv6 | **74 across the estate** |
| Rules labelled `BLOCK` whose action was `pass` | 3 |
| Port aliases named `Temp` exposing MySQL to the greynet | 1 |

The best-hardened enclave in the estate had 31 carefully-crafted rules. None of them applied to IPv6, which is also scored.

Every one of those is a check a validator performs in seconds. `EVIDENCE.md` has the detail.

## What changed the design

Three inputs, each of which moved something significant:

**The Technical Annexes** (one per enclave, issued the day before the range opens) carry the subnet table, a full host inventory with IPv6, and a Connectivity Requirements section that reads directly as starter policy. They give **no port numbers**.

**The ISA Target Checks Status board** gives the ports — per target, precisely, and visible to Blue Teams from day one. Reading it is the highest-value fifteen minutes of the exercise. Captured in `isa-checks.yaml`.

**The end-state configs** supplied the scoring topology the teams recovered under fire, the full interface role vocabulary, and the evidence above.

## Read in this order

| # | File | What it gives you |
|---|---|---|
| 1 | `CLAUDE.md` | Agent brief. Start here to build it. |
| 2 | `SPEC.md` | The authority on behaviour. |
| 3 | `BUILD-PLAN.md` | The merged build sequence. What to do first. |
| 4 | `WORKFLOW.md` | What the operator does, step by step, with timings. |
| 5 | `BASELINE-ANALYSIS.md` | What Green Team ships. Findings F1–F12. |
| 6 | `EVIDENCE.md` | What teams did with it. Findings E1–E10, and the validator test set. |
| 7 | `VERIFICATION.md` | Proving the ruleset does what the policy said. |
| 8 | `MONITORING.md` | Estate change detection — collection matrix, adapters, triage model. |
| 9 | `HARDENING.md` | Posture checks `H-*`, and the day-one ordering that avoids lockout. |
| 10 | `isa-checks.yaml` | ISA check → port mapping and scoring topology. |
| 11 | `service-catalogue.yaml`, `seed-profile.yaml`, `templates/` | Shipped data. |
| 12 | `wireframes/` | Open in a browser. |
| 13 | `OPEN-QUESTIONS.md` | What we don't know. Two still blocking. |

## Decisions

| | |
|---|---|
| Stack | Python 3.11+, FastAPI, Jinja2. Single container, fully offline. |
| Scope | Whole team estate, so cross-enclave dependencies validate. |
| Interaction | **Wizard-first** — walk each firewall interface by interface. Annex paste-parse is an accelerator inside wizard steps, never an alternative. |
| Timing | Runs off-range on team kit. Phase 1 completes from the documents alone, the night before. |
| Output | GUI checklist plus pfSense section-restore XML, plus a verification manifest. No live push. |
| Identity | Normalised semantic fingerprints, two tiers. Descriptions are display only. |
| Sections written | `<aliases>`, `<filter>`, `<nat>`. Nothing else, ever. |
| Source material | Blue Team Information Book content only. |

## Still blocking

1. **pfSense section-restore behaviour** — verify on a test CE 2.8.1 box before Tier 2 output ships.
2. **Single-digit team addressing** — `198.19.5.0/24` or `198.19.05.0/24`? One config export from any single-digit team settles it.

Neither stops the build starting.

## Worth doing regardless of the tool

- **Report the `Routers` alias IPv6 defect to Green Team** (F1). It affects every team; fixing it upstream beats every team working around it.
- **Raise the tooling question with the exercise lead** (Q6), unprompted and early.
- **Tell next year's Blue Team about the ISA board.** Even with no tool at all, reading it on day 0 is the difference between knowing the scored ports and guessing them.

## Next step

Hand `CLAUDE.md` to a Claude Code agent and start at Phase 0 of `BUILD-PLAN.md`. Each phase is independently useful — the generator is worth having at the end of Phase 3, before validators and XML export exist.

**Do not commit real range configuration.** Fixtures are hand-built and sanitised; the analysis documents and shipped data files contain everything needed to construct them.
