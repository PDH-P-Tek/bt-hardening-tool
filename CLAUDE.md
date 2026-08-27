# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

**BT Hardening Tool — agent brief. Read this, then `SPEC.md`, then `BASELINE-ANALYSIS.md` and `EVIDENCE.md`. Do not start coding until you have read all four.**

**If your task touches the monitor or the hardening checks, read `MONITORING.md` and `HARDENING.md` too.** They are a separate subsystem with their own constraints, some of which contradict assumptions that are safe for the generator.

**Live estate data stays out of the tree.** Not a classification rule — a hygiene one. No credentials, keys, `known_hosts`, real firewall exports, collected state or monitor databases get committed, because the tool reads material that would be a liability to store. Fixtures are hand-built and sanitised (`SPEC.md` §10.1) and the secret-exclusion test enforces it.

---

## What you are building

A self-hosted web app for the Blue Team's **firewall and router hardening cell**. Three subsystems, one tool:

1. **Generate** — turn range documentation into a correct, correctly-ordered pfSense ruleset, while guaranteeing the Green Team's pre-loaded configuration survives intact. `SPEC.md`.
2. **Monitor** — detect change across the managed estate against a known-good baseline and present it for human triage. `MONITORING.md`.
3. **Harden** — check collected state against a recommended posture, whether or not it has changed. `HARDENING.md`.

They share one estate inventory, one baseline artefact and one set of platform adapters. The generator's output *is* the monitor's firewall baseline; the monitor's collection feeds the hardening checks. Design that shared spine before building either half.

**Stack:** Python 3.11+, FastAPI, Jinja2, server-rendered HTML, light vanilla JS. Single container.

**Network posture — this changed, read it carefully.** The generator makes **no network calls, ever**. The monitor makes outbound SSH connections to managed hosts on the management path and nothing else: no internet, no telemetry, no package fetches at runtime. Any code path reaching the network outside the monitor's SSH transport is a defect.

**Scope:** whole team estate — all enclave firewalls together, so cross-enclave dependencies validate. The monitor extends the same inventory to the FRR routers.

`SPEC.md` is the authority on behaviour. This file is orientation and the working agreement.

## Why it exists — read `EVIDENCE.md` early

Seven Blue Team firewall configs from the end of DCM26 were analysed. Summary:

- **Every enclave** finished with `pass any → any` live on every internal segment. Only one closed the WAN catch-all. Thirty carefully-written rules sat above an open door.
- **Every enclave** had IPv4-only rules stacked above `inet46` catch-alls, so IPv6 bypassed the entire ruleset. The best-hardened enclave had 31 such rules — none of its work applied to IPv6, which is also scored.
- Three rules labelled `BLOCK` had action `pass`.
- A port alias named `Temp` exposed MySQL to the greynet.
- A port forward believed to be making FTP work was malformed and doing nothing; a catch-all was passing the traffic.

None of that reflects on the teams. It is what the environment produces under time pressure, which is exactly why a tool should carry it. Each finding maps to a validator ID and becomes a golden test.

## Who uses it, and why that shapes everything

Blue Team defenders with pfSense GUI access and nothing else. No Ansible, no API, no shell tooling on the range.

- **They get the documents one day before the range opens.** Phase 1 of `WORKFLOW.md` runs entirely off them. The tool must be fully usable with zero range access.
- **A wrong output costs points, and possibly their access to their own firewalls.** Refusing to generate always beats generating something plausible. Every ambiguity resolves toward stop-and-ask.
- **They read one line per rule, not the XML.** The plain-English summary is a first-class feature. Budget real effort on the wording.
- **They cannot debug your abstractions at 3am.** Explicit, ordered, described. Nothing clever.

## Ground truth — internalise before writing code

Read `BASELINE-ANALYSIS.md` properly. These six are load-bearing:

1. **`dsoc` inverts LAN.** On every other enclave `lan` is workstations; on `dsoc` it is servers. And **`mcu` straddles estates** — its WAN is Host Nation, its internals are deployed addressing. Any logic keyed to `lan`/`opt1`, or inferring estate from internal ranges, is wrong. Use derived roles (`SPEC.md` §4.1) and derive `estate_side` from the WAN address. This is the most common way to get this codebase dangerously wrong.
2. **Descriptions are not identity.** Three of the six protected rules have empty descriptions, and one baseline rule was later widened while keeping its label. Identity comes from normalised semantic fingerprints, two tiers, nothing else.
3. **pfSense booleans:** empty element = false, `yes` = true. Presence means nothing. Backwards, and the tool reports anti-lockout as disabled on every real config.
4. **The GT floating rules are non-quick and currently load-bearing.** Generated output must never depend on that. Every intended pass is an explicit quick rule.
5. **ISA is the port list.** The annexes give no port numbers. The ISA Target Checks Status board gives them per target and is visible to Blue Teams from day one. `isa-checks.yaml` is the most important data file in the package.
6. **Out-of-Bounds EXCON hosts live inside the workstation segment.** `scoringbot` at `<ws_subnet>.254` and `npc-server` at `.249`. Neither appears on the range diagram. Tightening the workstation segment kills scoring and the usersim engine from the inside.

## Working agreement

**Build in the order in `BUILD-PLAN.md`.** It merges `SPEC.md` §11 and `MONITORING.md` §10 into one sequence, puts the shared spine and the toolchain first, and marks what is gated on a test box or a person. Each phase is independently useful. Do not build UI before fingerprinting is proven by the property tests — a brittle fingerprint makes the tool worse than nothing, and you will not discover that through a UI.

**The estate is declared, never assumed.** On day one the operator sets the estate up: which enclaves exist and what they are called, what each device is (firewall, router, host) and which platform it runs, its management address, its interfaces and what each segment is for, and what the hosts run. All of it is theirs to name. **No enclave name, interface role token or side label may appear as a literal in the package** — not in a match, not as a default, not as a fallback. The shipped profile and enclave templates supply *suggestions* the operator confirms; `tests/fixtures/` reproduces one observed estate so the awkward cases stay tested. Neither is something the code may reach for when the operator has not declared it.

**The wizard is the spine, paste-parse is an accelerator.** Not alternatives. Every wizard step must be completable by typing, because the annex format will change and the paste will sometimes fail. A silent mis-parse is the failure mode to design against — always render the parse back for confirmation.

**Never commit real range configuration.** Fixtures are hand-built and sanitised (`SPEC.md` §10.1). `BASELINE-ANALYSIS.md`, `seed-profile.yaml` and the templates contain everything needed to construct them. The secret-exclusion test runs in CI on every commit and is not optional.

**Only `<aliases>`, `<filter>` and `<nat>` are written.** Source configs contain password hashes, private keys and cleartext service passwords. The parser reads a short explicit fact list beyond those three sections (`SPEC.md` §5.4) and retains nothing else.

**When the spec and convenience disagree, the spec wins.** The twelve non-negotiables in `SPEC.md` §12 are exactly the things that will feel like overhead during the build. They are the product.

**Open questions live in three places**, and none of them stop you starting. `OPEN-QUESTIONS.md` for the generator — pfSense section-restore behaviour must be verified on a test box before Tier 2 ships, and the single-digit-team addressing convention needs one config export to settle. `MONITORING.md` §12 for the monitor. `HARDENING.md` §12 for the posture checks. Build around them; do not quietly assume an answer.

Two are worth knowing before you touch the pfSense adapter: whether pfSense preserves `from=`/`command=` options when it regenerates `authorized_keys`, and whether its account sync reconciles strays or only adds.

**Where the documents specify a surface, build that surface.** `MONITORING.md` §8.2
describes the dashboard precisely — host tiles, worst-severity colour, one dominant
count. An earlier build substituted the topology diagram because reuse looked
economical, and produced a page that could not be triaged from. The specified shape is
usually specified for a reason that is not visible from inside the code.

**The monitor is read-only, and that is not negotiable.** It holds no credential that can change a firewall. It never reverts, never pushes, never remediates — it renders the change and a human acts on the box. This will feel like a missing feature: you will have SSH access, a diff, and an obvious button to add. Do not add it. Auto-revert was considered and rejected (`MONITORING.md` §2), and a write-capable collector also destroys the conflict-of-interest position the whole tool rests on. The same rule binds the hardening checks — they show remediation steps, they never apply them.

**No attribution lines.** No "Co-Authored-By", no "Generated with", in code, commits or documents.

## Repository state and commands

Phases 0–10 are complete except 8.1, which is blocked on a CE 2.8.1 test box.
The generator, the 31 `V-*` validators, the `H-*` posture checks, 24 `M-*` collectors,
the collection scheduler, the triage surface and the router hardening output are all
built and tested. Two CLI commands exist — `python -m btht map <config>...` prints an
estate's interface map, and `python -m btht classify <config>... --team N` reports what
the profile recognised and what still needs a human. `uv` manages the environment,
Python is pinned to 3.12 in `.python-version` (the spec floor is 3.11).

**The web app is the product.** `make run` serves it; `make demo` populates a two-enclave
range to look at. The operator's route through it is Range → Rules → Monitor, and
`web/guide.py` works out which of those they are up to from the estate's own state and
says so on every page.

**The monitor's collector runs in the same process as the builder** (`monitor/scheduler.py`,
started on FastAPI lifespan). It stays idle, with a stated reason, unless `BTHT_SSH_KEY`
names a private key — firing a doomed `ssh` at every managed box every minute would
achieve nothing but a failed-login line in each of the auth logs this tool asks people to
read. `BTHT_MONITOR=0` disables it entirely, which is what the test suite does.

```bash
make install      # uv sync — create the venv, install everything
make test         # uv run pytest
make test-one TEST=tests/test_x.py::test_y
make lint         # ruff check
make fmt          # ruff format + --fix
make typecheck    # mypy, strict, over btht/ and tests/
make check        # lint + typecheck + test. What CI runs.
```

CI is `.github/workflows/ci.yml`, running the same three steps on every push.

What the tooling has to support, from `SPEC.md` §10.2:

- **Per-validator golden tests.** Every `V-*` needs a case that fires *and* a clean-baseline case that stays silent. `make test-one` selects by node id; the `golden` marker groups them.
- **The secret-exclusion test runs on every commit** (`tests/test_secret_exclusion.py`). It scans tracked files and fixtures for credential material and asserts `.gitignore` still covers working data. It is the control; `.gitignore` is the safety net. It has been proved against a planted hash — keep it that way if you extend it.
- **Determinism is a test.** Byte-identical output across runs *and separate processes*, so nothing in emission may depend on dict ordering or hash seed.
- **Offline is testable too, and should be tested.** Any code path reaching the network outside the monitor's SSH transport is a defect, not a preference.

## Architecture — the shared spine

Module layout is `SPEC.md` §3; read it before adding a file. **One deviation:** `tests/` sits at the repository root rather than inside `btht/`, because `.gitignore`'s `!tests/fixtures/**/*.xml` negation is anchored to the root and would otherwise refuse to track any fixture XML. Everything else follows §3. What is worth knowing before you open it:

**One pipeline, pure at the core.**

```
wizard / annex paste / ISA checks / config ingest
    → estate policy (YAML — the durable artefact)
    → generate → validate → diff gate → export
```

`generate` is a pure function of `(baseline, policy, profile)`. All the mess lives in `ingest/`; keep it there. Nothing downstream of `normalise` should know what a pfSense XML element looks like.

**`ingest/normalise.py` and `ingest/fingerprint.py` are shared by both halves of the tool.** The generator uses them to decide which baseline rules are protected; the monitor's pfSense adapter uses the same code to give a rule a stable identity across polls. Change a normalisation rule and you move a classification result *and* a monitor item key at once — which is why fingerprinting is proven by property tests (build order step 2) before any UI exists.

**The estate inventory and the baseline artefact are the join between the subsystems.** The generator's output *is* the monitor's firewall baseline; hosts, addresses and roles are defined once and read by both. Design that spine before building either half (`MONITORING.md` §11).

**The monitor is adapters → normalise → diff → item store → triage UI.** Three adapters (`pfsense`, `linux`, `frr`) behind one interface, each returning a normalised item set; the diff engine is platform-agnostic and must stay that way. Persistence is SQLite, holding *items* — each with a stable identity key and a `review_state` (`unreviewed` / `accepted` / `flagged` / `suppressed`). Triage is per item, never per host: if accepting one change re-surfaces the other nine, the operator stops using accept and the model collapses (`MONITORING.md` §3.4).

**The monitor invariant that ranks with the generator's six ground truths: config is diffed, state is never diffed** (`MONITORING.md` §3.3). Rules, NAT, aliases, accounts, keys, sudoers, cron, units, boot hooks and routing *definitions* are config — baseline and alert on any change, deletions included. State tables, counters, routing tables, neighbour up/down, leases, uptime and logins are state — display, never alert. Get this backwards and it cries wolf every 60 s; a tool the operator has learned to dismiss is worse than no tool. The FRR adapter is where it bites: `show running-config` is config, `show ip route` is state.

**Hardening adds checks, not transport.** `H-*` evaluates the same collected item set the monitor already holds — one collection, two evaluations (`HARDENING.md` §11).

## Repository conventions

- Layout in `SPEC.md` §3.
- Validators are pure functions with stable IDs. One golden test per ID, asserting it fires on its case *and* stays silent on the clean baseline.
- Generation is a pure function of `(baseline, policy, profile)`. Byte-identical output across runs is a test.
- `data/estates/` is gitignored — populated policy files hold real estate detail.
- **Nothing collected from a live box is ever committed.** Baselines, collected state and the monitor's database are working data, not source. They are gitignored and the secret-exclusion test covers them.
- No credentials, keys or `known_hosts` in the tree. The monitor's key pair is generated by the operator at setup and lives outside the repo.
- Remote is `origin` → `git@github.com:PDH-P-Tek/bt-hardening-tool.git`. `_inbox/` is a gitignored drop-box, not part of the project — move files into the tree deliberately before committing them.
- Build order: `BUILD-PLAN.md` is the sequence. `SPEC.md` §11 and `MONITORING.md` §10 remain authoritative on what each step must do.
- **Every link the app renders is followed by a test** (`tests/test_web_links.py`). The topology once built its links against a retired route space, so every click 404'd — through a full green suite, because the tests asserted the query string and never that the path existed. A route rename now breaks a test.
- **ID namespaces are stable and load-bearing:** `V-*` generator validators (`SPEC.md` §8), `M-*` monitor collection (`MONITORING.md` §5), `H-*` posture checks (`HARDENING.md` §5–9). `F*` / `E*` are findings in `BASELINE-ANALYSIS.md` / `EVIDENCE.md` — name the golden test after the ID it defends so a failure points straight at the source finding.

## Files here

| File | What it is |
|---|---|
| `SPEC.md` | Authoritative specification — model, fingerprinting, inputs, generation, validators, tests, build order |
| `BUILD-PLAN.md` | The merged build sequence — phases 0–8, what gates what, what ships if time runs short |
| `WORKFLOW.md` | What the operator actually does, step by step, with timings |
| `BASELINE-ANALYSIS.md` | What Green Team ships; the annex structure; findings F1–F12 |
| `EVIDENCE.md` | What DCM26 teams did with it; findings E1–E10; the validator test set |
| `VERIFICATION.md` | Proving the ruleset does what the policy said |
| `MONITORING.md` | Estate change detection — collection matrix `M-*`, platform adapters, setup, triage model |
| `HARDENING.md` | Posture checks `H-*` — sshd, pfSense platform, ruleset, accounts, FRR; day-one ordering |
| `isa-checks.yaml` | ISA check → port mapping, and the scoring topology. **The port problem, solved.** |
| `service-catalogue.yaml` | Role-keyed port sets with honest confidence levels |
| `seed-profile.yaml` | Shipped classification profile for the GT baseline |
| `templates/do-enclave.yaml` | Deployed enclave starter (Annex A) |
| `templates/bank-enclave.yaml` | Host Nation starter (Annex G) — included to show what varies |
| `examples/enclave-policy.example.yaml` | Worked estate policy file |
| `wireframes/` | Wizard flow and triage modal |
| `OPEN-QUESTIONS.md` | What we don't know, who to ask, what's blocking |
