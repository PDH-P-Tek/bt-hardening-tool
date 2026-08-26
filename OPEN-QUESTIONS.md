# Open Questions

Status: **BLOCKING** — ships incomplete without it · **Needed** — affects design, workaround exists · **Nice** — improves quality · **CLOSED**.

---

## Q1 — Scoring and Yellow Team usersim sources · CLOSED (confirm with GT)

**Answered 21 Aug 26** from the DCM26 end-state configs, both Technical Annexes and the ISA board.

- **Deployed enclaves:** local scoring bot at `<workstation_subnet>.254`, listed in Annex A DO §2.5 as `25.XX.9.254`, Out of Bounds, "Not shown on diagram". Inside the workstation segment, so its checks against servers and DMZ cross the firewall.
- **Host Nation enclaves:** served from GOV. Annex G §2.6 — *"Scoringbot in Host Nation Government (GOV) must be able to communicate with all DNMP systems."* Observed at `10.XX.1.254`.
- **Central monitor:** `10.181.2.214`, in the range core block `10.181.0.0/16`.
- **YT usersims:** arrive within the existing `Remote_Access` ranges. No YT entry appears in that alias's `<detail>` field, so they most likely ride the White Team block — preserving `Remote_Access` intact covers it either way.
- **The scored port list** is the ISA Target Checks Status board, captured in `isa-checks.yaml`.

Still worth five minutes with GT to confirm the `.254` pattern holds for DCM27 and that the central monitor address is stable.

---

## Q2 — pfSense section-restore behaviour · BLOCKING

**Nobody needs to answer this. Someone needs to test it on a pfSense CE 2.8.1 box.**

1. Which restore-area names map to `<aliases>`, `<filter>` and `<interfaces>`?
2. Does a filter-section restore preserve or discard `<separator>` entries?
3. Does it trigger a filter reload, or is a manual apply needed?
4. Does restoring `<filter>` with referenced aliases absent fail cleanly or leave a broken ruleset?
5. Does the **Backup area** dropdown export those three sections cleanly and separately? (`WORKFLOW.md` §5 depends on this for the no-credentials-leave-the-box path.)

Tier 2 output is the main time saving over GUI entry. Shipping it on assumption risks a team pasting a config that half-applies mid-exercise. **Do not ship Tier 2 until answered.**

---

## Q3 — Team-number token in addressing · Needed

Both annexes define it identically: `X` unpadded (1…36), `XX` zero-padded (01…46). The worked example uses team 42, which does not disambiguate, and all our config evidence is team 14 where both forms are identical.

For a single-digit team, is the Blue Team VPN `198.19.5.0/24` or `198.19.05.0/24`? Same for `25.X.0.0/16` and the IPv6 groups.

A leading zero in an IPv4 octet is at best unconventional and at worst parsed as octal, so the padded form is unlikely in addresses — but the annex text says `XX` and uses `XX` in addresses. **Cheapest resolution: one config export from any single-digit team.**

---

## Q4 — DCM27 baseline stability · Needed

Will DCM27 ship the same pre-loaded aliases and rules? The DCM26 aliases carry `<detail>` timestamps from November 2023, so the baseline has survived at least three exercise years — inference, not confirmation.

If it changes, the design still works: changed items surface in triage as structural matches. But the team should expect a triage pass on day one rather than a clean ingest.

**Related, and worth doing regardless:** report the `Routers` alias IPv6 defect (F1) to Green Team. It affects every team, and fixing it upstream is better than every team working around it. If they fix it, `V-BASELINE-DRIFT` will fire — expected and fine.

---

## Q5 — Elastic component addressing and ports · Needed

The example policy uses stock ports (Fleet 8220, Elasticsearch 9200, Logstash 5044, Kibana 5601) and invented host addresses. Confirm actual values, and whether Elasticsearch sits behind a proxy on 443.

**Also:** what do Tines playbooks reach out to? SOAR enrichment and response actions may need egress into enclaves nobody has considered, and it is easy to strangle with a default-deny.

---

## Q6 — Is the tool permitted, and does the Green Team role complicate it? · Needed

**Ask the exercise lead, unprompted and early.**

Blue Teams bringing preparation tooling is normally unremarkable. The wrinkle is authorship on both sides — Green Team for range development, while the unit fields a Blue Team.

The line that keeps this clean: **built from Blue Team Information Book content only.** Enclave structure, addressing, host inventories, the ISA board and the pre-loaded firewall baseline are all material Blue Teams legitimately receive. Nothing from the Green Team build repository, scoring check *definitions* held GT-side, or GT-only access.

Cheap to raise now. Expensive if someone else raises it later.

---

## Q7 — Where does the tool run? · Nice

Off-range on team kit, generating files carried in, is the assumption throughout and needs no permission. Revisit only if that proves impractical. Reachability *from inside* the range during play would be a Green Team build request and a different conversation.

---

## Q8 — Interface role vocabulary · CLOSED

Recovered from the gov, mil, bank and mcu configs:

```
wan, ws, svrs, dmz, uav, scada, power, sat, port1, port2, stbd1, stbd2
```

`mcu` also revealed the straddle case — WAN on the Host Nation side, internal segments in deployed space — so `estate_side` is derived from the WAN address, never from internal ranges.

Only HNDC (Host Nation Data Centre) remains unseen. It is referenced by Annex G as a dependency target and appears on the ISA board (`PLC.HVAC.HNDC`, `CAMERA1.CCTV.HNDC`, `CRYPTONODE.SWIFT.HNDC`, `SIMULATOR01.DRS.HNDC`, `FW2.HNDC`, `DNS2.HNDC`). An annex or config export would let its roles be added properly.

---

## Q9 — What is "DNMP"? · Nice

Annex G §2.6: *"Scoringbot in Host Nation Government (GOV) must be able to communicate with all DNMP systems for availability scoring purposes."*

Unexplained and unexpanded anywhere seen. Possibly an acronym from the main handbook, possibly a typo. It changes nothing operationally — the scoring bot needs to reach everything scored — but the wording should be understood before it is quoted in a template.

---

## Q10 — Which ISA checks apply to the deployed firewalls? · Needed

The board shows `fw1.mil` scored on HOST, SSH, HTTPS **and Graynet Access**. No firewall card was legible for `do`, `ds` or `dsoc`.

This matters because two DCM26 enclaves shipped `BLOCK_ALL_FW_EGRESS`, which fails a Graynet Access check outright. If deployed firewalls carry the same check, that rule was costing points.

**Resolution: read the board on day 0 and filter for the firewall targets.** Two minutes. Until then, `V-EGRESS-CHECK` assumes the check exists and warns on any firewall egress block.

---

## Q11 — FTP passive data range · Needed

`ftp.do.XX.dcm.ex` is an FTP server in the DO DMZ. pfSense has no FTP helper, so passive FTP needs the data port range opened explicitly as well as 21.

Is the server configured for passive mode, and what range does it use? No ISA check was observed against it, so this is a usersim-experience question rather than an automated-scoring one — but usersim complaints are scored.

`EVIDENCE.md` E5: the DCM26 team believed a port forward on 21 made FTP work. It did not — a wide-open WAN catch-all did.

---

## Q12 — pfSense uses two boolean conventions, and they contradict · Needed

`BASELINE-ANALYSIS.md` §1 establishes the rule the parser follows: **empty element is
false, `yes` is true, presence means nothing.** It is right for the fields it was drawn
from — `noantilockout`, `disablenatreflection`.

But the GUI appears to write rule-level flags the other way, as bare `<disabled></disabled>`
and `<log></log>`, where presence *is* the value. Under the documented rule those read as
false, and a disabled rule would be treated as live.

The parser keeps the two apart as `pf_bool()` and `pf_flag_present()` rather than one
function that guesses, so which convention a field was read under is visible at the call
site. Rule-level `<disabled>` and `<log>` currently use presence.

**Resolution: on the CE 2.8.1 box, disable a rule and enable logging on another, export,
and read what the GUI wrote.** Same box as Q2 and `MONITORING.md` Q2 — one sitting closes
all three.

Erring towards "disabled" is the safe direction: an inactive rule read as live surfaces in
triage, where a live rule read as inactive would be silently dropped from the output.
