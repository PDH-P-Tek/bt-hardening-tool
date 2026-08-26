# DCM26 Baseline — Analysis

What Green Team ships, and what the Blue Team is given to work from. Compiled 21 Aug 26, revised with the Host Nation configs and two Technical Annexes.

For what teams actually did with this baseline during the exercise, see `EVIDENCE.md`.

## Sources

| Source | What it gave |
|---|---|
| `fw1.do` / `fw1.ds` / `fw1.dsoc` pre-build configs, 9 Feb 26 | The shipped baseline: protected set, interface maps, platform facts |
| `fw1.gov` / `fw1.mil` / `fw1.mcu` / `fw1.bank` end-state configs, 11–12 Feb 26 | Host Nation interface maps and the full role vocabulary |
| BT Technical Information Book **Annex A — DO**, Rev B2 | Document structure, host inventory, connectivity requirements |
| BT Technical Information Book **Annex G — HN BANK**, Rev C1 | Confirms the annex template; reveals per-enclave variation |
| ISA **Target Checks Status** board | The scored port list — see `isa-checks.yaml` |

> **No source configuration is stored in this subfolder.** The exports contain admin and `gt` password hashes, the webConfigurator private key, the GT SSH public key and cleartext service passwords. Everything the tool needs is abstracted into this document, `seed-profile.yaml`, `isa-checks.yaml` and `service-catalogue.yaml`.

---

## 1. Platform facts

| Property | Value |
|---|---|
| Config format version | `23.3` |
| pfSense build | CE 2.8.1 |
| Outbound NAT | **Disabled** — pure routed |
| NAT reflection | Disabled |
| Anti-lockout | Enabled |
| webGUI | HTTPS |
| Filter log descriptions | `1` — the firewall log names the matching rule |
| Packages | Open-VM-Tools, FRR (OSPF + OSPFv3 + BFD on WAN), sudo |
| Upstream DNS | `10.181.0.11`, `10.181.0.12` |
| Range core services block | `10.181.0.0/16` — DNS and the ISA monitor at `10.181.2.214` |

### What the build template shows that an export does not

The Green Team build template was read directly, and it settles four things that were
inferred from exports:

| | |
|---|---|
| Floating rules bind to | `<interface>any</interface>` — **not** a comma-separated interface list |
| The account password element is | `<sha512-hash>`, not `<bcrypt-hash>` |
| `<authorizedkeys>` is | **base64-encoded**. Read as text it is one meaningless blob |
| `frrbfdpeers` and `frrospfd` sit | directly under `<installedpackages>`, as siblings of `<frr>` |

Each of those was wrong in this tool and each failed *silently*: a comma-split turned
`any` into one interface literally named "any"; the wrong password element recorded
every account as having none; the keys were invisible; and the peer list came back empty
so `V-ROUTING-PEERS` stayed quiet on every real configuration while appearing to have
run. None of them would have surfaced as an error.

Also confirmed from the template: NIC order is arbitrary and does not follow interface
order (a four-interface build maps `wan` to `vmx1` and `opt2` to `vmx0`), separators are
present from the start, `snmpd` ships with `rocommunity public`, `gt` holds a
`NOPASSWD: ALL` sudo grant, and the FRR package password is the documented default.

### Boolean encoding

```xml
<disablenatreflection>yes</disablenatreflection>   <!-- true  -->
<noantilockout></noantilockout>                    <!-- false -->
```

**Parser rule: empty element = false, `yes` = true.** Presence means nothing. Get this backwards and the tool reports anti-lockout as disabled on every real config.

---

## 2. Interface roles

Segment-to-interface assignment is **not consistent between enclaves**. Any logic keyed to `lan` / `opt1` is wrong. Fingerprints and policy use a derived role token; only emission uses the pfSense ifname.

### Full role vocabulary

```
wan, ws, svrs, dmz, uav, scada, power, sat, port1, port2, stbd1, stbd2
```

### Observed maps (team 14)

| Enclave | WAN | Internal |
|---|---|---|
| `do` | `25.14.0.10` | lan=`ws` .9.1 · opt1=`svrs` .10.1 · opt2=`dmz` .11.1 |
| `ds` | `25.14.0.12` | lan=`ws` .17.1 · opt1=`svrs` .18.1 · opt2=`uav` .19.1 · opt3=`dmz` .21.1 |
| `dsoc` | `25.14.0.14` | **lan=`svrs` .7.1** · opt1=`ws` .8.1 |
| `gov` | `10.14.0.4` | lan=`ws` .1.1 · opt1=`svrs` .2.1 · opt2=`scada` .5.1 · opt3=`dmz` .4.1 |
| `mil` | `10.14.0.20` | lan=`ws` .9.1 · opt1=`svrs` .10.1 · opt2=`sat` .11.1 · opt3=`dmz` .12.1 · opt4=`power` .13.1 |
| `bank` | `10.14.80.6` | lan=`ws` .17.1 · opt1=`svrs` .18.1 · opt2=`dmz` .21.1 |
| `mcu` | `10.14.80.16` | lan=`dmz` `25.14.26.1` · opt1=`port1` .27.1 · opt2=`port2` .28.1 · opt3=`stbd1` .29.1 · opt4=`stbd2` .30.1 |

Three traps in that table:

- **`dsoc` inverts LAN.** `lan` is the server segment. Built-in anti-lockout therefore protects servers, and analysts on `dsoc_ws` have no safety net.
- **`mcu` straddles both estates.** Its WAN is on the Host Nation side (`10.14.80.16`) while its internal segments use deployed addressing (`25.14.26–30`). Any assumption that `25.x` means deployed and `10.x` means host nation is wrong.
- **Two Host Nation WAN segments exist**: `10.14.0.0/24` (gov, mil) and `10.14.80.0/24` (bank, mcu).

NIC ordering (`vmx0`–`vmx4`) is arbitrary and differs per enclave. Never infer role from NIC number.

---

## 3. The protected set

Identical across every deployed enclave, and near-identical on Host Nation (the `Routers` alias uses `10.XX.0.x` there).

### Floating — non-quick, all interfaces, `inet46`, empty descriptions

| # | Protocol | Destination |
|---|---|---|
| 1 | tcp/udp | any:53 |
| 2 | udp | any:123 |
| 3 | icmp, `icmptype: any` | any |

Rule 3 with `inet46` expands to both `icmp` and `ipv6-icmp` with no type restriction, so all of ND, RA/RS, PTB and echo currently passes.

### WAN

| # | Source | Destination | Description |
|---|---|---|---|
| 4 | alias `Remote_Access` | any | `VPN access for exercise participants` |
| 5 | alias `Routers` | `(self)` | `Routing information exchange` |
| 6 | `(self)` | any | `Firewall outbound traffic` |
| 7 | any | any | *(empty)* — **permissive default** |

### Internal

One `pass any → any`, `inet46`, empty description, per internal interface. **Permissive defaults.**

### Aliases

**`Routers`** (host) — `25.XX.0.1/.2/.3` plus `fd81:10:XX::1/::2/::3`. See F1.

**`Remote_Access`** (network), decoded against its `<detail>` field:

| Range | Owner |
|---|---|
| `172.21.31.0/24` (+v6) | Green Team VPN |
| `198.18.128.0/24` (+v6) | White Team VPN |
| **`198.19.XX.0/24`** (+v6) | **Blue Team VPN** |
| `172.21.28.0/24` (+v6) | Green Team Local |
| `172.21.29.0/24` (+v6) | Green Team Tools |

**Lockout-critical.** Narrow or drop it and the team loses access to its own firewalls. Also the route by which Yellow Team usersims arrive (F10).

Both aliases carry `<detail>` timestamps of *14 Nov 2023* — the baseline has survived at least three exercise years largely unchanged, which is what makes a shipped seed profile worthwhile and any change to it worth surfacing loudly.

---

## 4. The Technical Annex

One per enclave, issued to Blue Teams the day before the range opens, alongside the handbook and range diagram. Two examined (A — DO, Rev B2; G — HN BANK, Rev C1) and the structure is a template:

| Section | Content | Feeds |
|---|---|---|
| 1.1 Network | Topology diagram | context |
| **1.2 Subnets and Domain Names** | Name, IPv4, IPv6, domain | interface map |
| 1.3 Credentials | Default admin password | context |
| 1.4 System User Credentials | AD accounts, credential safe | context |
| 1.5 Connectivity | RDP/VNC/SSH, VLM-Up portal | context |
| 2.1 Firewall | pfSense FQDN | firewall identity |
| 2.2–2.4 | Workstations / Servers / DMZ prose | role hints |
| **2.5 Known Device List** | Hostname, IPv4 **and IPv6**, description | host inventory |
| **2.6 Connectivity Requirements** | Within / Inbound / Outbound, in prose | starter policy |

### Per-enclave variation the parser must tolerate

| | Annex A — DO | Annex G — BANK |
|---|---|---|
| §2.5 heading | "Known devices" | "Known Device List" |
| Default password | `Admin1Admin1` | `SilentMarbleTiger903#` |
| VLM-Up portal | `vlm-up.crp.cr14.net` | `vlm-up-evs.crp.cr14.net` |
| DNS destination | to the **domain controllers** | to the **DMZ proxy** |
| Scoring bot | listed in §2.5 at `25.XX.9.254` | **not listed** — §2.6 points to GOV |
| EXCON hosts in §2.5 | `npc-server-do`, `scoringbot` | none |
| Cross-enclave deps | none | two, to Host Nation Data Centre |

**Nothing about the annex may be hardcoded.** DNS destination, scoring source and EXCON host presence all vary. The parser reads the tables; the operator confirms the prose.

Both annexes state the `X` / `XX` convention identically: `X` unpadded (1…36), `XX` zero-padded (01…46). The worked example uses team 42, so it does not disambiguate single-digit teams — see `OPEN-QUESTIONS.md` Q3.

`Admin1Admin1` being the DO default explains the FRR package password found in the DO configs. It is documented, not a Green Team slip — but it does mean FRR sits on the published default, and changing it is legitimate Blue Team work.

---

## 5. Findings

### F1 — `Routers` alias IPv6 entries are wrong *(high)*

The alias lists `fd81:10:XX::1/2/3` — the **Host Nation** prefix — on deployed enclaves. The actual peers are on `fd81:25:XX::`, as the box's own FRR BFD peer list confirms:

```xml
<frrbfdpeers>
  <config><peer>25.14.0.1</peer></config>
  <config><peer>25.14.0.2</peer></config>
  <config><peer>fd81:25:14::2</peer></config>
  <config><peer>fd81:25:14::1</peer></config>
</frrbfdpeers>
```

Rule 5 therefore does not match the IPv6 peers. Masked by rule 7 until someone removes it — the first and most obvious hardening step. BT technical rule 3 makes IPv6 availability scored.

Validators: `V-ALIAS-FAMILY`, `V-ROUTING-PEERS`. **Worth reporting to Green Team** — it affects every team.

### F2 — `dsoc` LAN inversion *(high)*

See §2. Anti-lockout protects the wrong segment on the SOC firewall.

### F3 — Floating rules are non-quick, and that is load-bearing *(high)*

pfSense emits: default block → floating → interface group → interface. pf is last-match-wins unless `quick`; interface rules are quick by default, the GT floating rules are not.

Counter-intuitively, a tight interface allow-list **does not** break DNS/NTP/ICMP — those packets fall through to the non-quick floating pass, which stands as the last match.

What breaks them is adding an explicit `block` at the end of an interface tab: quick, matches first, terminates. DNS, NTP and ICMP die silently with nothing in the config looking wrong. `EVIDENCE.md` E6 is a live instance.

**Design consequence:** generated output never relies on non-quick semantics. Every intended pass is an explicit quick rule.

### F4 — Scoring topology *(high — was blocking, now resolved)*

- **Deployed enclaves:** a local scoring bot at `<workstation_subnet>.254`. Listed in Annex A §2.5, Out of Bounds, "Not shown on diagram". Checks against servers and DMZ therefore cross the firewall as `ws→svrs` and `ws→dmz`.
- **Host Nation enclaves:** served from GOV. Annex G §2.6 — *"Scoringbot in Host Nation Government (GOV) must be able to communicate with all DNMP systems."* Observed at `10.XX.1.254`.
- **Central monitor** at `10.181.2.214`, in the range core services block.

Full detail in `isa-checks.yaml`.

### F5 — IPv6 ICMP narrowing *(medium)*

Minimum preserve set: 133/134 (RS/RA), 135/136 (ND), 2 (Packet Too Big — PMTUD), 128/129 (echo, used by the ISA `HOST` check). Validator `V-ICMP6-MINIMUM`.

### F6 — Baseline internal inconsistencies *(low)*

`ds` OSPF router-id `25.14.0.12` vs OSPFv3 `25.14.0.16`; `dsoc` `.14` vs `.17`; `do` self-consistent. `Routers` description says "r1 and r2" but holds three addresses.

Establishes that the GT baseline is not authoritative reference data. Validate against it; do not trust it.

### F7 — Non-firewall items visible in the same files *(out of scope, worth raising)*

FRR package password on the documented default; `snmpd` block with `rocommunity: public` and no `<enable>`; `sudo` grants `gt` NOPASSWD ALL (out of bounds to modify).

### F8 — EXCON hosts sit inside the workstation segment *(high)*

Annex A DO §2.5:

| Host | Address | Note |
|---|---|---|
| `scoringbot` | `25.XX.9.254` / `fd81:25:XX:9::254` | EXCON, Out of Bounds, not on the diagram |
| `npc-server-do` | `25.XX.9.249` | EXCON, Out of Bounds |

Both are **inside** the workstation subnet. A team tightening the workstation segment — exactly what they are there to do — kills scoring and the usersim engine from the inside. Neither appears on the range diagram.

Annex A §2.2 on the NPC server: *"communications must be maintained through your firewall to external networks to avoid affecting your score."* Its egress is a scored obligation.

### F9 — The firewall is itself a scored target *(high)*

The ISA board shows `fw1.mil` checked on HOST, SSH, HTTPS **and "Graynet Access"**.

Two consequences: a management lockdown must permit the scoring source to reach 22 and 443 on the firewall, and an egress block on the firewall fails Graynet Access outright. Two DCM26 enclaves shipped `BLOCK_ALL_FW_EGRESS` (`EVIDENCE.md` E6).

Validator `V-EGRESS-CHECK`.

### F10 — Yellow Team is not named in `Remote_Access` *(medium)*

Both annexes require YT usersims to reach workstations by RDP/SSH "via their range VPN". The `Remote_Access` `<detail>` field decodes to GT/WT/BT VPN plus GT Local and GT Tools — no Yellow Team entry.

YT most likely rides the White Team range. Preserving `Remote_Access` intact covers it either way, which is the practical answer; confirming it is still worth five minutes with GT.

### F11 — NAT is in scope after all *(high)*

The baseline runs `<nat><outbound><mode>disabled</mode>` with no port forwards. Teams switched it to `hybrid` and added forwards (`EVIDENCE.md` E5). On a routed range that is unnecessary and risks rewriting source addresses on scored paths.

The tool must ingest, classify and preserve `<nat>`, and treat a mode change as blocking. Validator `V-NAT-MODE-CHANGED`.

### F12 — ISA is the port list *(high)*

The annexes give no port numbers. The ISA Target Checks Status board gives them precisely, per target, and is visible to Blue Teams from day one. Reading it is the highest-value five minutes available at the start of the exercise.

Captured in `isa-checks.yaml`. This closes the unknown-ports problem for everything that is scored; `service-catalogue.yaml` covers what services additionally *need* to function.

---

## 6. What this means for the tool

1. The hardening job is **replacing four to seven catch-all rules per firewall**. Everything else in the baseline is kept.
2. Six rules and two aliases form the protected set, stable across enclaves and years. Two aliases and one rule are lockout-critical.
3. Descriptions are unreliable identity — three of the six protected rules have none, and one baseline rule was later widened while keeping its label. Identity comes from a normalised semantic fingerprint.
4. Documentation gives inventory and intent; ISA gives ports; the config gives the baseline rules. All three cross-validate, and disagreement between them is itself a finding.
5. The baseline contains latent defects (F1) that only bite once a team starts working correctly. Catching that class of thing is the tool's core value.
