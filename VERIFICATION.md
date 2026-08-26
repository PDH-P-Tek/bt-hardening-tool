# Verification

How the tool proves a ruleset does what the policy said, rather than what it looks like it says.

The core idea: the tool already knows the intended policy and the ISA check set, so it can generate an **expected-results manifest** — for each source position, which host:port pairs should answer and which should not. Run the probe, import the results, get a pass/fail table.

That turns the firewall into something with a test suite, and produces the evidence annex for the post-exercise write-up as a by-product.

---

## Three distinct uses

They share a code path and have very different value.

### A · Pre-generation discovery — optional

Finds services the annex does not mention. Both annexes call §2.6 "a high-level guide", so there will be listeners it omits.

Use it narrowly, against the hosts in the `unverified` tier — `apj`, `modgpt`, anything bespoke. Not an estate sweep.

```
nmap -sV -p- -T3 <unverified hosts>
```

Prefer two cheaper sources first (see **Closing unverified services** below).

### B · Post-apply verification — the valuable one

The reason to build any of this. Confirms the applied ruleset matches the declared intent, per source position.

### C · Drift check — free once B exists

Re-run B's manifest later. A listener that was not there before is a possible Red persistence indicator; a check that has started failing is a scoring problem. Same code, different meaning.

---

## The manifest

Generated from the policy and the ISA check set. One manifest per **source position**, because a rule permitting `ws → svrs:445` can only be tested from the workstation segment.

```yaml
manifest:
  firewall: fw1.do.14.dcm.ex
  generated_from: phase1-baseline.yaml
  policy_sha256: 9c1b…4f2a
  position:
    segment: ws
    note: "Run from any workstation-segment host"
  assertions:
    - { target: "25.14.10.11", port: 53,   proto: tcp, expect: open,   why: "ISA check: dc01 DNS" }
    - { target: "25.14.10.11", port: 445,  proto: tcp, expect: open,   why: "ISA check: dc01 SMB" }
    - { target: "fd81:25:14:10::11", port: 53, proto: tcp, expect: open, why: "ISA check: dc01 DNS (v6)" }
    - { target: "25.14.10.25", port: 443,  proto: tcp, expect: open,   why: "ISA check: mail HTTPS (OWA)" }
    - { target: "25.14.10.25", port: 3306, proto: tcp, expect: closed, why: "Not in policy" }
    - { target: "25.14.11.22", port: 21,   proto: tcp, expect: open,   why: "Policy: ftp" }
```

Three rules for a good manifest:

- **Every ISA check becomes an `expect: open` assertion.** These are non-negotiable — a failure is points lost.
- **Every assertion exists in both address families.** A v4-only pass is a partial pass. IPv6 asymmetry is the single most common silent failure in this estate.
- **Include `expect: closed` assertions.** Proving something is shut is the half people skip, and it is the half that catches a catch-all you thought you removed.

---

## Running it

The tool emits both an nmap command and a PowerShell script per position. Use whichever suits where you are standing — most DO and BANK workstations are Windows and will not have nmap.

### nmap

```
nmap -Pn -T3 -p 53,445,443,3306 25.14.10.11 25.14.10.25 -oX verify-ws.xml
nmap -6 -Pn -T3 -p 53,445 fd81:25:14:10::11 -oX verify-ws-v6.xml
```

Import the XML; the tool renders the pass/fail table.

### PowerShell

```powershell
# BTHT verification — DO / ws position — generated from phase1-baseline.yaml
$assertions = @(
  @{ Target='25.14.10.11';       Port=53;   Want=$true;  Why='ISA: dc01 DNS' }
  @{ Target='25.14.10.11';       Port=445;  Want=$true;  Why='ISA: dc01 SMB' }
  @{ Target='fd81:25:14:10::11'; Port=53;   Want=$true;  Why='ISA: dc01 DNS (v6)' }
  @{ Target='25.14.10.25';       Port=443;  Want=$true;  Why='ISA: mail HTTPS (OWA)' }
  @{ Target='25.14.10.25';       Port=3306; Want=$false; Why='Not in policy' }
)

$results = $assertions | ForEach-Object {
    $r = Test-NetConnection -ComputerName $_.Target -Port $_.Port -WarningAction SilentlyContinue
    [pscustomobject]@{
        Target = "$($_.Target):$($_.Port)"
        Why    = $_.Why
        Open   = $r.TcpTestSucceeded
        Result = if ($r.TcpTestSucceeded -eq $_.Want) { 'PASS' } else { 'FAIL' }
    }
}

$results | Format-Table -AutoSize
$results | Where-Object Result -eq 'FAIL' | Export-Csv .\btht-failures.csv -NoTypeInformation
"{0}/{1} passed" -f ($results | Where-Object Result -eq 'PASS').Count, $results.Count
```

Two things worth knowing about `Test-NetConnection`: it performs a real TCP handshake rather than a ping, so it distinguishes "firewall blocked it" from "host is down"; and it reports the source interface and route it used, which tells you whether traffic even took the path you expected. `-WarningAction SilentlyContinue` suppresses the per-failure warning block — without it, every expected-closed port prints a paragraph and the table becomes unreadable.

Passing an IPv6 literal forces the v6 path explicitly. That is the only reliable way to prove both families work rather than assuming.

For ICMP assertions (the ISA `HOST` check), `Test-Connection -TargetName <host> -Count 2` covers v4, and `-IPv6` forces the v6 path.

---

## Guardrails — build these, do not rely on discipline

**Scan targets are hard-limited to the team's own declared subnets.** The tool refuses to emit a command against anything outside them. Scanning Host Nation networks you are not responsible for, or another team's space, is a hostile act under RoE — scoring penalty plus HICON action. This is exactly the mistake someone makes at speed by pasting the wrong CIDR, so the tool should make it impossible rather than discouraged.

**It will light up your own SIEM.** Elastic will alert and Endace captures everything. Log the start time and tell the SOC cell, or your analysts spend twenty minutes chasing you.

**Timing.** Best windows are the setup period before exercise start and immediately after each apply. Scanning during active Red operations muddies your own detection baseline for no benefit.

**Conservative rates.** `-T3` at most. Skip aggressive service probes unless closing an unverified service. Availability checks are running throughout.

---

## Closing unverified services

Ranked by cost. Reach for scanning last.

**1 · ISA check definitions.** If a host has ISA checks, those are the scored ports and you already have them. Free.

**2 · Watch the firewall.** With the permissive baseline still live, **Diagnostics → States** and **Status → System Logs → Firewall** show what is genuinely connecting. Since `<filterdescriptions>` is on, the log names the matching rule. Half an hour with usersims active tells you more than a scan, because it shows the **client** side too — which ports things actually use, not just which are listening.

**3 · Targeted nmap.** Only the specific unknown hosts, and only after 1 and 2.

Once the real ports are known, update the service entry, regenerate, re-verify. `V-UNVERIFIED-SERVICE` stops reporting and the amber goes away.

---

## Output

Every verification run is stored against the policy file: manifest, raw results, pass/fail, timestamp, position, operator.

That gives you three things — a record that the ruleset was verified rather than assumed, a baseline to diff later runs against for drift, and the evidence section of the post-exercise write-up without writing it twice.
