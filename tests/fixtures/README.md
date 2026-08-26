# Fixtures

**Hand-built and sanitised. No range configuration is stored here** — `SPEC.md` §10.1.

Everything in `baseline/` reproduces the *structure* of a shipped Green Team
baseline, with placeholder addressing on team **42** — the annexes' own worked
example, so no real team's addressing appears. `BASELINE-ANALYSIS.md` and
`seed-profile.yaml` contain everything needed to construct more.

| File | What it is for |
|---|---|
| `baseline/do-baseline.xml` | A standard deployed enclave: `lan`=ws, `opt1`=svrs, `opt2`=dmz. The reference shape |
| `baseline/dsoc-baseline.xml` | **The inversion.** `lan` is servers, `opt1` is workstations — F2 |
| `baseline/mcu-baseline.xml` | **The straddle.** WAN on Host Nation, internals in deployed space — §2 |
| `credentials/synthetic-secrets.xml` | Deliberately credential-shaped. Proves the parser *drops* secrets rather than being assumed to |

## The faults are the point

The baseline fixtures carry the defects the tool exists to find, and they are
there on purpose:

- The `Routers` alias lists the Host Nation IPv6 prefix on a deployed enclave, so
  the routing rule never matches the real v6 peers (**F1**).
- The floating rules are non-quick, which is currently load-bearing (**F3**).
- Every interface, WAN included, ends on `pass any → any` (**E1**).
- Anti-lockout is enabled and encoded as an empty element, which reads as *false*
  to anyone who assumes presence means true (**§1**).

`tests/test_fixtures.py` asserts each of those is still present. If a fixture is
ever tidied into good behaviour it stops defending anything, and nothing else in
the suite would notice.

## The credentials directory

It is the one path exempt from the secret-exclusion scan, because its whole
purpose is to contain credential-shaped material. The exemption is guarded: every
file there must carry the marker `SYNTHETIC-TEST-CREDENTIAL-NOT-REAL`, so a real
secret cannot be dropped in quietly. Every value in it is invented and
corresponds to nothing.
