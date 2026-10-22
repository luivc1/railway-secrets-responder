---
name: rsr-verify-close
description: Prove every Railway secret was actually rotated by comparing current values against the saved baseline fingerprints (no values stored), confirm services redeployed and old credentials revoked, then close out. Use for "did we rotate everything", "verify the rotation", "close the Railway incident", "verificar la rotación", "confirmar que cambiamos todo".
---

# Verify and Close (read-only)

Follow **rsr-navigator** rules. For many projects or client accounts, let a separate
agent or person verify (the bundled `rsr-verifier` agent in Claude Code).

## 1. Compare against the baseline

```bash
python3 "$RSR/scripts/railway-audit.py" --api --baseline reports/railway.baseline.json -o reports/after
```
(Use the same input mode as the first run: `--api`, or fresh `--cli-json` exports.)

| Per secret | Meaning | Action |
|---|---|---|
| ROTATED | Every location has a new value | Confirm the old credential is revoked at the provider |
| NOT ROTATED | At least one location still has the old value | Finish that location (often a forgotten service or environment) |
| NEW | Not in the baseline | Added since; make sure it was created after the incident |

Exit code 4 = something is still not rotated.

The fingerprints prove the **value in Railway changed**. They do not prove the old key
was revoked or that the service redeployed; check those separately:

## 2. Closure checklist

- [ ] Audit verify: no NOT ROTATED items (or each one has a documented reason)
- [ ] Every service with changed variables redeployed after deploys were restored
- [ ] Old credentials revoked at each provider (not just replaced)
- [ ] Copies updated: local .env, GitHub Actions secrets, other hosts, teammates
- [ ] Private registry credentials rotated
- [ ] Railway Public Access re-enabled only where needed, after DB passwords rotated
- [ ] Activity review done per P1 provider (rsr-activity-review)
- [ ] Audit token deleted at railway.com/account/tokens
- [ ] `rsr-log.md` complete; clients/colleagues informed (rsr-client-comms)

## 3. Closure summary

Scope (projects, environments, number of secrets), what was rotated and when, what was
contained instead, misuse findings, open items with owners and dates. No values.
