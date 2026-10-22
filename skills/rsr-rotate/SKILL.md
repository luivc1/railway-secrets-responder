---
name: rsr-rotate
description: Rotate secrets exposed by the Railway disclosure safely while builds/deploys may be paused - per-secret strategy (REVOKE-NOW, STAGE-THEN-REVOKE, CONTAIN-THEN-ROTATE for Railway databases, CONFIRM-RAILWAY-ROTATION for Buckets), provider-by-provider steps, updating Railway with --stdin --skip-deploys, and redeploy order. Use for "rotate the keys", "how do I rotate if deploys are paused", "cambiar las llaves", "rotar los secretos".
---

# Rotate (changes systems: approval required at every step)

Follow **rsr-navigator** rules. The person creates new credentials at each provider and
types them into Railway themselves; you prepare the plan and commands. Never ask for,
display or store a new value.

## 1. The core problem

A running Railway service keeps the variable values from its last deploy. If deploys
are paused (check `DEPLOY_NOTE` and status.railway.com), a new value set in Railway
does not reach the app yet. So revoking the old credential **breaks that app** until a
deploy can happen. Decide per secret (`references/deploy-pause.md`):

| Strategy | Use for | Steps |
|---|---|---|
| **REVOKE-NOW** | P1 keys where misuse costs more than downtime (AI keys, payments, cloud, code tokens) | Create new key → set in Railway with `--skip-deploys` → **revoke old now** (app may fail until redeploy) → redeploy when possible |
| **STAGE-THEN-REVOKE** | P2/P3, or P1 the owner decides cannot go down | Create new key → set with `--skip-deploys` → add guardrails on the old key (spend limit, IP restriction, lower scope) → redeploy when possible → revoke old immediately after |
| **CONTAIN-THEN-ROTATE** | Railway databases | Remove Public Access now (no deploy needed) → rotate password when deploys work |
| **CONFIRM-RAILWAY-ROTATION** | Railway Buckets | Check the bucket's Credentials tab for new values; services using references follow; redeploy when possible |

The default strategy per item comes from the audit; **the owner makes the final call**
for every REVOKE-NOW, because it can cause downtime. Many providers allow two active
keys at once, which makes STAGE-THEN-REVOKE cheap.

## 2. Per secret (repeat; P1 first, AI keys first within P1)

1. Show: provider, variable names, every location, strategy, expected impact.
2. Person creates the new credential at the provider (`references/provider-playbook.md`
   has the exact page and notes). Some keys may already be revoked by the provider at
   Railway's request: the app may already be failing, so rotate first.
3. Update each Railway location. The audit prints one command per location:
   ```bash
   railway variable set OPENAI_API_KEY --stdin --skip-deploys -e "production" -s "api"
   ```
   The person runs it in their own terminal and pastes the value at the prompt
   (stdin keeps it out of shell history). Shared variables: dashboard > Project
   Settings > Shared Variables. References (`${{...}}`) update automatically.
4. Update every other copy the audit found: local `.env` files, GitHub Actions secrets,
   other hosts (Vercel, Netlify...), teammates' machines.
5. Apply the strategy's revoke timing. Revoking is irreversible: explicit yes first.
6. Log it in `rsr-log.md` (names and times only).

## 3. When deploys are back

Redeploy every service whose variables changed (dashboard, or `railway redeploy` per
service), most critical first. Then revoke any old credentials still active
(STAGE-THEN-REVOKE). Then run **rsr-verify-close**.

## 4. Also rotate

- Private registry credentials in each service's Settings.
- The Railway token used for the audit (delete it when done) and any Railway tokens
  stored in variables or CI.
- Railway account: confirm 2FA is on; review team members and tokens at
  railway.com/account/tokens.
