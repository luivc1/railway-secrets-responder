---
name: rsr-inventory
description: Build the rotation list for Railway - every environment variable across all projects, environments, services and shared variables, classified by provider (Anthropic, OpenAI, Stripe, AWS, databases, GitHub, Supabase and 60+ more) and ranked, without ever showing a value. Also finds local .env copies, Railway-linked repos and Railway tokens in GitHub Actions. Use for "what do I need to rotate on Railway", "list my Railway secrets", "audit Railway variables", "qué tengo que rotar en Railway".
---

# Inventory (read-only)

Follow **rsr-navigator** rules. The tool reads values only in memory to identify the
provider and fingerprint them; reports never contain values.

## 1. Pick the input

| Option | When | Command |
|---|---|---|
| **Railway API** (best) | Covers every project, environment, service and shared variable | `RAILWAY_API_TOKEN=<set in env> python3 "$RSR/scripts/railway-audit.py" --api -o reports/railway` |
| Project token | Only one project/environment | `RAILWAY_TOKEN=... python3 ... --api --project-token` |
| Railway CLI | No API token wanted | `railway variables --json -s <service> -e <env> > cli/<service>.<env>.json` per service, then `--cli-json cli/*.json` |
| Local repos | Add to either of the above | `--local ~/code` finds .env copies, railway.json/toml links, `secrets.RAILWAY_TOKEN` in GitHub Actions |

**Token hygiene for the audit itself:** ask the user to create a **new** account token
after the disclosure (railway.com/account/tokens), set it with
`export RAILWAY_API_TOKEN=...` in their own terminal (or let the script prompt with
hidden input), and **delete that token when the response is done**. Never ask them to
paste a token into the chat; never pass it as an argument (the script refuses).

When the agent runs the CLI export, redirect to files; never let the JSON print into
the conversation.

## 2. Read the results

Outputs: `reports/railway.html` (color tracker with checkboxes), `.csv`, `.md`
(shareable checklist, no values), `.baseline.json` (salted fingerprints for
verification: keep it, it is needed by rsr-verify-close).

| Priority | Meaning |
|---|---|
| P1 | AI provider keys (named target), payments, cloud, databases, code/registry tokens, Railway tokens, email/SMS senders |
| P2 | Webhook secrets, app signing secrets (rotating logs users out), lower-impact APIs, unknown-provider secrets |
| P3 | Test keys, semi-public values (Sentry DSN) |
| REVIEW | Looks like a secret, name gives no hint: ask the owner |
| INFO | `${{Service.VAR}}` references (rotate at the source) and public/publishable values |

Grouping: the same value used in several services is one item ("rotate once, update
in N places"). A Railway database service's password and URLs are one item.

## 3. Things the tool cannot see (add them to the list)

- **Private registry credentials** set in each service's Settings (not variables).
- Secrets stored **outside Railway** that were derived from Railway values.
- Values Railway already rotated for you (Bucket credentials, per press reports).

## 4. Present

Show the P1 list as a table (provider, variable names, where, strategy). Then hand
off to **rsr-rotate**. Offer the `.md` checklist for colleagues.
