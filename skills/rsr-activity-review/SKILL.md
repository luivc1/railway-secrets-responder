---
name: rsr-activity-review
description: Look for misuse of secrets that were stored on Railway - AI usage spikes, unexpected charges, new payment or payout activity, unknown database connections, cloud API calls, repository access - across each provider's own logs and billing, as Railway advised. Use for "were our keys abused", "check for unusual activity", "review logs after the Railway incident", "revisar actividad sospechosa", "usaron nuestras llaves".
---

# Activity Review (read-only)

Follow **rsr-navigator** rules. Railway advises reviewing logs for unusual activity. The
evidence lives at each provider, not in Railway. Look from `EXPOSED_BEFORE` minus a few
days (no exact window was published) until each key was revoked.

## Where to look, by provider (from the audit's P1/P2 list)

| Provider type | Check | Red flags |
|---|---|---|
| AI providers | Usage/billing dashboards per key or project | Spikes, new models, odd hours, usage after revocation attempts |
| Stripe | Developers > Logs (API requests by key), Events, Payouts, Connect | Requests from unknown IPs, new payout destinations, refunds, new webhooks |
| AWS / cloud | CloudTrail by access key ID, billing, new IAM users/keys | Unknown regions, new instances, new IAM principals |
| GitHub | Org/user Security log, token last used | Clones of private repos, new deploy keys, workflow changes |
| Databases | Connection logs, `pg_stat_activity`, new roles, unusual query volume | Connections from unknown IPs (public proxy), new users, dumps |
| Supabase | Auth and API logs | service_role use from unknown origins |
| Email/SMS | Sending logs, bounces, Twilio usage | Spam bursts, SMS pumping to premium numbers |
| Railway | Project activity, deployments, members, tokens | Unknown deploys, new members or tokens |
| App logs | Railway service logs | Admin actions or logins you cannot explain |

## Steps

1. For each P1 provider, the person opens the console (or grants read access via a
   connected tool) and checks the views above. Do not ask them to paste logs that
   contain secrets; ask for counts, dates, IPs and descriptions.
2. Record findings per provider: `clean`, `suspicious` (why), or `confirmed misuse`.
3. Confirmed misuse: revoke immediately regardless of downtime, contact the
   provider's support (fraud/abuse teams can often reverse charges), and preserve
   evidence (exports, screenshots).
4. Customer data possibly accessed: recommend legal advice on notification duties;
   do not give a verdict. Recommend professional incident response if data
   exposure is likely.
5. Summarize in `rsr-log.md` and the closure report.
