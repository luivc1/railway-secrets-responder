# Rotating while Railway deploys are paused

Facts (Railway, Oct 21 2026): builds and deployments were paused during the
investigation; "until builds are restored, you will not be able to roll out new
versions". Check status.railway.com for the current state before planning.

## What still works without a deploy

- **Creating and revoking credentials at providers** (their consoles are not affected).
- **Setting Railway variables** with `--skip-deploys` (the dashboard and CLI accept
  changes; they take effect on the next deploy).
- **Networking changes**, such as removing a database's Public Access (TCP proxy).
- **Provider-side guardrails** on old keys: spend limits, usage alerts, IP/referrer
  allowlists, reduced scopes, webhook endpoint restrictions.

## Decision guide per secret

| Question | If yes |
|---|---|
| Can misuse cost money fast (AI usage, cloud, payments, SMS/email sending)? | Lean REVOKE-NOW, or add a hard spend cap to the old key right now |
| Does the key reach customer data (DB, Supabase service role, storage)? | REVOKE-NOW or contain (network restriction) now |
| Will revoking take down revenue (checkout, login)? | STAGE-THEN-REVOKE with guardrails, revoke the minute redeploy works |
| Does the provider allow 2 active keys? | Staging costs nothing: create the new one now |
| Did the provider already revoke it (Railway asked upstream providers)? | App is already failing: rotate and stage now |

Record each decision and who made it in `rsr-log.md`.

## If the outage lasts

- Some teams temporarily run the critical service elsewhere (another host) with the
  new credentials, then move back. That is a business decision with its own risks;
  present it as an option, not a recommendation.
- Keep the provider-side guardrails until the old key is revoked.
