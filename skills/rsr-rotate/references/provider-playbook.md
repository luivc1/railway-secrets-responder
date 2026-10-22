# Provider rotation playbook

The person does every step in the provider console. Menus change: if a path differs,
use the provider's own docs. "2 keys" = the provider allows a new and an old key to
be active at the same time (enables STAGE-THEN-REVOKE).

## AI providers (P1, rotate first)

| Provider | Where | Notes |
|---|---|---|
| Anthropic | console.anthropic.com > Settings > API Keys | 2 keys. Check Usage for spikes; set workspace spend limits |
| OpenAI | platform.openai.com > API keys | 2 keys. Check Usage; set project budgets/limits |
| Google Gemini / AI Studio | aistudio.google.com/apikey (or Cloud Console > Credentials) | Restrict the key to the Generative Language API |
| OpenRouter | openrouter.ai > Settings > Keys | Per-key credit limits available |
| Groq, xAI, Mistral, DeepSeek, Together, Fireworks, Perplexity, Cohere | Each console's API keys page | Check usage/billing for the exposure window |
| Hugging Face | huggingface.co > Settings > Access Tokens | Use fine-grained tokens |
| Replicate, ElevenLabs, Pinecone | Account > API tokens | Check usage |

## Payments

| Provider | Where | Notes |
|---|---|---|
| Stripe secret/restricted key | Dashboard > Developers > API keys > Roll key | Stripe can keep the old key valid for a chosen period: use that for STAGE-THEN-REVOKE. Review Developers > Logs and Events |
| Stripe webhook secret | Developers > Webhooks > endpoint > Roll secret | Same expiry option for the old secret |
| Clerk | Dashboard > API Keys | Rotating secret key; review sessions |
| Lemon Squeezy, PayPal | Settings > API | Review recent orders/payouts |

## Cloud, storage, code

| Item | Where | Notes |
|---|---|---|
| AWS access key | IAM > Users > Security credentials | 2 keys per user: create new, deactivate old, delete after redeploy. Check CloudTrail |
| Cloudflare / R2 | dash.cloudflare.com > API Tokens / R2 > Manage tokens | Roll token |
| Google service account | IAM > Service accounts > Keys | Add new key, delete old |
| Railway Buckets | Bucket > Credentials tab | Press reports: Railway rotates these itself. Confirm new values |
| GitHub token | Settings > Developer settings > Tokens | Prefer fine-grained; review Security log |
| npm token | npmjs.com > Access Tokens | Check recent publishes |
| Registry (Docker Hub, GHCR, ECR) | Registry account | Update Railway service Settings > private registry |
| Railway tokens | railway.com/account/tokens, project Settings > Tokens | Delete old, create new, update CI secrets |

## Databases

| Item | Where | Notes |
|---|---|---|
| Railway Postgres/MySQL/Redis/Mongo | DB service > Settings > Networking (Public Access) | Contain first. Then change the password in the DB and in the service's password variable; redeploy referencing services |
| Supabase | Project Settings > Database (reset password) and API keys (rotate service-role/secret) | New `sb_secret_` keys can be rotated individually |
| Neon, PlanetScale, Atlas, Upstash | Each console: reset role/user password | Check connection logs |

## Email, messaging, business apps

| Item | Where | Notes |
|---|---|---|
| Resend, SendGrid, Postmark, Mailgun, Brevo | API keys page | Check sending logs for spam |
| SMTP passwords | Email provider | App passwords where possible |
| Twilio | Console > API keys & tokens | Check usage for SMS pumping |
| Slack / Discord webhooks | Recreate the webhook | Old URL must be deleted |
| Telegram bot | @BotFather `/revoke` | |
| Notion, Airtable, HubSpot, Zoho, Linear | Integration/token settings | |
| Brokerage/data APIs (Alpaca, IBKR, Kraken, Polygon, Unusual Whales...) | Each API key page | Check recent orders and withdrawals first |

## App secrets (yours)

| Item | How | Impact |
|---|---|---|
| JWT/session/NextAuth/Better Auth secret | New random value (`openssl rand -base64 32`) | Logs everyone out |
| Encryption keys (N8N_ENCRYPTION_KEY, APP_KEY...) | Needs a re-encrypt/migration plan | Rotating blindly can make stored data unreadable |
| Webhook verification secrets you issued | New value, update the sender too | |
