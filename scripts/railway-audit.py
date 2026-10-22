#!/usr/bin/env python3
"""
railway-audit  v1.0.0  (railway-secrets-responder)

Inventory every secret stored in Railway, identify which provider it belongs to,
rank what to rotate first, and verify later that each one was actually rotated.

Built for the Railway security disclosure of October 21 2026 (customer
environment variables possibly accessed). Python 3.8+ standard library only.

SECRET VALUES ARE NEVER PRINTED, WRITTEN TO DISK, OR PUT ON A COMMAND LINE.
Reports show variable names, providers, locations and rotation links only.
Values live in memory just long enough to classify and fingerprint them.

USAGE
  # 1) Railway API (recommended): every project, environment, service, shared var
  export RAILWAY_API_TOKEN=...        # account or workspace token (railway.com/account/tokens)
  python3 railway-audit.py --api -o reports/railway
  #   no env var set? you are prompted (hidden input). Never pass tokens as arguments.
  #   project token instead:  RAILWAY_TOKEN=... python3 railway-audit.py --api --project-token
  #   extra workspace:        --workspace <id>      only some projects: --project <id> (repeatable)

  # 2) Railway CLI output (no API token needed)
  railway variables --json -s api -e production > cli/api.production.json
  python3 railway-audit.py --cli-json cli/*.json -o reports/railway

  # 3) Local repos linked to Railway (railway.json/toml, ~/.railway links, .env files,
  #    GitHub workflows using RAILWAY_TOKEN). Combine with 1 or 2 to find every
  #    place a rotated secret must also be updated.
  python3 railway-audit.py --api --local ~/code -o reports/railway

  # 4) Verify rotation later: compare with the fingerprints saved by an earlier run
  python3 railway-audit.py --api --baseline reports/railway.baseline.json -o reports/after

OUTPUTS   <out>.html (rotation tracker)  <out>.csv  <out>.md (shareable checklist)
          <out>.baseline.json (salted, truncated fingerprints; no secret values)
EXIT      0 nothing to rotate, 1 only review items, 2 secrets to rotate,
          3 usage/auth error, 4 verify: some secrets NOT rotated yet
"""

import argparse, csv, getpass, glob, hashlib, hmac, html, json, os, re, secrets as pysecrets
import sys, time, urllib.error, urllib.request
from datetime import datetime, timezone

VERSION = "1.0.0"
API_URL = "https://backboard.railway.com/graphql/v2"
HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_ADVISORY = os.path.join(HERE, "..", "advisories", "railway-2026-10-21.env")

# ----------------------------------------------------------------------------
# Terminal colors
# ----------------------------------------------------------------------------
TTY = sys.stdout.isatty()
def c(code, s): return f"\033[{code}m{s}\033[0m" if TTY else s
RED, YEL, GRN, CYA, DIM, BLD = (lambda s: c("31", s)), (lambda s: c("33", s)), (lambda s: c("32", s)), \
                               (lambda s: c("36", s)), (lambda s: c("2", s)), (lambda s: c("1", s))

def die(msg, code=3):
    print(RED("error: ") + msg, file=sys.stderr)
    sys.exit(code)

# ----------------------------------------------------------------------------
# Advisory
# ----------------------------------------------------------------------------
def load_advisory(path):
    adv = {}
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                m = re.match(r'^\s*([A-Z_]+)\s*=\s*"(.*)"\s*$', line)
                if m: adv[m.group(1)] = m.group(2)
    except OSError:
        die(f"advisory file not readable: {path}")
    return adv

# ----------------------------------------------------------------------------
# Provider rules: (id, label, category, priority, value_regex, name_regex, rotate_url, strategy_hint)
# Checked in order; value regex wins over name regex. P1 rotate now, P2 rotate
# soon, P3 low impact / test keys, INFO no rotation needed.
# ----------------------------------------------------------------------------
AI = "AI provider"
RULES = [
    # --- AI inference providers (P1: named target of the campaign) ---------
    ("anthropic", "Anthropic API key", AI, "P1", r"^sk-ant-", r"ANTHROPIC|CLAUDE", "https://console.anthropic.com/settings/keys"),
    ("openrouter", "OpenRouter key", AI, "P1", r"^sk-or-", r"OPENROUTER", "https://openrouter.ai/settings/keys"),
    ("openai", "OpenAI API key", AI, "P1", r"^sk-(proj|svcacct|admin)-", r"OPENAI", "https://platform.openai.com/api-keys"),
    ("groq", "Groq API key", AI, "P1", r"^gsk_", r"GROQ", "https://console.groq.com/keys"),
    ("xai", "xAI API key", AI, "P1", r"^xai-", r"XAI|GROK", "https://console.x.ai"),
    ("perplexity", "Perplexity API key", AI, "P1", r"^pplx-", r"PERPLEXITY", "https://www.perplexity.ai/settings/api"),
    ("huggingface", "Hugging Face token", AI, "P1", r"^hf_", r"HUGGING|HF_TOKEN", "https://huggingface.co/settings/tokens"),
    ("replicate", "Replicate API token", AI, "P1", r"^r8_", r"REPLICATE", "https://replicate.com/account/api-tokens"),
    ("fireworks", "Fireworks AI key", AI, "P1", r"^fw_", r"FIREWORKS", "https://fireworks.ai/account/api-keys"),
    ("deepseek", "DeepSeek API key", AI, "P1", None, r"DEEPSEEK", "https://platform.deepseek.com/api_keys"),
    ("mistral", "Mistral API key", AI, "P1", None, r"MISTRAL", "https://console.mistral.ai/api-keys"),
    ("cohere", "Cohere API key", AI, "P1", None, r"COHERE", "https://dashboard.cohere.com/api-keys"),
    ("together", "Together AI key", AI, "P1", None, r"TOGETHER", "https://api.together.ai/settings/api-keys"),
    ("gemini", "Google Gemini / AI Studio key", AI, "P1", None, r"GEMINI|GOOGLE_AI|GOOGLE_GENERATIVE|GENAI", "https://aistudio.google.com/apikey"),
    ("elevenlabs", "ElevenLabs API key", AI, "P1", None, r"ELEVEN", "https://elevenlabs.io/app/settings/api-keys"),
    ("pinecone", "Pinecone API key", AI, "P1", r"^pcsk_", r"PINECONE", "https://app.pinecone.io"),
    ("langsmith", "LangSmith key", AI, "P2", r"^lsv2_", r"LANGSMITH|LANGCHAIN", "https://smith.langchain.com/settings"),
    ("openai-generic", "OpenAI-style key (sk-)", AI, "P1", r"^sk-[A-Za-z0-9_-]{20,}$", r"OPENAI|LLM|AI_API|_AI_KEY", "Check which provider issued it (OpenAI, DeepSeek, Moonshot, others use sk-)"),
    # --- Payments ---------------------------------------------------------
    ("clerk", "Clerk secret key", "Auth", "P1", None, r"CLERK.*SECRET|CLERK_SECRET", "https://dashboard.clerk.com (API Keys)"),
    ("stripe-live", "Stripe live secret key", "Payments", "P1", r"^(sk|rk)_live_", r"STRIPE", "https://dashboard.stripe.com/apikeys"),
    ("stripe-webhook", "Stripe webhook signing secret", "Payments", "P2", r"^whsec_", r"STRIPE.*WEBHOOK|WEBHOOK_SECRET", "https://dashboard.stripe.com/webhooks (roll secret)"),
    ("stripe-test", "Stripe test key", "Payments", "P3", r"^(sk|rk)_test_", None, "https://dashboard.stripe.com/test/apikeys"),
    ("lemonsqueezy", "Lemon Squeezy API key", "Payments", "P1", None, r"LEMON", "https://app.lemonsqueezy.com/settings/api"),
    ("paypal", "PayPal client secret", "Payments", "P1", None, r"PAYPAL.*SECRET", "https://developer.paypal.com/dashboard/applications"),
    # --- Cloud ------------------------------------------------------------
    ("aws-key-id", "AWS access key ID (pair with its secret)", "Cloud", "P1", r"^(AKIA|ASIA)[A-Z0-9]{16}$", None, "https://console.aws.amazon.com/iam/home#/security_credentials"),
    ("aws-secret", "AWS / S3-compatible secret key", "Cloud", "P1", None, r"AWS_SECRET|S3_SECRET|SECRET_ACCESS_KEY|R2_SECRET|SPACES_SECRET", "AWS IAM, Cloudflare R2, DigitalOcean Spaces or your S3 provider (if this is a Railway Bucket, Railway reports rotating it)"),
    ("gcp-sa", "Google Cloud service account key", "Cloud", "P1", r'"type"\s*:\s*"service_account"', r"GOOGLE_APPLICATION_CREDENTIALS|GCP_.*KEY|SERVICE_ACCOUNT", "https://console.cloud.google.com/iam-admin/serviceaccounts"),
    ("google-api", "Google API key (Maps/Firebase/Gemini)", "Cloud", "P2", r"^AIza[0-9A-Za-z_-]{35}$", None, "https://console.cloud.google.com/apis/credentials"),
    ("azure", "Azure key or connection string", "Cloud", "P1", r"AccountKey=|SharedAccessKey=", r"AZURE.*(KEY|SECRET|CONNECTION)", "https://portal.azure.com"),
    ("cloudflare", "Cloudflare API token", "Cloud", "P1", None, r"CLOUDFLARE|CF_API", "https://dash.cloudflare.com/profile/api-tokens"),
    ("vercel", "Vercel token", "Cloud", "P1", None, r"VERCEL_TOKEN", "https://vercel.com/account/tokens"),
    ("private-key", "Private key (PEM)", "Cloud", "P1", r"-----BEGIN [A-Z ]*PRIVATE KEY-----", r"PRIVATE_KEY", "Reissue the key pair where it is used (cloud, JWT signing, SSH, Apple/Firebase)"),
    # --- Code and deploy platforms ----------------------------------------
    ("github", "GitHub token", "Code", "P1", r"^(ghp_|gho_|ghu_|ghs_|ghr_|github_pat_)", r"GITHUB_TOKEN|GH_TOKEN|GITHUB_PAT", "https://github.com/settings/tokens"),
    ("gitlab", "GitLab token", "Code", "P1", r"^glpat-", r"GITLAB", "https://gitlab.com/-/user_settings/personal_access_tokens"),
    ("npm", "npm token", "Code", "P1", r"^npm_", r"NPM_TOKEN", "https://www.npmjs.com/settings/~/tokens"),
    ("railway", "Railway API/project token", "Code", "P1", None, r"^RAILWAY_(API_)?TOKEN$|RAILWAY.*TOKEN", "https://railway.com/account/tokens (and project Settings > Tokens)"),
    ("registry", "Container registry credential", "Code", "P1", None, r"DOCKER.*(PASS|TOKEN)|REGISTRY.*(PASS|TOKEN)|GHCR|ECR_", "Your registry (Docker Hub, GHCR, ECR...). Also update Railway service Settings > private registry"),
    # --- Databases (Railway named database credentials) -------------------
    ("db-railway", "Railway-managed database credential", "Database", "P1", r"^(postgres(ql)?|mysql|mongodb(\+srv)?|rediss?)://[^:/@\s]+:[^@\s]+@[^/\s]*(railway\.internal|rlwy\.net|railway\.app)", None, "Railway DB: change the password inside the database (e.g. ALTER USER ... PASSWORD), set the same value in the DB service password variable (PGPASSWORD/POSTGRES_PASSWORD, MYSQLPASSWORD, REDISPASSWORD, MONGOPASSWORD); referencing services pick it up on their next deploy. Meanwhile consider turning off Settings > Networking > Public Access"),
    ("db-external", "External database credential", "Database", "P1", r"^(postgres(ql)?|mysql|mariadb|mongodb(\+srv)?|rediss?|amqps?|mssql|sqlserver|clickhouse)://[^:/@\s]*:[^@\s]+@", None, "Your database host (Neon, Supabase, PlanetScale, MongoDB Atlas, Upstash, CloudAMQP...): reset the user's password"),
    ("db-password", "Database password", "Database", "P1", None, r"(PG|POSTGRES|MYSQL|MONGO|REDIS|DB|DATABASE)_?PASS(WORD)?$|^PGPASSWORD$", "Your database host: reset this user's password"),
    # --- Auth / BaaS --------------------------------------------------------
    ("supabase-secret", "Supabase service-role / secret key", "Auth", "P1", r"^(sbp_|sb_secret_)", r"SUPABASE.*(SERVICE|SECRET)", "https://supabase.com/dashboard/project/_/settings/api-keys"),
    ("firebase-admin", "Firebase admin credential", "Auth", "P1", None, r"FIREBASE.*(PRIVATE|ADMIN|SECRET)", "https://console.firebase.google.com (Project settings > Service accounts)"),
    ("auth0", "Auth0 client secret", "Auth", "P1", None, r"AUTH0.*SECRET", "https://manage.auth0.com"),
    ("oauth-secret", "OAuth client secret", "Auth", "P1", None, r"(GOOGLE|GITHUB|DISCORD|APPLE|FACEBOOK|MICROSOFT|AZURE_AD|TWITTER|LINKEDIN)_CLIENT_SECRET|OAUTH.*SECRET|CLIENT_SECRET", "The identity provider's developer console (regenerate client secret)"),
    # --- Messaging / email / SMS ---------------------------------------------
    ("slack", "Slack token or webhook", "Messaging", "P2", r"^xox[abposr]-|^xapp-|hooks\.slack\.com/services/", r"SLACK", "https://api.slack.com/apps"),
    ("discord-webhook", "Discord webhook URL", "Messaging", "P2", r"discord(app)?\.com/api/webhooks/", None, "Discord channel settings > Integrations > Webhooks (delete and recreate)"),
    ("discord-bot", "Discord bot token", "Messaging", "P1", None, r"DISCORD.*TOKEN", "https://discord.com/developers/applications (Bot > Reset Token)"),
    ("telegram", "Telegram bot token", "Messaging", "P1", r"^\d{8,10}:[A-Za-z0-9_-]{35}$", r"TELEGRAM", "Telegram @BotFather: /revoke"),
    ("twilio", "Twilio credential", "Messaging", "P1", r"^SK[0-9a-fA-F]{32}$", r"TWILIO.*(TOKEN|SECRET|KEY)", "https://console.twilio.com (API keys & tokens)"),
    ("sendgrid", "SendGrid API key", "Email", "P1", r"^SG\.[\w-]{16,}\.[\w-]{16,}", r"SENDGRID", "https://app.sendgrid.com/settings/api_keys"),
    ("resend", "Resend API key", "Email", "P1", r"^re_[A-Za-z0-9]{8,}", r"RESEND", "https://resend.com/api-keys"),
    ("brevo", "Brevo API key", "Email", "P1", r"^xkeysib-", r"BREVO|SENDINBLUE", "https://app.brevo.com/settings/keys/api"),
    ("mailgun", "Mailgun API key", "Email", "P1", None, r"MAILGUN", "https://app.mailgun.com/settings/api_security"),
    ("postmark", "Postmark server token", "Email", "P1", None, r"POSTMARK", "https://account.postmarkapp.com/servers"),
    ("smtp", "SMTP password", "Email", "P1", None, r"(SMTP|MAIL|EMAIL)_?(PASS|PASSWORD)$", "Your email provider: reset the SMTP password / app password"),
    # --- Business apps ------------------------------------------------------
    ("shopify", "Shopify token", "Business", "P1", r"^shp(at|ss|ca|pa)_", r"SHOPIFY", "Shopify admin > Apps > Develop apps"),
    ("notion", "Notion integration token", "Business", "P2", r"^(secret_|ntn_)", r"NOTION", "https://www.notion.so/my-integrations"),
    ("airtable", "Airtable token", "Business", "P2", r"^pat[A-Za-z0-9]{14}\.", r"AIRTABLE", "https://airtable.com/create/tokens"),
    ("hubspot", "HubSpot token", "Business", "P2", r"^pat-(na|eu)", r"HUBSPOT", "HubSpot > Settings > Private apps"),
    ("zoho", "Zoho credential", "Business", "P2", None, r"ZOHO", "https://api-console.zoho.com"),
    ("linear", "Linear API key", "Business", "P2", r"^lin_api_", r"LINEAR", "https://linear.app/settings/api"),
    ("n8n", "n8n API key / encryption key", "Business", "P1", None, r"N8N_(API_KEY|ENCRYPTION_KEY)", "n8n Settings > API (encryption key: plan a credential re-encrypt)"),
    ("unusual-whales", "Unusual Whales API key", "Business", "P2", None, r"UNUSUAL|UW_API", "https://unusualwhales.com/settings/api-dashboard"),
    ("alpaca", "Brokerage / trading API key", "Business", "P1", None, r"ALPACA|ROBINHOOD|SCHWAB|IBKR|KRAKEN|BINANCE|COINBASE|POLYGON|ALPHA_?VANTAGE|DATABENTO|KALSHI|POLYMARKET", "The brokerage/data provider's API key page (revoke, reissue, check recent orders)"),
    # --- Monitoring (low) ----------------------------------------------------
    ("sentry-auth", "Sentry auth token", "Monitoring", "P2", r"^sntrys_", r"SENTRY_AUTH", "https://sentry.io/settings/account/api/auth-tokens/"),
    ("sentry-dsn", "Sentry DSN", "Monitoring", "P3", r"^https://[0-9a-f]+@[^/]*sentry\.io/", r"SENTRY_DSN", "Sentry project > Client Keys (DSNs are semi-public; rotate if abused)"),
    # --- App signing secrets (rotating logs users out) ------------------------
    ("app-secret", "App signing / session secret", "App secret", "P2", None, r"JWT_SECRET|JWT_KEY|SESSION_SECRET|NEXTAUTH_SECRET|AUTH_SECRET|BETTER_AUTH_SECRET|COOKIE_SECRET|SECRET_KEY_BASE|DJANGO_SECRET_KEY|^SECRET_KEY$|^APP_KEY$|ENCRYPTION_KEY|SIGNING_(KEY|SECRET)|HMAC", "Generate a new random value (e.g. openssl rand -base64 32). Rotating logs users out; encryption keys need a re-encrypt plan"),
    ("webhook-secret", "Webhook signing secret", "App secret", "P2", None, r"WEBHOOK.*(SECRET|TOKEN|KEY)", "The service that sends the webhook (roll the signing secret there, then update here)"),
]
COMPILED = [(r[0], r[1], r[2], r[3], re.compile(r[4]) if r[4] else None, re.compile(r[5], re.I) if r[5] else None, r[6]) for r in RULES]

GENERIC_NAME = re.compile(r"(KEY|SECRET|TOKEN|PASSWORD|PASSWD|PASS|PWD|PRIVATE|CREDENTIAL|AUTH|DSN|SALT|CERT)", re.I)
PUBLIC_NAME = re.compile(r"^(NEXT_PUBLIC_|VITE_|PUBLIC_|REACT_APP_|EXPO_PUBLIC_|NUXT_PUBLIC_|GATSBY_)", re.I)
PUBLIC_VALUE = re.compile(r"^(pk_(live|test)_|sb_publishable_)")
REFERENCE = re.compile(r"\$\{\{\s*([^}]+?)\s*\}\}")
URL_WITH_CREDS = re.compile(r"^[a-z][a-z0-9+.-]*://[^:/@\s]*:[^@\s]+@", re.I)
# Railway-provided system variables (not secrets)
RAILWAY_SYSTEM = re.compile(r"^RAILWAY_(?!(API_)?TOKEN$)[A-Z0-9_]+$")
NON_SECRET_NAMES = re.compile(r"^(PORT|HOST|HOSTNAME|NODE_ENV|ENV|ENVIRONMENT|APP_ENV|RAILS_ENV|FLASK_ENV|DEBUG|LOG_LEVEL|TZ|LANG|NIXPACKS_.*|PYTHON_VERSION|NODE_VERSION|NPM_CONFIG_.*|CI|BASE_URL|APP_URL|PUBLIC_URL|.*_URL|.*_HOST|.*_PORT|.*_REGION|.*_BUCKET|.*_ENDPOINT|.*_ID)$", re.I)

PRIO_ORDER = {"P1": 0, "P2": 1, "P3": 2, "REVIEW": 3, "INFO": 4}
DB_RAILWAY_VALUE = re.compile(r"^(postgres(ql)?|mysql|mongodb(\+srv)?|rediss?)://[^:/@\s]+:[^@\s]+@[^/\s]*(railway\.internal|rlwy\.net|railway\.app)")
RAILWAY_DB_NOTE = ("1) Now, no deploy needed: Railway dashboard > this database service > Settings > Networking: remove Public Access if your apps "
                   "only connect over the private network (*.railway.internal). That blocks outside use of a leaked password. "
                   "2) When deploys work: change the password inside the database (e.g. ALTER USER ... PASSWORD), set the same value in this "
                   "service's password variable (PGPASSWORD/POSTGRES_PASSWORD, MYSQLPASSWORD, REDISPASSWORD, MONGOPASSWORD), and redeploy the "
                   "services that reference it. Test on a non-production environment first.")
STRATEGY_OVERRIDE = {"railway-db": "CONTAIN-THEN-ROTATE", "railway-bucket": "CONFIRM-RAILWAY-ROTATION"}
STRATEGY = {
    "P1": "REVOKE-NOW",        # exposure risk outweighs downtime: decide with the owner
    "P2": "STAGE-THEN-REVOKE",
    "P3": "STAGE-THEN-REVOKE",
    "REVIEW": "CONFIRM",
    "INFO": "NONE",
}

def entropy_ok(v):
    return len(v) >= 12 and len(set(v)) >= 8

LOCAL_HOST = re.compile(r"@(localhost|127\.0\.0\.1|0\.0\.0\.0|host\.docker\.internal|db|postgres|mysql|redis|mongo|mongodb)(:\d+)?(/|$|\?)", re.I)
AMBIGUOUS_VALUE_RULES = {"stripe-live", "stripe-test", "openai-generic", "notion", "google-api"}
GEMINI_NAME = re.compile(r"GEMINI|GENAI|GOOGLE_AI|GOOGLE_GENERATIVE", re.I)

def _name_rule(name, v, exclude=None):
    if not GENERIC_NAME.search(name):
        return None
    for rid, label, cat, prio, vre, nre, url in COMPILED:
        if rid == exclude or not nre or not nre.search(name):
            continue
        if entropy_ok(v) or cat == "Database" or rid in ("smtp", "db-password"):
            return {"provider": rid, "label": label, "category": cat, "priority": prio, "rotate": url, "basis": "name"}
    return None

def classify(name, value):
    """Return dict(provider, label, category, priority, rotate, basis) or None for non-secrets.
    Never returns or logs the value."""
    v = (value or "").strip()
    if not v or RAILWAY_SYSTEM.match(name):
        return None
    ref = REFERENCE.search(v)
    if ref:
        return {"provider": "reference", "label": f"Reference to {ref.group(1)}", "category": "Reference",
                "priority": "INFO", "rotate": f"Rotate at the source ({ref.group(1)}); this value follows it", "basis": "reference"}
    if URL_WITH_CREDS.match(v) and LOCAL_HOST.search(v):
        return None  # local development connection string
    if PUBLIC_NAME.match(name) or PUBLIC_VALUE.match(v):
        for rid, label, cat, prio, vre, nre, url in COMPILED:
            if vre and vre.search(v) and prio == "P1" and not PUBLIC_VALUE.match(v) and rid != "google-api":
                return {"provider": rid, "label": label + " (stored in a PUBLIC_ variable!)", "category": cat,
                        "priority": "P1", "rotate": url, "basis": "value"}
        return {"provider": "public", "label": "Public/publishable value", "category": "Public",
                "priority": "INFO", "rotate": "Public by design: no rotation needed", "basis": "name"}
    for rid, label, cat, prio, vre, nre, url in COMPILED:
        if vre and vre.search(v):
            hit = {"provider": rid, "label": label, "category": cat, "priority": prio, "rotate": url, "basis": "value"}
            if rid == "google-api" and GEMINI_NAME.search(name):
                g = next(r for r in COMPILED if r[0] == "gemini")
                return {"provider": "gemini", "label": g[1], "category": g[2], "priority": "P1", "rotate": g[6], "basis": "value+name"}
            if rid in AMBIGUOUS_VALUE_RULES:
                byname = _name_rule(name, v, exclude=rid)
                if byname and byname["category"] != "Database" and byname["provider"].split("-")[0] != rid.split("-")[0]:
                    best = min(prio, byname["priority"], key=lambda x: PRIO_ORDER[x])
                    byname.update({"priority": best, "basis": "value+name"})
                    return byname
            return hit
    hit = _name_rule(name, v)
    if hit:
        return hit
    if URL_WITH_CREDS.match(v):
        return {"provider": "url-creds", "label": "URL with embedded credentials", "category": "Credential",
                "priority": "P1", "rotate": "The service in the URL host: reset that user/password", "basis": "value"}
    if GENERIC_NAME.search(name) and entropy_ok(v):
        return {"provider": "unknown", "label": "Secret (provider unknown)", "category": "Other",
                "priority": "P2", "rotate": "Wherever it was issued: generate a new value there", "basis": "name"}
    if NON_SECRET_NAMES.match(name) or v.lower() in ("true", "false", "0", "1", "yes", "no") or len(v) < 12:
        return None
    if (entropy_ok(v) and re.fullmatch(r"[A-Za-z0-9_\-+/=.]{24,}", v) and re.search(r"[A-Z]", v) and re.search(r"[a-z]", v)
            and re.search(r"\d", v) and not re.fullmatch(r"[A-Za-z0-9]+([-.][A-Za-z0-9]+)+", v)
            and not re.search(r"(_MODEL|_VERSION|_NAME|_REGION|_ID|_TAG|_BRANCH|_SHA)$", name, re.I)):
        return {"provider": "unknown", "label": "High-entropy value (possible secret)", "category": "Other",
                "priority": "REVIEW", "rotate": "Confirm what it is; rotate if it is a credential", "basis": "shape"}
    return None

def mask(value, info):
    """Show only a provider's public format prefix, never secret material."""
    v = value.strip()
    if info["basis"] == "reference":
        return v  # e.g. ${{Postgres.DATABASE_URL}}: a reference, not a secret
    m = re.match(r"^(sk-ant-|sk-or-|sk-proj-|sk-svcacct-|sk-admin-|sk_live_|rk_live_|sk_test_|rk_test_|whsec_|gsk_|xai-|pplx-|hf_|r8_|fw_|pcsk_|lsv2_|ghp_|gho_|ghu_|ghs_|ghr_|github_pat_|glpat-|npm_|sbp_|sb_secret_|xox[abposr]-|xapp-|SG\.|re_|xkeysib-|shp(at|ss|ca|pa)_|secret_|ntn_|lin_api_|sntrys_|AKIA|ASIA|AIza|pk_live_|pk_test_|sk-)", v)
    if m:
        return m.group(0) + "…"
    m = re.match(r"^([a-z][a-z0-9+.-]*)://", v, re.I)
    if m:
        host = re.search(r"@([^/:?\s]+)", v)
        if host:
            return f"{m.group(1)}://user:•••@{host.group(1)}"
        h = re.match(r"^[a-z][a-z0-9+.-]*://([^/?#\s]+)", v, re.I)
        return f"{m.group(1)}://{h.group(1) if h else ''}/…"
    if v.startswith("-----BEGIN"):
        return "-----BEGIN … PRIVATE KEY-----"
    if v.startswith("{"):
        return "{json …}"
    return "•••• (" + str(len(v)) + " chars)"

def fingerprint(salt, value):
    return hmac.new(salt, value.strip().encode("utf-8"), hashlib.sha256).hexdigest()[:12]

# ----------------------------------------------------------------------------
# Railway GraphQL API
# ----------------------------------------------------------------------------
class Railway:
    def __init__(self, token, project_token=False, delay=0.12):
        self.token, self.project_token, self.delay, self.calls = token, project_token, delay, 0

    def q(self, query, variables=None, soft=False):
        body = json.dumps({"query": query, "variables": variables or {}}).encode()
        headers = {"Content-Type": "application/json", "User-Agent": f"railway-secrets-responder/{VERSION}"}
        if self.project_token:
            headers["Project-Access-Token"] = self.token
        else:
            headers["Authorization"] = "Bearer " + self.token
        for attempt in range(5):
            time.sleep(self.delay)
            self.calls += 1
            req = urllib.request.Request(os.environ.get("RAILWAY_API_URL", API_URL), data=body, headers=headers, method="POST")
            try:
                with urllib.request.urlopen(req, timeout=30) as r:
                    data = json.loads(r.read().decode())
            except urllib.error.HTTPError as e:
                if e.code == 429 and attempt < 4:
                    wait = int(e.headers.get("Retry-After", "5") or 5)
                    print(DIM(f"  rate limited, waiting {wait}s"), file=sys.stderr)
                    time.sleep(min(wait, 120)); continue
                if e.code in (401, 403):
                    die("Railway rejected the token (401/403). Check the token type: account/workspace tokens use "
                        "the default mode, project tokens need --project-token.")
                if soft: return None
                die(f"Railway API HTTP {e.code}")
            except urllib.error.URLError as e:
                die(f"cannot reach Railway API ({e.reason}). Check your network.")
            if data.get("errors"):
                if soft: return None
                msgs = "; ".join(str(x.get("message", ""))[:160] for x in data["errors"])
                if "Not Authorized" in msgs or "authorized" in msgs.lower():
                    die("Railway says 'Not Authorized'. Use an account or workspace token, or --project-token for a project token.")
                die(f"Railway API error: {msgs}")
            return data.get("data") or {}
        die("Railway API kept rate limiting; try again later or pass --delay 1")

Q_PROJECTS = "query { projects { edges { node { id name } } } }"
Q_WS_PROJECTS = "query wp($workspaceId: String!) { projects(workspaceId: $workspaceId) { edges { node { id name } } } }"
Q_WORKSPACES = "query { me { workspaces { id name } } }"
Q_PROJECT = """query project($id: String!) { project(id: $id) { id name
  services { edges { node { id name } } } environments { edges { node { id name } } } } }"""
Q_VARS = """query variables($projectId: String!, $environmentId: String!, $serviceId: String, $unrendered: Boolean) {
  variables(projectId: $projectId, environmentId: $environmentId, serviceId: $serviceId, unrendered: $unrendered) }"""
Q_PROJECT_TOKEN = "query { projectToken { projectId environmentId } }"

def edges(conn):
    return [e["node"] for e in ((conn or {}).get("edges") or []) if e and e.get("node")]

def collect_api(args):
    token = os.environ.get("RAILWAY_API_TOKEN") or os.environ.get("RAILWAY_TOKEN")
    if not token:
        if not sys.stdin.isatty():
            die("set RAILWAY_API_TOKEN (account/workspace token) or RAILWAY_TOKEN (project token) in the environment")
        token = getpass.getpass("Railway token (input hidden): ").strip()
    if not token:
        die("no token provided")
    api = Railway(token, project_token=args.project_token, delay=args.delay)
    del token
    rows, envfilter = [], {e.lower() for e in (args.environment or [])}
    projects = {}
    only_env = None
    if args.project_token:
        pt = api.q(Q_PROJECT_TOKEN).get("projectToken") or {}
        if not pt.get("projectId"):
            die("could not read project token scope")
        projects[pt["projectId"]] = "?"
        only_env = pt.get("environmentId")
    else:
        for p in edges(api.q(Q_PROJECTS).get("projects")):
            projects[p["id"]] = p["name"]
        ws = api.q(Q_WORKSPACES, soft=True)
        wids = [w["id"] for w in (((ws or {}).get("me") or {}).get("workspaces") or [])] + list(args.workspace or [])
        for wid in dict.fromkeys(wids):
            d = api.q(Q_WS_PROJECTS, {"workspaceId": wid}, soft=True)
            for p in edges((d or {}).get("projects")):
                projects[p["id"]] = p["name"]
    if args.project:
        projects = {pid: projects.get(pid, "?") for pid in args.project}
    if not projects:
        die("no projects visible to this token", 3)

    print(DIM(f"Found {len(projects)} project(s). Reading variables (values stay in memory, never shown)..."))
    for pid in projects:
        proj = (api.q(Q_PROJECT, {"id": pid}).get("project")) or {}
        pname = proj.get("name") or projects[pid]
        services = edges(proj.get("services"))
        envs = edges(proj.get("environments"))
        if only_env:
            envs = [e for e in envs if e["id"] == only_env] or [{"id": only_env, "name": "token-env"}]
        if envfilter:
            envs = [e for e in envs if e["name"].lower() in envfilter]
        for env in envs:
            scopes = [(None, "(shared)")] + [(s["id"], s["name"]) for s in services]
            for sid, sname in scopes:
                vars_ = {"projectId": pid, "environmentId": env["id"], "unrendered": True}
                if sid: vars_["serviceId"] = sid
                d = api.q(Q_VARS, vars_, soft=True)
                if d is None:
                    continue
                for name, value in sorted(((d.get("variables") or {}).items())):
                    rows.append({"project": pname, "environment": env["name"], "service": sname,
                                 "name": name, "_value": value if isinstance(value, str) else json.dumps(value),
                                 "source": "railway-api"})
        print(DIM(f"  {pname}: {len(envs)} environment(s), {len(services)} service(s)"))
    print(DIM(f"  API calls: {api.calls}"))
    return rows

def collect_cli_json(paths):
    rows = []
    for pattern in paths:
        for p in sorted(glob.glob(pattern)) or [pattern]:
            try:
                with open(p, encoding="utf-8") as f:
                    data = json.load(f)
            except (OSError, ValueError) as e:
                die(f"cannot read CLI JSON {p}: {e.__class__.__name__}")
            if isinstance(data, dict) and "variables" in data and isinstance(data["variables"], dict):
                data = data["variables"]
            if not isinstance(data, dict):
                die(f"{p}: expected the object printed by 'railway variables --json'")
            base = os.path.basename(p).rsplit(".json", 1)[0]
            parts = base.split(".")
            svc = parts[0] if parts else base
            env = parts[1] if len(parts) > 1 else "?"
            proj = data.get("RAILWAY_PROJECT_NAME") or "?"
            env = data.get("RAILWAY_ENVIRONMENT_NAME") or env
            svc = data.get("RAILWAY_SERVICE_NAME") or svc
            for name, value in sorted(data.items()):
                rows.append({"project": proj, "environment": env, "service": svc, "name": name,
                             "_value": value if isinstance(value, str) else json.dumps(value), "source": f"cli:{os.path.basename(p)}"})
    return rows

# ----------------------------------------------------------------------------
# Local repos linked to Railway
# ----------------------------------------------------------------------------
SKIP_DIRS = {"node_modules", ".git", ".next", ".nuxt", "dist", "build", ".venv", "venv", "__pycache__", ".cache", "vendor", "coverage", ".turbo"}

def parse_dotenv(path):
    out = {}
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                m = re.match(r'^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.]*)\s*=\s*(.*)$', line)
                if not m: continue
                val = m.group(2).strip()
                if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
                    val = val[1:-1]
                elif " #" in val:
                    val = val.split(" #", 1)[0].strip()
                out[m.group(1)] = val
    except OSError:
        pass
    return out

def collect_local(roots):
    rows, findings = [], []
    linked = set()
    cfg = os.path.expanduser("~/.railway/config.json")
    if os.path.isfile(cfg):
        try:
            with open(cfg, encoding="utf-8") as f:
                data = json.load(f)
            for path, meta in (data.get("projects") or {}).items():
                linked.add(os.path.realpath(path))
                findings.append(("INFO", "Railway CLI link", path, f"linked to project {meta.get('name') or meta.get('project', '?')}"))
            user = data.get("user") or {}
            if any(user.get(k) for k in ("token", "accessToken", "refreshToken")):
                findings.append(("P2", "Railway CLI session token on disk", cfg,
                                 "Precaution: run 'railway logout' then 'railway login' to issue a fresh session (value not shown)"))
        except (OSError, ValueError):
            findings.append(("REVIEW", "Railway CLI config unreadable", cfg, "check manually"))
    for root in roots:
        root = os.path.realpath(os.path.expanduser(root))
        if not os.path.isdir(root):
            die(f"--local path is not a directory: {root}")
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            rp = os.path.realpath(dirpath)
            if {"railway.json", "railway.toml"} & set(filenames) or rp in linked:
                linked.add(rp)
                findings.append(("INFO", "Railway-linked repo", dirpath, "railway.json/toml or CLI link found"))
            for fn in filenames:
                full = os.path.join(dirpath, fn)
                if fn.startswith(".env") and not fn.endswith((".example", ".sample", ".template", ".dist")):
                    for name, value in parse_dotenv(full).items():
                        rows.append({"project": "(local)", "environment": fn, "service": os.path.relpath(dirpath, root) if dirpath != root else os.path.basename(root),
                                     "name": name, "_value": value, "source": f"local:{full}", "_linked": rp in linked or any(rp.startswith(l + os.sep) for l in linked)})
                if dirpath.endswith(os.path.join(".github", "workflows")) and fn.endswith((".yml", ".yaml")):
                    try:
                        txt = open(full, encoding="utf-8", errors="replace").read()
                    except OSError:
                        continue
                    for m in sorted(set(re.findall(r"secrets\.(RAILWAY[A-Z_]*TOKEN[A-Z_]*)", txt))):
                        findings.append(("P1", "Railway token in GitHub Actions secrets", full,
                                         f"secrets.{m}: if this token was ever stored in Railway variables, create a new one and update the GitHub secret"))
    return rows, findings

# ----------------------------------------------------------------------------
# Analysis
# ----------------------------------------------------------------------------
BUCKET_NOTE = ("Railway Bucket credential. Press reports say Railway is rotating bucket credentials itself: check the bucket's "
               "Credentials tab for new values, update services that copy them (references follow automatically), redeploy when builds are available")

def analyze(rows, salt):
    scope = lambda r: (r["project"], r["environment"], r["service"])
    bucket_scopes = {scope(r) for r in rows if isinstance(r.get("_value"), str) and "storageapi.dev" in r["_value"]}
    db_scopes = {scope(r) for r in rows if isinstance(r.get("_value"), str) and DB_RAILWAY_VALUE.match(r["_value"].strip())}
    items, skipped = {}, 0
    for r in rows:
        info = classify(r["name"], r["_value"])
        if not info:
            skipped += 1
            continue
        sc = scope(r)
        if info["provider"] in ("aws-key-id", "aws-secret") and sc in bucket_scopes:
            info = {**info, "provider": "railway-bucket", "label": "Railway Bucket credential", "category": "Storage", "rotate": BUCKET_NOTE}
        fp = fingerprint(salt, r["_value"]) if info["basis"] != "reference" else "ref:" + hashlib.sha256(r["_value"].encode()).hexdigest()[:8]
        if sc in db_scopes and info["provider"] in ("db-railway", "db-password", "url-creds") and not r["source"].startswith("local:"):
            info = {**info, "provider": "railway-db", "label": f"Railway database credentials ({sc[2]})", "category": "Database",
                    "priority": "P1", "rotate": RAILWAY_DB_NOTE}
            key = ("railway-db",) + sc          # one rotation for the whole database service
        else:
            key = (fp, info["provider"])
        it = items.setdefault(key, {"fp": fp, **info, "masked": mask(r["_value"], info), "names": set(), "locations": []})
        it["names"].add(r["name"])
        it["locations"].append({"project": r["project"], "environment": r["environment"], "service": r["service"],
                                "name": r["name"], "source": r["source"], "linked": r.get("_linked", True), "fp": fp})
        if PRIO_ORDER[info["priority"]] < PRIO_ORDER[it["priority"]]:
            it.update({k: info[k] for k in ("priority", "label", "rotate", "category", "provider")})
    for r in rows:
        r["_value"] = None  # drop secret material as soon as possible
    out = []
    for it in items.values():
        remote = [l for l in it["locations"] if not l["source"].startswith("local:")]
        local_linked = [l for l in it["locations"] if l["source"].startswith("local:") and l["linked"]]
        if not remote and not local_linked:
            continue  # only in local repos that are not linked to Railway: out of scope
        it["names"] = sorted(it["names"])
        if it["provider"] == "railway-db":
            it["masked"] = f"{len(it['locations'])} variable(s) on this database service"
        it["strategy"] = STRATEGY_OVERRIDE.get(it["provider"], STRATEGY[it["priority"]])
        it["note"] = ("Same value also found in local files: update them too." if remote and len(remote) < len(it["locations"]) else
                      "Found only in a local repo linked to Railway: confirm it is also set in Railway." if not remote else "")
        out.append(it)
    out.sort(key=lambda x: (PRIO_ORDER[x["priority"]], {"AI provider": 0}.get(x["category"], 1), x["category"], x["label"], x["names"][0]))
    return out, skipped

def cli_cmd(loc):
    if loc["source"].startswith("local:"):
        return f"edit {loc['source'][6:]}  ({loc['name']})"
    svc = "" if loc["service"] == "(shared)" else f" -s \"{loc['service']}\""
    shared = "   # shared variable: update in the dashboard (Project > Settings > Shared Variables)" if loc["service"] == "(shared)" else ""
    return f"railway variable set {loc['name']} --stdin --skip-deploys -e \"{loc['environment']}\"{svc}{shared}"

def apply_baseline(baseline_path):
    try:
        with open(baseline_path, encoding="utf-8") as f:
            base = json.load(f)
    except (OSError, ValueError):
        die(f"cannot read baseline {baseline_path}")
    salt = bytes.fromhex(base["salt"])
    prev = {(e["project"], e["environment"], e["service"], e["name"]): e["fp"] for e in base.get("entries", [])}
    return salt, prev

def verify_status(items, prev):
    not_rotated = 0
    for it in items:
        if it["priority"] in ("INFO",):
            it["verify"] = ""
            continue
        states = []
        for l in it["locations"]:
            k = (l["project"], l["environment"], l["service"], l["name"])
            if k in prev:
                same = prev[k] == l["fp"]
                l["verify"] = "NOT ROTATED" if same else "ROTATED"
                states.append(same)
            else:
                l["verify"] = "NEW"
        if states and any(states):
            it["verify"] = "NOT ROTATED"; not_rotated += 1
        elif states:
            it["verify"] = "ROTATED"
        else:
            it["verify"] = "NEW"
    return not_rotated

# ----------------------------------------------------------------------------
# Output
# ----------------------------------------------------------------------------
PCOL = {"P1": RED, "P2": YEL, "P3": CYA, "REVIEW": YEL, "INFO": DIM}

def print_terminal(items, skipped, findings, adv, verify):
    print()
    print(BLD(CYA("Railway secrets audit")) + "  " + DIM(f"({adv.get('ADVISORY_NAME', '')})"))
    print(DIM("Values are never shown. Masks show only a provider's public prefix."))
    print()
    for it in items:
        if it["priority"] == "INFO" and not verify:
            continue
        tag = PCOL[it["priority"]](BLD(f"{it['priority']:<6}"))
        ver = ""
        if verify and it.get("verify"):
            ver = "  " + (GRN("ROTATED") if it["verify"] == "ROTATED" else RED(BLD("NOT ROTATED")) if it["verify"] == "NOT ROTATED" else YEL("NEW"))
        print(f"{tag} {BLD(it['label'])}  {DIM(it['masked'])}{ver}")
        print(f"       vars: {', '.join(it['names'])}   used in {len(it['locations'])} place(s)   strategy: {it['strategy']}")
        print(f"       rotate: {it['rotate']}")
        if it.get("note"):
            print(YEL(f"       note: {it['note']}"))
        for l in it["locations"][:6]:
            where = l["source"][6:] if l["source"].startswith("local:") else f"{l['project']} / {l['environment']} / {l['service']}"
            v = f"  [{l['verify']}]" if verify and l.get("verify") else ""
            print(DIM(f"         - {where}  ({l['name']}){v}"))
        if len(it["locations"]) > 6:
            print(DIM(f"         ... {len(it['locations']) - 6} more"))
        print()
    for prio, what, where, note in findings:
        if prio == "INFO": continue
        print(f"{PCOL[prio](BLD(f'{prio:<6}'))} {BLD(what)}  {DIM(where)}\n       {note}\n")
    counts = {p: sum(1 for i in items if i["priority"] == p) for p in PRIO_ORDER}
    print(BLD("Summary: ") + RED(f"{counts['P1']} P1") + ", " + YEL(f"{counts['P2']} P2") + ", " + CYA(f"{counts['P3']} P3") +
          f", {counts['REVIEW']} to review, {counts['INFO']} info/references, {skipped} non-secret config values skipped")

def write_csv(path, items):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["priority", "strategy", "provider", "category", "variable", "project", "environment", "service",
                    "source", "masked", "fingerprint", "rotate_at", "update_command", "verify"])
        for it in items:
            for l in it["locations"]:
                w.writerow([it["priority"], it["strategy"], it["label"], it["category"], l["name"], l["project"],
                            l["environment"], l["service"], l["source"], it["masked"], l["fp"], it["rotate"],
                            cli_cmd(l), l.get("verify", "")])

def write_md(path, items, findings, adv):
    L = [f"# Railway secret rotation checklist", "",
         f"Incident: {adv.get('ADVISORY_NAME', '')}. Generated {datetime.now().strftime('%Y-%m-%d %H:%M')}.",
         "No secret values are included in this file.", "",
         "Order for each item: create a new credential at the provider -> set it in Railway with `--stdin --skip-deploys` -> deploy when builds are available -> revoke the old one -> re-run the audit with `--baseline` to confirm.", ""]
    for prio, title in (("P1", "P1: rotate now"), ("P2", "P2: rotate soon"), ("P3", "P3: low impact"), ("REVIEW", "Review: confirm what these are")):
        group = [i for i in items if i["priority"] == prio]
        if not group: continue
        L += [f"## {title}", ""]
        for it in group:
            L.append(f"- [ ] **{it['label']}** (`{'`, `'.join(it['names'])}`), {len(it['locations'])} place(s), strategy {it['strategy']}")
            L.append(f"  - Rotate at: {it['rotate']}")
            for l in it["locations"]:
                L.append(f"  - [ ] `{cli_cmd(l)}`")
        L.append("")
    other = [f for f in findings if f[0] != "INFO"]
    if other:
        L += ["## Other findings", ""] + [f"- [ ] **{w}** ({p}): `{wh}`. {n}" for p, w, wh, n in other] + [""]
    L += ["## Also check", "",
          "- [ ] Private registry credentials in each service's Settings (not visible as variables)",
          "- [ ] Provider dashboards: usage, billing and logs since the disclosure for unexpected activity",
          "- [ ] Railway email from the security team (sent to confirmed affected accounts)",
          f"- [ ] Status page for builds/deploys: {adv.get('SOURCES', '').split('|')[-1].strip()}", ""]
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(L))

def write_baseline(path, items, salt, adv):
    entries = []
    for it in items:
        if it["priority"] == "INFO": continue
        for l in it["locations"]:
            entries.append({"project": l["project"], "environment": l["environment"], "service": l["service"],
                            "name": l["name"], "fp": l["fp"], "priority": it["priority"]})
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"tool": "railway-secrets-responder", "version": VERSION, "advisory": adv.get("ADVISORY_ID"),
                   "created": datetime.now(timezone.utc).isoformat(), "note": "Salted, truncated HMAC fingerprints only. No secret values.",
                   "salt": salt.hex(), "entries": entries}, f, indent=1)
    try: os.chmod(path, 0o600)
    except OSError: pass

def write_html(path, items, skipped, findings, adv, verify, not_rotated):
    e = html.escape
    counts = {p: sum(1 for i in items if i["priority"] == p) for p in PRIO_ORDER}
    def card(it):
        locs = "".join(
            f"<li><code>{e(l['source'][6:] if l['source'].startswith('local:') else l['project'] + ' / ' + l['environment'] + ' / ' + l['service'])}</code>"
            f" <span class=mut>({e(l['name'])})</span>"
            + (f" <span class='vb {('ok' if l.get('verify') == 'ROTATED' else 'bad' if l.get('verify') == 'NOT ROTATED' else 'new')}'>{e(l.get('verify', ''))}</span>" if verify and l.get('verify') else "")
            + f"<div class=cmd>{e(cli_cmd(l))}</div></li>" for l in it["locations"])
        vtag = ""
        if verify and it.get("verify"):
            cls = {"ROTATED": "ok", "NOT ROTATED": "bad"}.get(it["verify"], "new")
            vtag = f"<span class='vb {cls}'>{e(it['verify'])}</span>"
        rot = re.sub(r"(https://[^\s<)&]+)", lambda m: f"<a href='{m.group(1)}' target=_blank rel=noopener>{m.group(1)}</a>", e(it["rotate"]))
        note = f"<div class=note>{e(it['note'])}</div>" if it.get("note") else ""
        return (f"<details class='card {it['priority']}' data-fp='{e(it['fp'])}'><summary>"
                f"<input type=checkbox class=done title='Mark rotated' onclick='event.stopPropagation()'>"
                f"<span class=badge>{e(it['priority'])}</span><b>{e(it['label'])}</b> {vtag}"
                f"<span class=meta>{e(', '.join(it['names']))} · {len(it['locations'])} place(s) · {e(it['strategy'])}</span></summary>"
                f"<div class=body><div><span class=mut>Value:</span> <code>{e(it['masked'])}</code> <span class=mut>· fingerprint {e(it['fp'])}</span></div>"
                f"<div><span class=mut>Rotate at:</span> {rot}</div>{note}<ul>{locs}</ul></div></details>")
    sections = ""
    for prio, title, sub in (("P1", "Rotate now", "Highest impact. AI keys first: the campaign targets AI inference providers."),
                             ("P2", "Rotate soon", "Real credentials with lower blast radius, or rotations that log users out."),
                             ("P3", "Low impact", "Test keys and semi-public values."),
                             ("REVIEW", "Review", "Looks like a secret; confirm what it is."),
                             ("INFO", "No action", "References (rotate at the source) and public values.")):
        group = [i for i in items if i["priority"] == prio]
        if group:
            sections += f"<h2 class='h {prio}'>{e(title)} <small>{len(group)}</small></h2><p class=mut>{e(sub)}</p>" + "".join(card(i) for i in group)
    other = [f for f in findings if f[0] != "INFO"]
    if other:
        sections += "<h2 class='h REVIEW'>Other findings</h2>" + "".join(
            f"<div class='card {p} flat'><span class=badge>{e(p)}</span><b>{e(w)}</b><div class=mut><code>{e(wh)}</code></div><div>{e(n)}</div></div>" for p, w, wh, n in other)
    vbanner = ""
    if verify:
        vbanner = (f"<div class='banner {'bad' if not_rotated else 'ok'}'>Verification against baseline: "
                   f"{'<b>' + str(not_rotated) + ' secret(s) still have the SAME value</b> (not rotated yet).' if not_rotated else '<b>every secret from the baseline has a new value.</b>'}</div>")
    doc = f"""<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Railway Rotation Tracker</title>
<style>
:root{{--bg:#f6f5fb;--fg:#17151f;--mut:#615c70;--card:#fff;--line:#e4e1ee;--p1:#d92d20;--p2:#dc8a00;--p3:#0e7490;--rv:#a16207;--info:#7a828e;--ok:#16a34a;--accent:#7c3aed}}
@media (prefers-color-scheme:dark){{:root:not([data-theme=light]){{--bg:#0f0e14;--fg:#eeecf5;--mut:#a29db3;--card:#1a1823;--line:#2c2938}}}}
:root[data-theme=dark]{{--bg:#0f0e14;--fg:#eeecf5;--mut:#a29db3;--card:#1a1823;--line:#2c2938}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;padding:24px 16px}}
.wrap{{max-width:1020px;margin:0 auto}}h1{{margin:0 0 4px;font-size:24px}}h1 span{{color:var(--accent)}}.mut{{color:var(--mut)}}.sub{{color:var(--mut);font-size:13px;margin:0 0 16px}}
.banner{{border-radius:12px;padding:12px 14px;margin:0 0 16px;border:1px solid var(--line);background:var(--card)}}.banner.bad{{border-color:var(--p1)}}.banner.ok{{border-color:var(--ok)}}
.warn{{border-left:5px solid var(--accent);border-radius:0;background:var(--card);padding:10px 14px;margin:0 0 16px;font-size:14px}}
.sum{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin:0 0 20px}}
.stat{{background:var(--card);border:1px solid var(--line);border-top:5px solid var(--c);border-radius:14px;padding:12px 14px}}.stat b{{display:block;font-size:28px;color:var(--c)}}.stat span{{font-size:13px;color:var(--mut)}}
.P1{{--c:var(--p1)}}.P2{{--c:var(--p2)}}.P3{{--c:var(--p3)}}.REVIEW{{--c:var(--rv)}}.INFO{{--c:var(--info)}}.prog{{--c:var(--accent)}}
h2.h{{font-size:18px;margin:26px 0 2px;color:var(--c)}}h2 small{{color:var(--mut);font-weight:400}}
.card{{background:var(--card);border:1px solid var(--line);border-left:6px solid var(--c);border-radius:12px;margin:10px 0;min-width:0}}.card.flat{{padding:12px 14px}}
summary{{cursor:pointer;padding:12px 14px;display:flex;flex-wrap:wrap;gap:8px;align-items:center;list-style:none}}summary::-webkit-details-marker{{display:none}}
.meta{{flex-basis:100%;color:var(--mut);font-size:13px;word-break:break-word}}.badge{{background:var(--c);color:#fff;font-weight:700;font-size:11px;letter-spacing:.06em;padding:2px 8px;border-radius:6px}}
.body{{padding:0 14px 12px;font-size:14px;word-break:break-word}}.body ul{{padding-left:18px}}.body li{{margin:6px 0}}
code{{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px}}.cmd{{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;color:var(--mut);background:var(--bg);border-radius:6px;padding:4px 8px;margin-top:3px;overflow-x:auto}}
.done{{width:18px;height:18px;accent-color:var(--ok)}}.card.isdone{{opacity:.55}}.card.isdone b{{text-decoration:line-through}}
.note{{margin-top:6px;font-size:13px;color:var(--rv)}}.vb{{font-size:11px;font-weight:700;padding:1px 7px;border-radius:6px;color:#fff}}.vb.ok{{background:var(--ok)}}.vb.bad{{background:var(--p1)}}.vb.new{{background:var(--info)}}
a{{color:var(--accent)}}footer{{color:var(--mut);font-size:12px;margin-top:28px}}
</style></head><body><div class=wrap>
<h1><span>Railway</span> rotation tracker</h1>
<p class=sub>{e(adv.get('ADVISORY_NAME', ''))} · generated {e(datetime.now().strftime('%Y-%m-%d %H:%M'))} · no secret values in this file</p>
{vbanner}
<div class=warn><b>Deploys:</b> {e(adv.get('DEPLOY_NOTE', ''))}<br><b>Upstream revocations:</b> {e(adv.get('UPSTREAM_NOTE', ''))}</div>
<div class=sum>
<div class='stat P1'><b>{counts['P1']}</b><span>P1 rotate now</span></div>
<div class='stat P2'><b>{counts['P2']}</b><span>P2 rotate soon</span></div>
<div class='stat P3'><b>{counts['P3'] + counts['REVIEW']}</b><span>Low impact / review</span></div>
<div class='stat prog'><b id=prog>0</b><span>marked rotated (this browser)</span></div>
</div>
{sections}
<footer>Strategy: CONTAIN-THEN-ROTATE (Railway databases) = remove Public Access now, change the password when deploys work. CONFIRM-RAILWAY-ROTATION (Buckets) = check for new credentials from Railway and redeploy. REVOKE-NOW = revoke the old credential immediately even if the app breaks until it can be redeployed (decide with the owner). STAGE-THEN-REVOKE = create the new credential, set it with --skip-deploys, deploy when builds are available, then revoke the old one. Verify by re-running the audit with --baseline. {skipped} non-secret config values were skipped. Sources: {e(adv.get('SOURCES', ''))}</footer>
</div>
<script>
(function(){{var K='rsr-done-'+location.pathname,s={{}};try{{s=JSON.parse(localStorage.getItem(K)||'{{}}')}}catch(e){{}}
var boxes=document.querySelectorAll('.done');function upd(){{var n=0;boxes.forEach(function(b){{var c=b.closest('.card');c.classList.toggle('isdone',b.checked);if(b.checked)n++}});document.getElementById('prog').textContent=n+' / '+boxes.length}}
boxes.forEach(function(b){{var fp=b.closest('.card').dataset.fp;b.checked=!!s[fp];b.addEventListener('change',function(){{s[fp]=b.checked;try{{localStorage.setItem(K,JSON.stringify(s))}}catch(e){{}}upd()}})}});upd()}})();
</script></body></html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(doc)

# ----------------------------------------------------------------------------
def main():
    idflags = {"--workspace", "--project", "--environment", "-o", "--out", "--baseline", "--advisory", "--delay"}
    argv = sys.argv[1:]
    for i, a in enumerate(argv):
        if (i > 0 and argv[i - 1] in idflags) or a.startswith("-"):
            continue
        if re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", a) or re.match(r"^(sk-|sk_|ghp_|xox)", a):
            die("this looks like a token on the command line. Put tokens in RAILWAY_API_TOKEN instead (command lines end up in shell history).")

    ap = argparse.ArgumentParser(description="Inventory and prioritize secrets stored in Railway for rotation. Values are never shown.",
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__.split("USAGE", 1)[1])
    ap.add_argument("--api", action="store_true", help="read variables through the Railway API (token from RAILWAY_API_TOKEN / RAILWAY_TOKEN or hidden prompt)")
    ap.add_argument("--project-token", action="store_true", help="the token is a project token (Project-Access-Token header)")
    ap.add_argument("--workspace", action="append", help="extra workspace id to include (repeatable)")
    ap.add_argument("--project", action="append", help="only these project ids (repeatable)")
    ap.add_argument("--environment", action="append", help="only these environment names (repeatable)")
    ap.add_argument("--cli-json", nargs="+", metavar="FILE", help="files from 'railway variables --json' (name them service.environment.json)")
    ap.add_argument("--local", action="append", metavar="DIR", help="scan local repos for Railway links, .env copies and CI tokens")
    ap.add_argument("--baseline", help="earlier <out>.baseline.json: report which secrets were rotated")
    ap.add_argument("--advisory", default=DEFAULT_ADVISORY)
    ap.add_argument("--delay", type=float, default=0.12, help="seconds between API calls (default 0.12)")
    ap.add_argument("-o", "--out", default="railway-secrets-report")
    ap.add_argument("--version", action="version", version=VERSION)
    args = ap.parse_args()
    if not (args.api or args.cli_json or args.local):
        ap.print_help(); sys.exit(3)
    adv = load_advisory(args.advisory)
    salt, prev = (None, None)
    if args.baseline:
        salt, prev = apply_baseline(args.baseline)
    salt = salt or pysecrets.token_bytes(16)

    rows, findings = [], []
    if args.api: rows += collect_api(args)
    if args.cli_json: rows += collect_cli_json(args.cli_json)
    if args.local:
        lrows, findings = collect_local(args.local)
        rows += lrows
    items, skipped = analyze(rows, salt)
    del rows

    not_rotated = verify_status(items, prev) if prev is not None else 0
    print_terminal(items, skipped, findings, adv, prev is not None)
    d = os.path.dirname(args.out)
    if d: os.makedirs(d, exist_ok=True)
    write_html(args.out + ".html", items, skipped, findings, adv, prev is not None, not_rotated)
    write_csv(args.out + ".csv", items)
    write_md(args.out + ".md", items, findings, adv)
    if prev is None:
        write_baseline(args.out + ".baseline.json", items, salt, adv)
    print(f"Reports: {args.out}.html (tracker) | {args.out}.csv | {args.out}.md" + ("" if prev is not None else f" | {args.out}.baseline.json (keep it to verify later)"))
    print()
    if prev is not None:
        sys.exit(4 if not_rotated else 0)
    if any(i["priority"] in ("P1", "P2", "P3") for i in items) or any(f[0] in ("P1", "P2") for f in findings):
        sys.exit(2)
    sys.exit(1 if any(i["priority"] == "REVIEW" for i in items) else 0)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\ninterrupted"); sys.exit(3)
