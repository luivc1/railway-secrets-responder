#!/usr/bin/env bash
# PreToolUse guard (Claude Code) for railway-secrets-responder.
#  DENY: commands that would print secret values into the conversation
#        (railway variables without redirect, printenv/env, railway run env,
#         cat/less of .env files, railway CLI config), tokens on the command line.
#  ASK:  changes - railway variable set/delete, deploys/redeploys, service/env
#        changes, logout, token or registry edits.
#  Read-only commands and the masked audit tool pass through.
IN=$(cat)
if command -v jq >/dev/null 2>&1; then
  CMD=$(printf '%s' "$IN" | jq -r '.tool_input.command // empty' 2>/dev/null)
elif command -v python3 >/dev/null 2>&1; then
  CMD=$(printf '%s' "$IN" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("tool_input",{}).get("command",""))' 2>/dev/null)
else
  CMD=$IN
fi
[ -z "$CMD" ] && exit 0
LC=$(printf '%s' "$CMD" | tr 'A-Z' 'a-z')
decide() { printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"%s","permissionDecisionReason":"%s"}}\n' "$1" "$2"; exit 0; }
NOSHOW="railway-secrets-responder: this would print secret values into the conversation. Use scripts/railway-audit.py (values masked), or redirect CLI JSON to a file for --cli-json."

# 1. tokens/secrets typed on the command line
if printf '%s' "$CMD" | grep -qE '(RAILWAY_(API_)?TOKEN|API_KEY|SECRET[A-Z_]*)=[^ $"'"'"'{][^ ]{8,}|sk-ant-[A-Za-z0-9]|sk-proj-[A-Za-z0-9]|sk_live_[A-Za-z0-9]|ghp_[A-Za-z0-9]{20}'; then
  decide deny "railway-secrets-responder: a token or secret appears in the command. Set it in your own terminal (export) or use --stdin prompts; never in agent commands."
fi
# 2. printing variables
if echo "$LC" | grep -qE '(^|[;&|[:space:]])railway[[:space:]]+(variables?|vars?)([[:space:]]+(list|ls))?([[:space:]]|$)' \
   && ! echo "$LC" | grep -qE 'railway[[:space:]]+(variables?|vars?)[[:space:]]+(set|delete|rm|remove)' \
   && ! echo "$LC" | grep -qE '>[[:space:]]*[^&]'; then
  decide deny "$NOSHOW"
fi
if echo "$LC" | grep -qE '(^|[;&|[:space:]])(printenv|env)([[:space:]]*($|[;&|]))|railway[[:space:]]+(run|shell)[[:space:]].*(printenv|env([[:space:]]|$)|set([[:space:]]|$))'; then
  decide deny "$NOSHOW"
fi
if echo "$LC" | grep -qE '(^|[;&|[:space:]])(cat|less|more|head|tail|bat|type|strings|xxd|od|grep|awk|sed)[[:space:]][^;&|]*(\.env([^a-z]|$)|\.railway/config\.json|cli/[^ ]*\.json)' \
   && ! echo "$LC" | grep -qE 'grep[[:space:]]+(-[a-z]*[lc][a-z]*[[:space:]])'; then
  decide deny "$NOSHOW (reading .env / Railway config / CLI exports prints secrets)"
fi
# 3. changes that need approval
if echo "$LC" | grep -qE 'railway[[:space:]]+(variables?|vars?)[[:space:]]+(set|delete|rm|remove)|railway[[:space:]]+(up|redeploy|deploy|down|restart|environment|service|link|unlink|logout|domain|volume)'; then
  decide ask "railway-secrets-responder: this changes Railway (variables, deploys or links). Confirm the exact command and that the new value is entered by you via --stdin."
fi
if echo "$LC" | grep -qE 'backboard\.railway\.com' && echo "$LC" | grep -qE 'mutation'; then
  decide ask "railway-secrets-responder: Railway API mutation. Approve this exact change?"
fi
exit 0
