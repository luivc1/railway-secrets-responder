---
name: rsr-client-comms
description: Bilingual (English/Spanish) messages about the Railway secrets incident - client notice for apps you host on Railway, team/colleague briefing with the checklist, rotation-complete confirmation, and possible-misuse notice. Use for "tell my clients about Railway", "brief the team", "avísale a los clientes", "escribe a mis colegas".
---

# Communications

Follow **rsr-navigator** rules: facts from the advisory, the audit report and
`rsr-log.md`. Never include secret values, masked prefixes, fingerprints or tokens in
messages. Never say a client was "not affected"; say what was checked and done.

| Situation | Template (`templates/`) |
|---|---|
| First notice to a client whose app runs on Railway | `client-notice.md` |
| Briefing colleagues / team (attach the `.md` checklist) | `team-briefing.md` |
| Rotation done and verified | `rotation-complete.md` |
| Possible or confirmed misuse found | `misuse-notice.md` |

## How to fill

1. Client's language (EN or ES; ask if unsure).
2. Replace every `{{placeholder}}` with real data; unknown value: ask or drop the
   sentence.
3. Calm and short: what happened (Railway's words), what it means for them, what we
   did, what they need to do (often nothing), when they hear next.
4. Clients whose own accounts or keys we do not control (e.g. their Stripe): tell them
   exactly which key to rotate and where, without naming its value.
5. Draft only; sending is an action the user approves.
