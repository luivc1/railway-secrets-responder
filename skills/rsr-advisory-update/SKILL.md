---
name: rsr-advisory-update
description: Refresh the advisory file behind the Railway rotation tools when Railway publishes new details (exposure window, affected credential types, deploy status, automatic rotations) or for a future platform secret-exposure incident. Use for "Railway posted an update", "is there new info on the Railway incident", "actualiza el advisory de Railway".
---

# Advisory Update

Every value must come from a source read in this session.

## Sources, in priority order

1. Railway blog post(s) for the incident and Railway emails the user received
2. status.railway.com incident page (deploy/build state, timeline)
3. Railway docs for any new rotation features
4. Security press only for context; label anything not from Railway as "reported"

## Steps

1. Read the sources. Note new facts: exposure window, credential types confirmed or
   ruled out, automatic rotations, deploy status, IOCs.
2. Edit `advisories/railway-2026-10-21.env` (or copy it for a new incident):
   `SUMMARY`, `ROTATE_SCOPE`, `EXPOSED_BEFORE` (use the real window if published),
   `DEPLOY_NOTE`, `UPSTREAM_NOTE`, `REPORTED_NOTE`, `SOURCES`, `LAST_VERIFIED`.
3. If Railway confirms a credential type is NOT affected, do not delete items from
   users' lists automatically; tell the user, and let them decide.
4. Re-run the audit so the HTML shows the new notes. Show the user a diff of the
   advisory and the sources.
