---
description: Verify every secret was rotated (baseline fingerprints) and close out
argument-hint: "<path to .baseline.json>"
---
Use the rsr-verify-close skill with RSR=${CLAUDE_PLUGIN_ROOT}. Baseline: $ARGUMENTS
For client accounts, delegate verification to the rsr-verifier agent so it is independent of the rotation work.
