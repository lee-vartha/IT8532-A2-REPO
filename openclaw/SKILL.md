---
name: shredr-predict
description: "Run the complete SHREDR malware triage workflow for a structured malware feature record. Use when asked to classify, triage, analyse, or create an incident report for a SHREDR feature record."
---

# SHREDR Predict

## Goal

Given one complete structured malware feature JSON object, run the SHREDR triage workflow and return its verified result.

## Execution

Run exactly:

python3 {baseDir}/scripts/triage.py '<FEATURE_JSON>'

Use the supplied feature JSON exactly.

Do not invent, estimate, remove, rename, or modify features.

## Result handling

If the workflow returns `status: completed`, report:

- classification
- malware probability
- decision threshold
- generated incident report
- Gitea issue number
- Gitea issue URL

Then stop.

If the workflow returns `status: manual_review`, report the reason and stop.

Do not bypass a guardrail or manually create a Gitea issue after a manual-review result.

## Stopping condition

Stop after exactly one verified Gitea incident issue is created.

Alternatively, stop immediately when the workflow returns a manual-review or failure state.

Never repeat the workflow automatically.

## Safety

Never execute, delete, quarantine, upload, or modify a suspected executable.

Never override `human_review_required`.

Never invent malware indicators or evidence.

Human approval is required before destructive or containment actions.
